# Architecture

## Source mapping

RustMQ keeps the responsibility boundaries observed in the Apache-2.0 core of EMQX 5.8.9 without transliterating Erlang code:

| EMQX responsibility | RustMQ module |
|---|---|
| `emqx_frame` incremental framing | `src/protocol.rs` |
| `emqx_connection` / `emqx_channel` / `emqx_ws_connection` / `emqx_quic_stream` connection state | `src/server.rs` |
| `emqx_session` / `emqx_session_mem` | session records in `src/broker.rs` |
| `emqx_broker` / `emqx_router` | broker and first-level topic buckets in `src/broker.rs` |
| `emqx_shared_sub` | grouped round-robin dispatch in `src/broker.rs` |
| `emqx_retainer` | retained map in `src/broker.rs` |
| management and Prometheus apps | Axum routes in `src/server.rs` |

The protocol subset is implemented directly rather than through a general MQTT crate. This keeps packet limits, incremental framing, supported MQTT 5 properties, and malformed-input behavior explicit. Expanding MQTT 5 property support should remain test-driven.

## P0 data plane

- One Tokio task owns each plain TCP, TLS, WebSocket, or QUIC-control-stream connection and its protocol state. All listeners feed the same transport-generic MQTT state machine; TLS negotiation, WebSocket framing, and QUIC stream establishment remain listener-local. The Axum WebSocket listener enforces `/mqtt`-style routing and MQTT subprotocol negotiation, then bridges binary messages through bounded Tokio duplex I/O. Outbound stream bytes are reassembled at MQTT packet boundaries before becoming WebSocket messages. The Quinn endpoint requires ALPN `mqtt`, combines its first bidirectional receive/send stream with Tokio `io::join`, limits each QUIC connection to that control stream, and uses bounded graceful shutdown.
- Each client has a bounded `mpsc` outbound queue. `try_send` prevents a slow consumer from blocking publishers; overflow increments `dropped` and requests disconnect.
- Payloads use `bytes::Bytes`, so fan-out clones reference-counted data rather than payload buffers.
- Shared state uses sharded `DashMap` instances. No map guard is held across `.await`.
- Subscription lookup uses a first-topic-level bucket plus a wildcard bucket. This avoids an unbounded scan of all subscriptions for ordinary topics. A compressed topic trie is the P1 replacement when wildcard cardinality becomes material.
- MQTT 5 subscription state stores QoS, No Local, Retain As Published, and Retain Handling. Overlapping regular subscriptions are coalesced per client; shared subscriptions remain online-only round-robin groups.
- Sessions retain outbound QoS 1/2 inflight entries and a bounded FIFO offline queue in memory. QoS 1 waits for PUBACK; QoS 2 transitions from PUBLISH/PUBREC to PUBREL/PUBCOMP. Retry and reconnect replay reuse packet identifiers, resending DUP PUBLISH or PUBREL according to phase.
- Inflight and offline queue persistence is process-local only. A broker restart loses both; durable storage remains a later milestone.
- Session Expiry Interval is read from CONNECT and may be reduced/changed by MQTT 5 DISCONNECT (except zero may not be raised). It is enforced lazily on reconnect, publish, and status reads. Zero removes the session at disconnect, finite values set an in-memory deadline, and `0xFFFFFFFF` retains it until process exit or Clean Start.
- MQTT 5 Receive Maximum limits QoS 1/2 PUBLISH packets awaiting PUBACK/PUBREC. QoS 2 releases a client PUBLISH slot at PUBREC while remaining in the server inflight table until PUBCOMP. Reconnect with a smaller value replays old inflight incrementally.
- Message Expiry is represented as an absolute monotonic deadline shared by live delivery, inflight retry, offline queues, and retained storage. MQTT 5 serialization emits the remaining lifetime; expired `Ack`/`Rec` and queued messages are removed, while QoS 2 `Comp` remains until PUBCOMP so protocol state is not corrupted.
- Pending Will messages are keyed by Client ID and guarded by a generation number. They fire at `min(Will Delay, Session Expiry)`, are cancelled by a successful session resume, and are published immediately for Clean Start takeover, zero-delay takeover, or DISCONNECT reason `0x04`. Will Message Expiry starts when the Will is actually published.
- QoS 2 inbound state is connection-local: PUBLISH is staged, PUBREL routes once, repeated PUBREL receives PUBCOMP without re-routing.

## Cluster boundary: designed, not implemented

RustMQ 0.1.0 is single-node. `src/cluster.rs` provides `Cluster`, `MetadataStore`, `SingleNodeCluster`, and deterministic rendezvous owner selection as replaceable seams. There is no multi-node replication or forwarding in this release.

The intended P1 control plane is:

1. `openraft` for linearizable cluster metadata and membership changes.
2. RocksDB (through a maintained Rust binding) for Raft log, state-machine snapshots, durable sessions, retained messages, and offline queues.
3. SWIM-style failure detection for fast liveness hints. SWIM must never be the source of truth for committed membership; only Raft commits membership.
4. Rendezvous hashing maps session/topic partitions to owners. Ownership epochs come from Raft to fence stale owners.
5. QUIC (`quinn`) is preferred for multiplexed inter-node publish forwarding; `tonic` remains suitable for lower-rate control RPC and administration. The client-facing MQTT QUIC listener now uses Quinn, but that does not implement this inter-node forwarding protocol.

OpenRaft/RocksDB/SWIM remain intentionally absent until a complete replication path consumes them. Quinn is now an active dependency for the client-facing MQTT QUIC listener, not evidence of multi-node forwarding or replication.

## Consistency boundaries

Linearizable through Raft:

- node membership and ownership epochs;
- authentication/authorization configuration revisions;
- durable-session owner changes;
- partition assignment and failover fencing.

Partition-ordered and replicated:

- QoS 1/2 inflight transitions;
- durable session subscriptions and offline queues;
- retained-message updates for an owned partition.

Eventually consistent:

- route advertisements and cache invalidation;
- metrics, node load, liveness hints;
- transient online-client locations, provided ownership epochs fence stale writes.

The PUBLISH hot path must not append every QoS 0 message to a global Raft group. It routes locally or to the partition owner; only durability-requiring state uses the partition replication log.

## Failure semantics and migration

- P0 process failure loses all in-memory sessions, retained messages, QoS inflight state, offline queues, and pending Will timers. Network reconnect within the same process preserves/cancels them according to Session Expiry and Will Delay.
- P1 should use one Raft group for metadata and multiple partition groups for data; quorum loss makes affected durable partitions unavailable rather than accepting split-brain writes.
- Node forwarding must include partition epoch and message identity. A receiver rejects stale epochs and deduplicates QoS message identities.
- Migration sequence: durable local store → metadata Raft → static two-node forwarding → replicated partitions → SWIM discovery → online resharding.
- Rolling upgrades require a versioned inter-node protocol and snapshot schema before multi-node mode is enabled.

## Security and overload

Static credentials use constant-time byte comparison. The packet-size limit is enforced before frame allocation. The optional rustls listener loads a PEM certificate chain and private key at startup, runs alongside plain TCP, and cancels incomplete handshakes during graceful shutdown. Optional mTLS builds a rustls client verifier from the configured CA bundle and requires every TLS client to present a trusted certificate. Certificate identity is not yet propagated into MQTT authentication or authorization. Production follow-up must add certificate reload, certificate-to-principal mapping, per-listener policies, authorization, rate limits, connection quotas, revocation handling, and secret-provider integration.
