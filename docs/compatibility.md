# Compatibility and Roadmap

RustMQ 0.1.0 is not a complete EMQX 5.8.9 rewrite and is not configuration-, API-, or plugin-compatible with EMQX. EMQX 5.8.9 contains about 369,000 lines of Erlang and more than 100 applications; this release deliberately implements a tested broker core first.

## P0 implemented

| Capability | Status |
|---|---|
| MQTT 3.1.1 TCP | CONNECT/CONNACK, PING, SUBSCRIBE, UNSUBSCRIBE, PUBLISH, DISCONNECT |
| MQTT 5.0 TCP | Practical packet subset plus CONNECT/DISCONNECT Session Expiry, Receive Maximum, PUBLISH Message Expiry, Will Delay/Expiry, Topic Alias, Subscription Identifier, and SUBSCRIBE NL/RAP/RH semantics |
| MQTT TLS / mTLS | Optional rustls listener with PEM certificate chain/private key, optional mandatory client-certificate verification against a configured CA bundle, concurrent plain TCP listener, shared MQTT state machine, and graceful handshake cancellation |
| MQTT WebSocket | Optional Axum listener with configurable path (default `/mqtt`), binary MQTT messages, `mqtt`/`mqtt-v3`/`mqtt-v3.1.1`/`mqtt-v5` subprotocol negotiation, control ping/pong, packet-size limits, shared MQTT state machine, and graceful shutdown |
| MQTT QUIC | Optional Quinn UDP listener with TLS 1.3 PEM certificate/key, ALPN `mqtt`, one client-initiated bidirectional MQTT control stream, configurable idle timeout, shared MQTT state machine, and bounded graceful shutdown |
| QoS | QoS 0/1/2 delivery; outbound phase-aware retry/reconnect replay; complete client-to-broker QoS 2 PUBREC/PUBREL/PUBCOMP with route-once behavior |
| Topics | exact, `+`, `#`, MQTT `$` system-topic wildcard rule |
| Shared subscriptions | `$share/group/filter`, local online round-robin |
| Retained messages | in-memory store, empty-payload delete, Message Expiry, replay on subscribe |
| Sessions | in-memory persistent subscriptions, Session Expiry, finite offline QoS 1/2 queue, phase-aware inflight-first reconnect replay, duplicate-client takeover |
| Will / keepalive | Will Delay, reconnect cancellation, takeover rules, Will Message Expiry, DISCONNECT 0x04, normal suppression, 1.5× keepalive |
| Operations | TOML/env config, health, JSON status, Prometheus text, graceful shutdown |
| Safety | max packet size, bounded outbound queue, optional static authentication |

## Known P0 limits

- Outbound QoS 1/2 state is memory-only and is lost on process restart.
- MQTT 5 Session Expiry, Receive Maximum, Message Expiry, Will Delay/Expiry, subscription NL/RAP/RH, Subscription Identifier, and bidirectional Topic Alias are implemented. Enhanced authentication and general reason-string semantics are not implemented.
- Offline queues contain QoS 1/2 messages, are bounded/drop-oldest, and are not durable across process restart.
- Retained messages and sessions are memory-only and are lost on restart.
- No certificate-to-MQTT-principal mapping, certificate revocation checking, certificate hot reload, WSS, ACL engine, rate limiter, ban list, or dynamic listener API. QUIC additional data streams, 0-RTT, client-certificate authentication, and explicit migration semantics are not implemented.
- Shared subscriptions are local-node only. Selection retries for a concurrently disappearing subscriber are not implemented.
- Static username/password authentication is global. There is no per-user database or authorization.
- Management API is intentionally small and is not compatible with EMQX Dashboard APIs.
- Multi-node cluster behavior is not implemented; `cluster.rs` is an interface and owner-selection boundary only.

## EMQX 5.8.9 core-parity gaps

“P0 implemented” above means the first runnable RustMQ milestone. It does **not** mean parity with the EMQX core feature set. A stricter EMQX-compatibility baseline still has these gaps:

| EMQX-visible behavior | RustMQ 0.1.0 status |
|---|---|
| MQTT 5 Session Expiry, Assigned Client Identifier, Receive Maximum, User Property and reason-string semantics | Session Expiry and Receive Maximum are implemented in memory; the other listed semantics are not implemented |
| MQTT 5 No Local, Retain As Published, Retain Handling and Subscription Identifier | Implemented, including merged identifiers for overlapping subscriptions and retained delivery |
| MQTT 5 Topic Alias | Implemented per connection in both directions, including advertised/configurable inbound maximum, client-advertised outbound maximum, alias reuse, limit validation, and protocol error reason codes |
| Outbound QoS 1/2 inflight state, DUP/PUBREL retransmission, reconnect replay and finite offline queue | QoS 1/2 are implemented in memory with bounded drop-oldest queue; restart durability is not |
| Inbound QoS 2 EMQX timing | RustMQ routes on PUBREL; EMQX 5.8.9 may publish on first PUBLISH and track `awaiting_rel`, so timing is not identical even though RustMQ guarantees route-once |
| Session expiry, queued delivery while offline and expiry GC | In-memory expiry and bounded QoS 1/2 queue are implemented with lazy GC; persistent storage is not |
| Will Delay and Will Message Expiry | Implemented in memory, including reconnect cancellation, takeover, session-expiry interaction and DISCONNECT 0x04 |
| Retained Message Expiry and Retain Handling 0/1/2 | Implemented in memory with lazy retained cleanup |
| Publish/subscribe ACL and authentication/authorization failure metrics | Static global authentication only; no authorization engine |
| Limits for ClientId/topic length, subscriptions, inflight, queue, connection count and rate | Packet-size, outbound channel, inflight, and offline queue limits are implemented; the others are not |
| Full malformed-frame and UTF-8 validation matrix from `emqx_frame_SUITE` | Partial validation only; not yet differential-tested against the full EMQX corpus |
| EMQX-compatible `/api/v5` clients, subscriptions, publish, stats and metrics APIs with OpenAPI/authentication | Not implemented; RustMQ exposes only its own health, status and Prometheus endpoints |
| EMQX-wide packets/bytes/messages/acked/authn/authz statistics | Five core RustMQ counters only |
| Shared-subscription failure retry, NACK/redispatch and multiple selection strategies | Local online round-robin only |
| HOCON configuration and EMQX `listeners`, `zones`, `broker`, `stats` schema compatibility | Not implemented; RustMQ uses its own TOML schema |
| 1,000-client/10-minute mixed-QoS soak and full EMQX differential suite | Not run; current evidence is the checked-in 78-test functional suite, including WebSocket and QUIC handshake/data-path coverage, trusted/missing/untrusted client-certificate handshakes, and TCP/container smoke tests |

These are compatibility requirements for later milestones, not claims about the current binary. The detailed source references are the EMQX `emqx_frame`, `emqx_channel`, `emqx_session_mem`, `emqx_shared_sub`, `emqx_retainer` implementations and their Common Test suites.

## P1

- Certificate reload/principal mapping, WSS, and EMQX-compatible QUIC multi-stream/0-RTT behavior; remaining MQTT 5 property semantics.
- Durable-on-restart sessions, retained messages, pending Will timers, and persistent queues.
- OpenRaft metadata group, RocksDB state, partition ownership epochs, node forwarding, static cluster formation.
- Trie/radix topic index, per-tenant quotas, authorization hooks, HTTP/JWT authentication.
- Client/session/subscription management APIs, tracing, OpenTelemetry, load and soak benchmarks.

## P2

- SWIM/DNS/Kubernetes discovery, online resharding, replicated data partitions, disaster recovery.
- Rule engine and connector SDK; HTTP, Kafka, SQL, object-store, and cloud integrations as independent plugins.
- MQTT-SN, CoAP, LwM2M, STOMP, and other gateways.
- Dashboard, RBAC/SSO, schema registry/validation, message transformation, audit, rebalance tooling.

Enterprise EMQX applications marked with `BSL.txt` were excluded from implementation reference. Equivalent future capabilities must be independently designed or used under their applicable license.
