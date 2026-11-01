# RustMQ

RustMQ is a compact, high-performance MQTT broker written in Rust. Its module boundaries are informed by the Apache-2.0 core of EMQX 5.8.9: protocol framing, connection state, sessions, local broker/router, shared subscriptions, retained messages, and management are separate concerns.

RustMQ 0.1.0 is a working P0 broker, not a drop-in or full-featured replacement for EMQX. See `docs/compatibility.md` before deployment.

## Run

```bash
source "$HOME/.cargo/env"
cargo run --release -- --config config/rustmq.toml
```

Default endpoints:

- MQTT TCP: `0.0.0.0:1883`
- MQTT TLS: `0.0.0.0:8883` when `[mqtt_tls].enabled = true`
- MQTT WebSocket: `ws://0.0.0.0:8083/mqtt` when `[mqtt_ws].enabled = true`
- MQTT QUIC: `0.0.0.0:14567/udp` when `[mqtt_quic].enabled = true`
- Health: `http://127.0.0.1:18083/healthz`
- Status: `http://127.0.0.1:18083/api/v1/status`
- EMQX-style public status: `http://127.0.0.1:18083/status` and `/api/v5/status`
- Protected EMQX-style core management API: `/api/v5/*` when `[management].enabled = true`
- Prometheus: `http://127.0.0.1:18083/metrics`

Override configuration with `RUSTMQ_CONFIG`, `RUSTMQ_MQTT_BIND`, `RUSTMQ_MQTT_TLS_ENABLED`, `RUSTMQ_MQTT_TLS_BIND`, `RUSTMQ_MQTT_TLS_CERTFILE`, `RUSTMQ_MQTT_TLS_KEYFILE`, `RUSTMQ_MQTT_TLS_VERIFY_PEER`, `RUSTMQ_MQTT_TLS_CACERTFILE`, `RUSTMQ_MQTT_WS_ENABLED`, `RUSTMQ_MQTT_WS_BIND`, `RUSTMQ_MQTT_WS_PATH`, `RUSTMQ_MQTT_QUIC_ENABLED`, `RUSTMQ_MQTT_QUIC_BIND`, `RUSTMQ_MQTT_QUIC_CERTFILE`, `RUSTMQ_MQTT_QUIC_KEYFILE`, `RUSTMQ_MQTT_QUIC_VERIFY_PEER`, `RUSTMQ_MQTT_QUIC_CACERTFILE`, `RUSTMQ_MQTT_QUIC_ENABLE_0RTT`, `RUSTMQ_MQTT_QUIC_MIGRATION_ENABLED`, `RUSTMQ_MQTT_QUIC_PEER_BIDI_STREAM_COUNT`, `RUSTMQ_MQTT_QUIC_IDLE_TIMEOUT_MS`, `RUSTMQ_HTTP_BIND`, `RUSTMQ_MANAGEMENT_ENABLED`, `RUSTMQ_MANAGEMENT_API_KEY`, `RUSTMQ_MANAGEMENT_API_SECRET`, `RUSTMQ_MANAGEMENT_BEARER_ENABLED`, `RUSTMQ_MANAGEMENT_DASHBOARD_USERNAME`, `RUSTMQ_MANAGEMENT_DASHBOARD_PASSWORD`, `RUSTMQ_MANAGEMENT_BEARER_TOKEN_TTL_MS`, `RUSTMQ_MANAGEMENT_BEARER_MAX_TOKENS`, `RUSTMQ_MANAGEMENT_MAX_PAGE_LIMIT`, `RUSTMQ_MANAGEMENT_MAX_BODY_BYTES`, `RUSTMQ_MAX_PACKET_SIZE`, `RUSTMQ_MAX_TOPIC_ALIAS`, `RUSTMQ_INFLIGHT_LIMIT`, `RUSTMQ_OFFLINE_QUEUE_LIMIT`, `RUSTMQ_RETRY_INTERVAL_MS`, `RUSTMQ_USERNAME`, `RUSTMQ_PASSWORD`, `RUSTMQ_PERSISTENCE_ENABLED`, `RUSTMQ_PERSISTENCE_PATH`, `RUSTMQ_PERSISTENCE_SYNC`, `RUSTMQ_PERSISTENCE_WRITER_QUEUE_CAPACITY`, and `RUSTMQ_NODE_ID`.

### Management API

The EMQX-style management surface is deliberately disabled by default. Enable `[management]` and configure both `api_key` and `api_secret` (prefer the environment overrides). Protected routes accept HTTP Basic credentials:

```bash
curl -u 'dashboard:change-me' 'http://127.0.0.1:18083/api/v5/clients?page=1&limit=100'
curl -u 'dashboard:change-me' -H 'content-type: application/json' \
  -d '{"topic":"admin/notice","payload":"hello","qos":1}' \
  'http://127.0.0.1:18083/api/v5/publish'
```

For EMQX-style Dashboard sessions, also enable `bearer_enabled` and configure `dashboard_username` and `dashboard_password`. These values bootstrap the protected default administrator only when that username does not already exist; later API password changes are not overwritten on restart. Dashboard passwords must be 8–64 ASCII bytes and contain characters from at least two of the letter, number, and special-character groups. Login is public and returns a random 256-bit opaque token:

```bash
TOKEN=$(curl -sS -H 'content-type: application/json' \
  -d '{"username":"admin","password":"change-me"}' \
  'http://127.0.0.1:18083/api/v5/login' | jq -r .token)
curl -H "authorization: Bearer $TOKEN" 'http://127.0.0.1:18083/api/v5/clients'
curl -X POST -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"username":"admin"}' 'http://127.0.0.1:18083/api/v5/logout'
```

Bearer administrators can list, create, update, and delete local Dashboard users through `/api/v5/users`. Community-edition responses intentionally omit role/backend fields; the only current role is `administrator`. Passwords use Argon2id rather than EMQX's fast SHA-256 construction. Changing a password or deleting a user invalidates all of that user's existing tokens on their next request, while a description-only update preserves tokens. The configured default administrator and the current Bearer owner cannot be deleted. Static or dynamic Basic credentials cannot manage users, API keys, or logout, but can call `change_pwd` when the target user's old password is supplied:

```bash
curl -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"username":"operator_1","password":"Operator-123","description":"operations"}' \
  'http://127.0.0.1:18083/api/v5/users'
```

A Bearer session can create up to 100 dynamic API keys. The secret appears only in the create response; list, get, and update never return it. Dynamic keys can authenticate other protected APIs with Basic, but static or dynamic Basic credentials cannot manage `/api/v5/api_key` itself:

```bash
curl -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"name":"Automation-1","desc":"CI publisher","enable":true}' \
  'http://127.0.0.1:18083/api/v5/api_key'
```

Bans support exact `clientid`, `username`, and `peerhost` values plus `clientid_re`, `username_re`, and `peerhost_net` rules. All authenticated management identities can list/create/delete bans. A matching MQTT 5 CONNECT receives reason `0x8A`; MQTT 3.1.1 receives CONNACK code 5. Creating an exact client ID ban also disconnects that online client with MQTT 5 reason `0x98`:

```bash
curl -u 'dashboard:change-me' -H 'content-type: application/json' \
  -d '{"as":"clientid_re","who":"^blocked-","reason":"maintenance"}' \
  'http://127.0.0.1:18083/api/v5/banned'
```

`/status`, `/api/v5/status`, and `/api/v5/login` are public; the remaining `/api/v5` router, including unknown-path fallbacks and method-not-allowed responses, requires Basic or Bearer authentication. Bearer sessions use a sliding lifetime configured by `bearer_token_ttl_ms`, are capped by `bearer_max_tokens`, and are process-local, so restart invalidates them. Dashboard users use a local `DashMap` and are restart-durable when persistence is enabled. The listener is HTTP-only, so bind it to loopback or put it behind a TLS reverse proxy before using reusable credentials or tokens. Pagination defaults to `page=1&limit=100`; clients, subscriptions, and retained handlers build only bounded owned snapshots, reject arithmetic overflow with 400, and return `503 RESOURCE_LIMIT` when the filtered snapshot exceeds `management.max_page_limit` or all four snapshot slots remain busy. JSON bodies and decoded publish payloads are capped by `management.max_body_bytes`.

Implemented groups cover Dashboard user management and password changes, clients and kickout, per-client and global subscriptions, trusted administrative publish/bulk publish, retained-message list/get/delete/clear, nodes, stats, the five real RustMQ metrics, Bearer-managed API Key CRUD, and persistent ban management/enforcement. Administrative DELETE sends MQTT 5 `DISCONNECT 0x98` (`Administrative Action`; MQTT 3.1.1 is closed directly), waits for the observed connection generation to finalize, publishes its active Will immediately, and discards all durable session state. Administrative subscribe/unsubscribe requires a currently online generation; an offline durable session returns `CLIENTID_NOT_FOUND`. Administrative publish returns 202 when no subscription matches (even when retain storage changed), 503 when matches exist but no send or durable queue accepts the dispatch, and 200 with only an `id` after acceptance; bulk status uses 503 over 202 over 200 after validating the complete body. These trusted operations bypass MQTT ACL evaluation and therefore depend on authenticated management access. Client timestamps are exposed as `last_alive_epoch_ms`; retained expiry uses `expires_at_epoch_ms`. Retained detail payloads are base64 and omitted above 1 MiB. This is a focused compatibility surface, not the complete EMQX management API; see `docs/compatibility.md`.

To enable single-node restart durability, set `[persistence].enabled = true` (or `RUSTMQ_PERSISTENCE_ENABLED=true`) and choose a writable `path`. With the default `sync = true`, critical session, retained, outbound inflight/offline queue, active-Will, and pending-Will mutations commit before their Broker operation returns. Dynamic API Key, ban, and Dashboard user mutations always use an acknowledged Immediate commit, including when `sync = false`, so a crash cannot revive a successfully disabled, deleted, or cleared security control. Synchronous writer waits enter an explicit Tokio blocking boundary on multi-thread runtimes and safely run directly on current-thread or non-runtime callers. `sync = false` uses eventual durability for higher throughput; graceful shutdown still flushes a barrier, but an unexpected process or host crash may lose recent acknowledged mutations. Eventual mode does not tolerate a known storage failure: the first hard writer transaction or flush error terminates the process so protocol handling cannot continue fail-open. Database/schema open errors fail startup before any listener binds.

A persisted online session is treated as a connection terminated by process crash during recovery. Zero-expiry sessions are immediately tombstoned; finite sessions and active Wills use the persisted `last_alive_epoch_ms` to derive absolute deadlines, so downtime consumes the configured interval, while `u32::MAX` sessions do not expire. This timestamp is refreshed by critical session persistence and is a conservative single-node crash boundary—not a cluster heartbeat or an exact crash timestamp.

To enable MQTT over TLS, set `[mqtt_tls].enabled = true` and provide PEM certificate-chain and private-key paths through `certfile` and `keyfile`. The TLS and plain TCP listeners run concurrently and share the same MQTT state machine. For mTLS, additionally set `verify_peer = true` and provide the trusted client CA bundle through `cacertfile`; clients without a certificate signed by that CA are rejected during the TLS handshake. The verified certificate is currently a transport admission check only and is not mapped to an MQTT username or ACL identity.

To enable MQTT over WebSocket, set `[mqtt_ws].enabled = true`. The default endpoint is `/mqtt` on port 8083 and requires one of the EMQX-compatible subprotocols `mqtt`, `mqtt-v3`, `mqtt-v3.1.1`, or `mqtt-v5`. MQTT packets use binary WebSocket messages; the listener reuses the TCP/TLS connection state machine. WSS is not implemented yet.

To enable MQTT over QUIC, set `[mqtt_quic].enabled = true` and provide PEM certificate-chain and private-key paths through `certfile` and `keyfile`. The Quinn endpoint requires ALPN `mqtt`; the first client-initiated bidirectional stream is the MQTT control stream and reuses the same connection state machine as TCP/TLS/WebSocket. Further bidirectional streams are activated only after a successful control-stream CONNECT and independently process PUBLISH, SUBSCRIBE, UNSUBSCRIBE, and QoS acknowledgement state, so a partial or malformed data stream does not block or close its siblings. Subscriptions and outbound deliveries are affine to the stream that created them: duplicate subscriptions on separate streams each receive a delivery, ACKs and retries stay on that stream, cross-stream unsubscribe does not remove another stream's subscription, and closing a stream removes only its own transient state. `peer_bidi_stream_count` bounds concurrent client streams and defaults to the EMQX 5.8.9 value of 10. `enable_0rtt = true` accepts resumed TLS 1.3 early control/data streams and keeps those streams usable after handshake completion. QUIC 0-RTT is replayable, so applications that cannot tolerate duplicate effects must add their own idempotency. When `verify_peer = true`, RustMQ ignores early-data enablement and waits for full client-certificate authentication before MQTT processing. `migration_enabled = true` advertises active migration and preserves the same MQTT connection, broker generation, subscriptions, and data streams when the client changes UDP address. The verified certificate is currently a transport admission check only and is not mapped to an MQTT username or ACL identity.

## Implemented P0

- MQTT 3.1.1 and a practical MQTT 5.0 packet subset over plain TCP, WebSocket, QUIC control/data streams, server-authenticated TLS, and optional mTLS
- CONNECT, PING, SUBSCRIBE, UNSUBSCRIBE, PUBLISH, DISCONNECT
- QoS 0/1/2 delivery, outbound PUBACK/PUBREC/PUBREL/PUBCOMP state and retries, and inbound QoS 2 route-once handshake
- `+`, `#`, `$SYS` wildcard rule, and `$share/group/filter` round-robin
- MQTT 5 No Local, Retain As Published, Retain Handling, Subscription Identifier, bidirectional Topic Alias, Session Expiry (CONNECT/DISCONNECT), Receive Maximum, and Message Expiry
- in-memory state by default; optional single-node redb durability for control-target retained messages, sessions, subscriptions, outbound inflight/offline queues, pending Wills, dynamic management API keys, MQTT bans, and Dashboard users
- duplicate-client takeover, Will Delay/cancellation/expiry, 1.5× keepalive, packet-size limit
- bounded per-client, inflight, and offline queues; static optional authentication, metrics, status
- SIGINT/SIGTERM graceful shutdown including established connections

## Quality gates

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

## Docker

```bash
docker compose build
docker compose up -d
```

Use unique host ports/container names on shared Docker hosts. The supplied compose name is intentionally namespaced for this environment.

## License and provenance

RustMQ is Apache-2.0 licensed. It is a clean Rust implementation informed by public MQTT behavior and the Apache-2.0 EMQX core. EMQX applications carrying `BSL.txt` were excluded from implementation reference.
