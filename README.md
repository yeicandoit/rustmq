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
- Prometheus: `http://127.0.0.1:18083/metrics`

Override configuration with `RUSTMQ_CONFIG`, `RUSTMQ_MQTT_BIND`, `RUSTMQ_MQTT_TLS_ENABLED`, `RUSTMQ_MQTT_TLS_BIND`, `RUSTMQ_MQTT_TLS_CERTFILE`, `RUSTMQ_MQTT_TLS_KEYFILE`, `RUSTMQ_MQTT_TLS_VERIFY_PEER`, `RUSTMQ_MQTT_TLS_CACERTFILE`, `RUSTMQ_MQTT_WS_ENABLED`, `RUSTMQ_MQTT_WS_BIND`, `RUSTMQ_MQTT_WS_PATH`, `RUSTMQ_MQTT_QUIC_ENABLED`, `RUSTMQ_MQTT_QUIC_BIND`, `RUSTMQ_MQTT_QUIC_CERTFILE`, `RUSTMQ_MQTT_QUIC_KEYFILE`, `RUSTMQ_MQTT_QUIC_IDLE_TIMEOUT_MS`, `RUSTMQ_HTTP_BIND`, `RUSTMQ_MAX_PACKET_SIZE`, `RUSTMQ_MAX_TOPIC_ALIAS`, `RUSTMQ_INFLIGHT_LIMIT`, `RUSTMQ_OFFLINE_QUEUE_LIMIT`, `RUSTMQ_RETRY_INTERVAL_MS`, `RUSTMQ_USERNAME`, `RUSTMQ_PASSWORD`, and `RUSTMQ_NODE_ID`.

To enable MQTT over TLS, set `[mqtt_tls].enabled = true` and provide PEM certificate-chain and private-key paths through `certfile` and `keyfile`. The TLS and plain TCP listeners run concurrently and share the same MQTT state machine. For mTLS, additionally set `verify_peer = true` and provide the trusted client CA bundle through `cacertfile`; clients without a certificate signed by that CA are rejected during the TLS handshake. The verified certificate is currently a transport admission check only and is not mapped to an MQTT username or ACL identity.

To enable MQTT over WebSocket, set `[mqtt_ws].enabled = true`. The default endpoint is `/mqtt` on port 8083 and requires one of the EMQX-compatible subprotocols `mqtt`, `mqtt-v3`, `mqtt-v3.1.1`, or `mqtt-v5`. MQTT packets use binary WebSocket messages; the listener reuses the TCP/TLS connection state machine. WSS is not implemented yet.

To enable MQTT over QUIC, set `[mqtt_quic].enabled = true` and provide PEM certificate-chain and private-key paths through `certfile` and `keyfile`. The Quinn endpoint requires ALPN `mqtt`; the first client-initiated bidirectional stream is the MQTT control stream and reuses the same connection state machine as TCP/TLS/WebSocket. This milestone deliberately permits one bidirectional stream per QUIC connection. EMQX-compatible additional data streams, 0-RTT, client certificates, and explicit connection-migration behavior remain unimplemented.

## Implemented P0

- MQTT 3.1.1 and a practical MQTT 5.0 packet subset over plain TCP, WebSocket, QUIC control stream, server-authenticated TLS, and optional mTLS
- CONNECT, PING, SUBSCRIBE, UNSUBSCRIBE, PUBLISH, DISCONNECT
- QoS 0/1/2 delivery, outbound PUBACK/PUBREC/PUBREL/PUBCOMP state and retries, and inbound QoS 2 route-once handshake
- `+`, `#`, `$SYS` wildcard rule, and `$share/group/filter` round-robin
- MQTT 5 No Local, Retain As Published, Retain Handling, Subscription Identifier, bidirectional Topic Alias, Session Expiry (CONNECT/DISCONNECT), Receive Maximum, and Message Expiry
- in-memory retained messages, persistent subscriptions, finite offline QoS 1/2 queue, and phase-aware reconnect replay
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
