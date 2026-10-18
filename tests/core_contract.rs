use bytes::BytesMut;
use rustmq::{
    cluster::{owner_for_key, Cluster, SingleNodeCluster},
    config::Config,
    protocol::{decode_packet, encode_packet, Packet, ProtocolVersion, Publish},
    topic::{parse_filter, topic_matches},
};

#[test]
fn topic_wildcards_and_system_topics_follow_mqtt_rules() {
    assert!(topic_matches("sensors/+/temp", "sensors/a/temp"));
    assert!(topic_matches("sensors/#", "sensors"));
    assert!(!topic_matches("#", "$SYS/broker/uptime"));
    assert!(topic_matches("$SYS/#", "$SYS/broker/uptime"));
    assert!(parse_filter("$share/workers/sensors/+").is_ok());
    assert!(parse_filter("bad/#/tail").is_err());
    assert!(parse_filter("bad+level").is_err());
}

#[test]
fn codec_handles_fragmentation_and_packet_limit() {
    let packet = Packet::Publish(Publish {
        dup: false,
        qos: 1,
        retain: true,
        topic: "a/b".into(),
        packet_id: Some(7),
        payload: b"payload".to_vec().into(),
        expires_at: None,
        subscription_identifiers: Vec::new(),
        topic_alias: None,
    });
    let encoded = encode_packet(&packet, ProtocolVersion::V311).unwrap();
    let mut partial = BytesMut::from(&encoded[..2]);
    assert!(decode_packet(&mut partial, ProtocolVersion::V311, 1024)
        .unwrap()
        .is_none());
    partial.extend_from_slice(&encoded[2..]);
    assert_eq!(
        decode_packet(&mut partial, ProtocolVersion::V311, 1024)
            .unwrap()
            .unwrap(),
        packet
    );

    let mut oversized = BytesMut::from(&encoded[..]);
    assert!(decode_packet(&mut oversized, ProtocolVersion::V311, 2).is_err());
}

#[test]
fn cluster_owner_is_stable_and_single_node_routes_locally() {
    let nodes = vec!["n1".to_string(), "n2".to_string(), "n3".to_string()];
    let first = owner_for_key("tenant/topic", &nodes).unwrap();
    assert_eq!(first, owner_for_key("tenant/topic", &nodes).unwrap());
    assert!(nodes.contains(&first));

    let cluster = SingleNodeCluster::new("local");
    assert_eq!(cluster.owner("anything").unwrap(), "local");
    assert!(cluster.is_local("local"));
}

#[test]
fn config_environment_overrides_file_values() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rustmq.toml");
    std::fs::write(
        &path,
        "[mqtt]\nbind = '127.0.0.1:1884'\nmax_packet_size = 2048\n[http]\nbind = '127.0.0.1:18084'\n",
    )
    .unwrap();
    std::env::set_var("RUSTMQ_MQTT_BIND", "127.0.0.1:2883");
    std::env::set_var("RUSTMQ_MQTT_TLS_ENABLED", "true");
    std::env::set_var("RUSTMQ_MQTT_TLS_BIND", "127.0.0.1:8884");
    std::env::set_var("RUSTMQ_MQTT_TLS_CERTFILE", "/tmp/rustmq-cert.pem");
    std::env::set_var("RUSTMQ_MQTT_TLS_KEYFILE", "/tmp/rustmq-key.pem");
    std::env::set_var("RUSTMQ_MQTT_TLS_VERIFY_PEER", "true");
    std::env::set_var("RUSTMQ_MQTT_TLS_CACERTFILE", "/tmp/rustmq-ca.pem");
    std::env::set_var("RUSTMQ_MQTT_WS_ENABLED", "true");
    std::env::set_var("RUSTMQ_MQTT_WS_BIND", "127.0.0.1:8084");
    std::env::set_var("RUSTMQ_MQTT_WS_PATH", "/custom-mqtt");
    std::env::set_var("RUSTMQ_MQTT_QUIC_ENABLED", "true");
    std::env::set_var("RUSTMQ_MQTT_QUIC_BIND", "127.0.0.1:14568");
    std::env::set_var("RUSTMQ_MQTT_QUIC_CERTFILE", "/tmp/rustmq-quic-cert.pem");
    std::env::set_var("RUSTMQ_MQTT_QUIC_KEYFILE", "/tmp/rustmq-quic-key.pem");
    std::env::set_var("RUSTMQ_MQTT_QUIC_ENABLE_0RTT", "false");
    std::env::set_var("RUSTMQ_MQTT_QUIC_MIGRATION_ENABLED", "false");
    std::env::set_var("RUSTMQ_MQTT_QUIC_IDLE_TIMEOUT_MS", "4321");
    std::env::set_var("RUSTMQ_MAX_TOPIC_ALIAS", "123");
    std::env::set_var("RUSTMQ_INFLIGHT_LIMIT", "12");
    std::env::set_var("RUSTMQ_OFFLINE_QUEUE_LIMIT", "34");
    std::env::set_var("RUSTMQ_RETRY_INTERVAL_MS", "56");
    let cfg = Config::load(&path).unwrap();
    std::env::remove_var("RUSTMQ_MQTT_BIND");
    std::env::remove_var("RUSTMQ_MQTT_TLS_ENABLED");
    std::env::remove_var("RUSTMQ_MQTT_TLS_BIND");
    std::env::remove_var("RUSTMQ_MQTT_TLS_CERTFILE");
    std::env::remove_var("RUSTMQ_MQTT_TLS_KEYFILE");
    std::env::remove_var("RUSTMQ_MQTT_TLS_VERIFY_PEER");
    std::env::remove_var("RUSTMQ_MQTT_TLS_CACERTFILE");
    std::env::remove_var("RUSTMQ_MQTT_WS_ENABLED");
    std::env::remove_var("RUSTMQ_MQTT_WS_BIND");
    std::env::remove_var("RUSTMQ_MQTT_WS_PATH");
    std::env::remove_var("RUSTMQ_MQTT_QUIC_ENABLED");
    std::env::remove_var("RUSTMQ_MQTT_QUIC_BIND");
    std::env::remove_var("RUSTMQ_MQTT_QUIC_CERTFILE");
    std::env::remove_var("RUSTMQ_MQTT_QUIC_KEYFILE");
    std::env::remove_var("RUSTMQ_MQTT_QUIC_ENABLE_0RTT");
    std::env::remove_var("RUSTMQ_MQTT_QUIC_MIGRATION_ENABLED");
    std::env::remove_var("RUSTMQ_MQTT_QUIC_IDLE_TIMEOUT_MS");
    std::env::remove_var("RUSTMQ_MAX_TOPIC_ALIAS");
    std::env::remove_var("RUSTMQ_INFLIGHT_LIMIT");
    std::env::remove_var("RUSTMQ_OFFLINE_QUEUE_LIMIT");
    std::env::remove_var("RUSTMQ_RETRY_INTERVAL_MS");
    assert_eq!(cfg.mqtt.bind, "127.0.0.1:2883");
    assert!(cfg.mqtt_tls.enabled);
    assert_eq!(cfg.mqtt_tls.bind, "127.0.0.1:8884");
    assert_eq!(
        cfg.mqtt_tls.certfile.as_deref(),
        Some(std::path::Path::new("/tmp/rustmq-cert.pem"))
    );
    assert_eq!(
        cfg.mqtt_tls.keyfile.as_deref(),
        Some(std::path::Path::new("/tmp/rustmq-key.pem"))
    );
    assert!(cfg.mqtt_tls.verify_peer);
    assert_eq!(
        cfg.mqtt_tls.cacertfile.as_deref(),
        Some(std::path::Path::new("/tmp/rustmq-ca.pem"))
    );
    assert!(cfg.mqtt_ws.enabled);
    assert_eq!(cfg.mqtt_ws.bind, "127.0.0.1:8084");
    assert_eq!(cfg.mqtt_ws.path, "/custom-mqtt");
    assert!(cfg.mqtt_quic.enabled);
    assert_eq!(cfg.mqtt_quic.bind, "127.0.0.1:14568");
    assert_eq!(
        cfg.mqtt_quic.certfile.as_deref(),
        Some(std::path::Path::new("/tmp/rustmq-quic-cert.pem"))
    );
    assert_eq!(
        cfg.mqtt_quic.keyfile.as_deref(),
        Some(std::path::Path::new("/tmp/rustmq-quic-key.pem"))
    );
    assert!(!cfg.mqtt_quic.enable_0rtt);
    assert!(!cfg.mqtt_quic.migration_enabled);
    assert_eq!(cfg.mqtt_quic.idle_timeout_ms, 4321);
    assert_eq!(cfg.mqtt.max_packet_size, 2048);
    assert_eq!(cfg.mqtt.max_topic_alias, 123);
    assert_eq!(cfg.mqtt.inflight_limit, 12);
    assert_eq!(cfg.mqtt.offline_queue_limit, 34);
    assert_eq!(cfg.mqtt.retry_interval_ms, 56);
}

#[test]
fn mqtt_v5_unsuback_contains_one_reason_code_per_filter() {
    let encoded = encode_packet(
        &Packet::UnsubAck {
            packet_id: 9,
            codes: vec![0, 0],
        },
        ProtocolVersion::V5,
    )
    .unwrap();
    assert_eq!(encoded.as_ref(), &[0xb0, 5, 0, 9, 0, 0, 0]);
}

#[test]
fn mqtt_v5_subscription_options_are_decoded_and_validated() {
    let mut packet = BytesMut::from(&b"\x82\x09\x00\x01\x00\x00\x03a/+\x1d"[..]);
    let decoded = decode_packet(&mut packet, ProtocolVersion::V5, 1024)
        .unwrap()
        .unwrap();
    let Packet::Subscribe { filters, .. } = decoded else {
        panic!("expected subscribe");
    };
    assert_eq!(filters[0].qos, 1);
    assert!(filters[0].no_local);
    assert!(filters[0].retain_as_published);
    assert_eq!(filters[0].retain_handling, 1);

    let mut invalid = BytesMut::from(&b"\x82\x09\x00\x01\x00\x00\x03a/+\x40"[..]);
    assert!(decode_packet(&mut invalid, ProtocolVersion::V5, 1024).is_err());

    let filter = b"$share/g/a";
    let mut body = vec![0, 1, 0, 0, filter.len() as u8];
    body.extend_from_slice(filter);
    body.push(0x04);
    let mut shared = vec![0x82, body.len() as u8];
    shared.extend(body);
    assert!(decode_packet(
        &mut BytesMut::from(shared.as_slice()),
        ProtocolVersion::V5,
        1024,
    )
    .is_err());
}
