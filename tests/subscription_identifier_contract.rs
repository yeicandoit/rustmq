use bytes::BytesMut;
use rustmq::protocol::{decode_packet, encode_packet, Packet, ProtocolVersion, Publish};

#[test]
fn subscribe_decodes_subscription_identifier() {
    // id=1, properties=[Subscription Identifier=321], filter=sid/#, qos1
    let mut packet = BytesMut::from(&b"\x82\x0e\x00\x01\x03\x0b\xc1\x02\x00\x05sid/#\x01"[..]);
    let decoded = decode_packet(&mut packet, ProtocolVersion::V5, 1024)
        .unwrap()
        .unwrap();
    let Packet::Subscribe {
        subscription_identifier,
        filters,
        ..
    } = decoded
    else {
        panic!("expected SUBSCRIBE");
    };
    assert_eq!(subscription_identifier, Some(321));
    assert_eq!(filters.len(), 1);
}

#[test]
fn subscribe_rejects_zero_duplicate_and_invalid_properties() {
    for raw in [
        &b"\x82\x0d\x00\x01\x02\x0b\x00\x00\x05sid/#\x00"[..],
        &b"\x82\x0f\x00\x01\x04\x0b\x01\x0b\x02\x00\x05sid/#\x00"[..],
        &b"\x82\x0d\x00\x01\x02\x11\x00\x00\x05sid/#\x00"[..],
    ] {
        assert!(decode_packet(&mut BytesMut::from(raw), ProtocolVersion::V5, 1024,).is_err());
    }
}

#[test]
fn publish_encodes_repeated_subscription_identifiers() {
    let encoded = encode_packet(
        &Packet::Publish(Publish {
            dup: false,
            qos: 0,
            retain: false,
            topic: "sid/topic".into(),
            packet_id: None,
            payload: b"value".to_vec().into(),
            expires_at: None,
            subscription_identifiers: vec![7, 321],
            topic_alias: None,
        }),
        ProtocolVersion::V5,
    )
    .unwrap();
    let bytes = encoded.as_ref();
    let topic_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    let props = 4 + topic_len;
    assert_eq!(bytes[props], 5); // 0x0b 0x07 + 0x0b 0xc1 0x02
    assert_eq!(
        &bytes[props + 1..props + 6],
        &[0x0b, 0x07, 0x0b, 0xc1, 0x02]
    );
}
