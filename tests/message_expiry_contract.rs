use std::time::{Duration, Instant};

use bytes::BytesMut;
use rustmq::protocol::{decode_packet, encode_packet, Packet, ProtocolVersion, Publish};

#[test]
fn mqtt_v5_publish_decodes_message_expiry_to_deadline() {
    let topic = b"expiry/topic";
    let payload = b"payload";
    let mut body = Vec::new();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic);
    body.extend_from_slice(&7_u16.to_be_bytes());
    body.extend_from_slice(&[5, 0x02, 0, 0, 0, 2]);
    body.extend_from_slice(payload);
    let mut frame = vec![0x32, body.len() as u8];
    frame.extend(body);

    let before = Instant::now();
    let Packet::Publish(publish) = decode_packet(
        &mut BytesMut::from(frame.as_slice()),
        ProtocolVersion::V5,
        1024,
    )
    .unwrap()
    .unwrap() else {
        panic!("expected PUBLISH");
    };
    let deadline = publish.expires_at.expect("expiry deadline");
    assert!(deadline >= before + Duration::from_millis(1800));
    assert!(deadline <= Instant::now() + Duration::from_millis(2200));
    assert_eq!(publish.payload.as_ref(), payload);
}

#[test]
fn mqtt_v5_publish_rejects_duplicate_or_invalid_properties() {
    let topic = b"t";
    let mut duplicate_body = Vec::new();
    duplicate_body.extend_from_slice(&1_u16.to_be_bytes());
    duplicate_body.extend_from_slice(topic);
    duplicate_body.extend_from_slice(&1_u16.to_be_bytes());
    duplicate_body.extend_from_slice(&[10, 0x02, 0, 0, 0, 1, 0x02, 0, 0, 0, 2]);
    let mut duplicate = vec![0x32, duplicate_body.len() as u8];
    duplicate.extend(duplicate_body);
    assert!(decode_packet(
        &mut BytesMut::from(duplicate.as_slice()),
        ProtocolVersion::V5,
        1024,
    )
    .is_err());

    let mut invalid_body = Vec::new();
    invalid_body.extend_from_slice(&1_u16.to_be_bytes());
    invalid_body.extend_from_slice(topic);
    invalid_body.extend_from_slice(&1_u16.to_be_bytes());
    invalid_body.extend_from_slice(&[2, 0x11, 0]);
    let mut invalid = vec![0x32, invalid_body.len() as u8];
    invalid.extend(invalid_body);
    assert!(decode_packet(
        &mut BytesMut::from(invalid.as_slice()),
        ProtocolVersion::V5,
        1024,
    )
    .is_err());
}

#[test]
fn mqtt_v5_publish_encodes_remaining_message_expiry() {
    let packet = Packet::Publish(Publish {
        dup: false,
        qos: 1,
        retain: false,
        topic: "expiry/topic".into(),
        packet_id: Some(9),
        payload: b"value".to_vec().into(),
        expires_at: Some(Instant::now() + Duration::from_secs(3)),
        subscription_identifiers: Vec::new(),
        topic_alias: None,
    });
    let encoded = encode_packet(&packet, ProtocolVersion::V5).unwrap();
    let bytes = encoded.as_ref();
    let topic_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    let properties = 4 + topic_len + 2;
    assert_eq!(bytes[properties], 5);
    assert_eq!(bytes[properties + 1], 0x02);
    let remaining = u32::from_be_bytes([
        bytes[properties + 2],
        bytes[properties + 3],
        bytes[properties + 4],
        bytes[properties + 5],
    ]);
    assert!((2..=3).contains(&remaining));
}
