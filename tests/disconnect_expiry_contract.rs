use bytes::BytesMut;
use rustmq::protocol::{decode_packet, Packet, ProtocolVersion};

#[test]
fn mqtt_v5_disconnect_decodes_session_expiry_override() {
    let mut frame = BytesMut::from(&b"\xe0\x07\x00\x05\x11\x00\x00\x00\x3c"[..]);
    let packet = decode_packet(&mut frame, ProtocolVersion::V5, 1024)
        .unwrap()
        .unwrap();
    assert_eq!(
        packet,
        Packet::Disconnect {
            reason_code: 0,
            session_expiry_interval: Some(60),
        }
    );
}

#[test]
fn mqtt_v5_disconnect_rejects_duplicate_or_invalid_properties() {
    let mut duplicate =
        BytesMut::from(&b"\xe0\x0c\x00\x0a\x11\x00\x00\x00\x3c\x11\x00\x00\x00\x3d"[..]);
    assert!(decode_packet(&mut duplicate, ProtocolVersion::V5, 1024).is_err());

    let mut invalid = BytesMut::from(&b"\xe0\x04\x00\x02\x21\x01"[..]);
    assert!(decode_packet(&mut invalid, ProtocolVersion::V5, 1024).is_err());
}

#[test]
fn mqtt311_zero_length_disconnect_remains_supported() {
    let mut frame = BytesMut::from(&b"\xe0\x00"[..]);
    assert_eq!(
        decode_packet(&mut frame, ProtocolVersion::V311, 1024)
            .unwrap()
            .unwrap(),
        Packet::Disconnect {
            reason_code: 0,
            session_expiry_interval: None,
        }
    );
}
