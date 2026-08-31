use bytes::BytesMut;
use rustmq::protocol::{decode_packet, Packet, ProtocolVersion};

fn connect_v5(client: &str, expiry_values: &[u32]) -> Vec<u8> {
    let mut properties = Vec::new();
    for expiry in expiry_values {
        properties.push(0x11);
        properties.extend_from_slice(&expiry.to_be_bytes());
    }
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 5, 2, 0, 30];
    body.push(properties.len() as u8);
    body.extend(properties);
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    let mut frame = vec![0x10, body.len() as u8];
    frame.extend(body);
    frame
}

#[test]
fn mqtt_v5_connect_decodes_session_expiry() {
    let frame = connect_v5("expiry-client", &[60]);
    let packet = decode_packet(
        &mut BytesMut::from(frame.as_slice()),
        ProtocolVersion::V311,
        1024,
    )
    .unwrap()
    .unwrap();
    let Packet::Connect(connect) = packet else {
        panic!("expected connect");
    };
    assert_eq!(connect.session_expiry_interval, 60);
}

#[test]
fn mqtt_v5_connect_rejects_duplicate_session_expiry() {
    let frame = connect_v5("expiry-client", &[60, 61]);
    assert!(decode_packet(
        &mut BytesMut::from(frame.as_slice()),
        ProtocolVersion::V311,
        1024,
    )
    .is_err());
}
