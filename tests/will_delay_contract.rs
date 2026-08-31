use bytes::BytesMut;
use rustmq::protocol::{decode_packet, Packet, ProtocolVersion};

fn connect_with_will_properties(properties: &[u8]) -> Vec<u8> {
    let client = b"will-properties";
    let topic = b"will/topic";
    let payload = b"will-payload";
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 5, 6, 0, 30, 0];
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client);
    body.push(properties.len() as u8);
    body.extend_from_slice(properties);
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic);
    body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    body.extend_from_slice(payload);
    let mut packet = vec![0x10, body.len() as u8];
    packet.extend(body);
    packet
}

#[test]
fn mqtt_v5_connect_decodes_will_delay_and_message_expiry() {
    let properties = [0x18, 0, 0, 0, 5, 0x02, 0, 0, 0, 9];
    let frame = connect_with_will_properties(&properties);
    let packet = decode_packet(
        &mut BytesMut::from(frame.as_slice()),
        ProtocolVersion::V311,
        1024,
    )
    .unwrap()
    .unwrap();
    let Packet::Connect(connect) = packet else {
        panic!("expected CONNECT");
    };
    let will = connect.will.expect("will");
    assert_eq!(will.delay_interval, 5);
    assert_eq!(will.message_expiry_interval, Some(9));
}

#[test]
fn mqtt_v5_connect_rejects_duplicate_or_invalid_will_properties() {
    let duplicate_delay = [0x18, 0, 0, 0, 1, 0x18, 0, 0, 0, 2];
    let frame = connect_with_will_properties(&duplicate_delay);
    assert!(decode_packet(
        &mut BytesMut::from(frame.as_slice()),
        ProtocolVersion::V311,
        1024,
    )
    .is_err());

    let invalid_property = [0x11, 0, 0, 0, 1];
    let frame = connect_with_will_properties(&invalid_property);
    assert!(decode_packet(
        &mut BytesMut::from(frame.as_slice()),
        ProtocolVersion::V311,
        1024,
    )
    .is_err());
}
