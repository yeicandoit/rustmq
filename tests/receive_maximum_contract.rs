use bytes::BytesMut;
use rustmq::protocol::{decode_packet, Packet, ProtocolVersion};

fn connect_with_receive_maximum(values: &[u16]) -> Vec<u8> {
    let mut properties = Vec::new();
    for value in values {
        properties.push(0x21);
        properties.extend_from_slice(&value.to_be_bytes());
    }
    let client = b"receive-max";
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 5, 2, 0, 30];
    body.push(properties.len() as u8);
    body.extend(properties);
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client);
    let mut packet = vec![0x10, body.len() as u8];
    packet.extend(body);
    packet
}

#[test]
fn mqtt_v5_connect_decodes_receive_maximum() {
    let frame = connect_with_receive_maximum(&[7]);
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
    assert_eq!(connect.receive_maximum, 7);
}

#[test]
fn mqtt_v5_connect_defaults_receive_maximum_to_65535() {
    let frame = connect_with_receive_maximum(&[]);
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
    assert_eq!(connect.receive_maximum, u16::MAX);
}

#[test]
fn mqtt_v5_connect_rejects_zero_or_duplicate_receive_maximum() {
    for values in [&[0_u16][..], &[1_u16, 2][..]] {
        let frame = connect_with_receive_maximum(values);
        assert!(decode_packet(
            &mut BytesMut::from(frame.as_slice()),
            ProtocolVersion::V311,
            1024,
        )
        .is_err());
    }
}
