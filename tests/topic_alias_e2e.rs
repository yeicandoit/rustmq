use std::{net::SocketAddr, time::Duration};

use bytes::BytesMut;
use rustmq::{
    broker::Broker,
    config::Config,
    protocol::{decode_packet, Packet, ProtocolVersion},
    server::spawn,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn frame(header: u8, body: Vec<u8>) -> Vec<u8> {
    let mut packet = vec![header, body.len() as u8];
    packet.extend(body);
    packet
}

fn connect(client: &str, version: u8) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', version, 2, 0, 30];
    if version == 5 {
        body.push(0);
    }
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    frame(0x10, body)
}

fn connect_v5_with_topic_alias_maximum(client: &str, maximum: u16) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 5, 2, 0, 30, 3, 0x22];
    body.extend_from_slice(&maximum.to_be_bytes());
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    frame(0x10, body)
}

fn subscribe_v311(packet_id: u16, filter: &str) -> Vec<u8> {
    let mut body = packet_id.to_be_bytes().to_vec();
    body.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    body.extend_from_slice(filter.as_bytes());
    body.push(0);
    frame(0x82, body)
}

fn subscribe_v5(packet_id: u16, filter: &str) -> Vec<u8> {
    let mut body = packet_id.to_be_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    body.extend_from_slice(filter.as_bytes());
    body.push(0);
    frame(0x82, body)
}

fn publish_v5(topic: &str, alias: u16, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    body.extend_from_slice(&[3, 0x23]);
    body.extend_from_slice(&alias.to_be_bytes());
    body.extend_from_slice(payload);
    frame(0x30, body)
}

fn publish_v5_without_alias(topic: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    body.push(0);
    body.extend_from_slice(payload);
    frame(0x30, body)
}

fn publish_v311(topic: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    body.extend_from_slice(payload);
    frame(0x30, body)
}

async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
    let mut first = [0_u8; 1];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut first))
        .await
        .expect("packet timeout")
        .unwrap();
    let mut encoded = vec![first[0]];
    let mut remaining = 0_usize;
    let mut multiplier = 1_usize;
    loop {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        encoded.push(byte[0]);
        remaining += usize::from(byte[0] & 0x7f) * multiplier;
        if byte[0] & 0x80 == 0 {
            break;
        }
        multiplier *= 128;
    }
    let mut body = vec![0; remaining];
    stream.read_exact(&mut body).await.unwrap();
    encoded.extend(body);
    encoded
}

fn publish_topic(packet: &[u8]) -> &str {
    let topic_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    std::str::from_utf8(&packet[4..4 + topic_len]).unwrap()
}

fn publish_topic_alias(packet: &[u8]) -> Option<u16> {
    let topic_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let property_length_index = 4 + topic_len;
    match packet[property_length_index] {
        0 => None,
        3 => {
            assert_eq!(packet[property_length_index + 1], 0x23);
            Some(u16::from_be_bytes([
                packet[property_length_index + 2],
                packet[property_length_index + 3],
            ]))
        }
        length => panic!("unexpected property length {length}"),
    }
}

async fn start() -> (rustmq::server::RunningServer, SocketAddr) {
    let mut config = Config::default();
    config.mqtt.bind = "127.0.0.1:0".into();
    config.http.bind = "127.0.0.1:0".into();
    start_with_config(config).await
}

async fn start_with_config(config: Config) -> (rustmq::server::RunningServer, SocketAddr) {
    let running = spawn(config, Broker::new()).await.unwrap();
    let address = running.mqtt_addr;
    (running, address)
}

#[test]
fn mqtt_v5_connect_decodes_and_validates_topic_alias_maximum() {
    let mut packet = BytesMut::from(&connect_v5_with_topic_alias_maximum("alias-codec", 12)[..]);
    let decoded = decode_packet(&mut packet, ProtocolVersion::V311, 1024)
        .unwrap()
        .unwrap();
    let Packet::Connect(connect) = decoded else {
        panic!("expected CONNECT");
    };
    assert_eq!(connect.topic_alias_maximum, 12);

    let mut body = vec![
        0, 4, b'M', b'Q', b'T', b'T', 5, 2, 0, 30, 6, 0x22, 0, 1, 0x22, 0, 2,
    ];
    body.extend_from_slice(&[0, 3, b'd', b'u', b'p']);
    assert!(decode_packet(
        &mut BytesMut::from(frame(0x10, body).as_slice()),
        ProtocolVersion::V311,
        1024,
    )
    .is_err());
}

#[tokio::test]
async fn mqtt_v5_registers_and_reuses_inbound_topic_alias() {
    let (running, address) = start().await;

    let mut subscriber = TcpStream::connect(address).await.unwrap();
    subscriber
        .write_all(&connect("alias-sub", 4))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;
    subscriber
        .write_all(&subscribe_v311(1, "alias/#"))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;

    let mut publisher = TcpStream::connect(address).await.unwrap();
    publisher.write_all(&connect("alias-pub", 5)).await.unwrap();
    let connack = read_packet(&mut publisher).await;
    assert_eq!(connack, [0x20, 6, 0, 0, 3, 0x22, 0xff, 0xff]);

    publisher
        .write_all(&publish_v5("alias/topic", 1, b"registered"))
        .await
        .unwrap();
    let registered = read_packet(&mut subscriber).await;
    assert_eq!(publish_topic(&registered), "alias/topic");
    assert!(registered.ends_with(b"registered"));

    publisher
        .write_all(&publish_v5("", 1, b"reused"))
        .await
        .unwrap();
    let reused = read_packet(&mut subscriber).await;
    assert_eq!(publish_topic(&reused), "alias/topic");
    assert!(reused.ends_with(b"reused"));

    drop(subscriber);
    drop(publisher);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn mqtt_v5_rejects_alias_above_advertised_maximum() {
    let mut config = Config::default();
    config.mqtt.bind = "127.0.0.1:0".into();
    config.http.bind = "127.0.0.1:0".into();
    config.mqtt.max_topic_alias = 1;
    let (running, address) = start_with_config(config).await;

    let mut publisher = TcpStream::connect(address).await.unwrap();
    publisher
        .write_all(&connect("alias-limit", 5))
        .await
        .unwrap();
    assert_eq!(
        read_packet(&mut publisher).await,
        [0x20, 6, 0, 0, 3, 0x22, 0, 1]
    );
    publisher
        .write_all(&publish_v5("alias/topic", 2, b"invalid"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut publisher).await, [0xe0, 2, 0x94, 0]);

    drop(publisher);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn mqtt_v5_rejects_unknown_alias_and_empty_topic_without_alias() {
    let (running, address) = start().await;

    let mut unknown = TcpStream::connect(address).await.unwrap();
    unknown
        .write_all(&connect("alias-unknown", 5))
        .await
        .unwrap();
    read_packet(&mut unknown).await;
    unknown
        .write_all(&publish_v5("", 1, b"unknown"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut unknown).await, [0xe0, 2, 0x82, 0]);

    let mut missing = TcpStream::connect(address).await.unwrap();
    missing
        .write_all(&connect("alias-missing", 5))
        .await
        .unwrap();
    read_packet(&mut missing).await;
    missing
        .write_all(&publish_v5_without_alias("", b"missing"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut missing).await, [0xe0, 2, 0x82, 0]);

    drop(unknown);
    drop(missing);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn mqtt_v5_topic_aliases_are_isolated_per_connection() {
    let (running, address) = start().await;

    let mut first = TcpStream::connect(address).await.unwrap();
    first.write_all(&connect("alias-first", 5)).await.unwrap();
    read_packet(&mut first).await;
    first
        .write_all(&publish_v5("alias/topic", 1, b"registered"))
        .await
        .unwrap();
    first.write_all(&[0xc0, 0]).await.unwrap();
    assert_eq!(read_packet(&mut first).await, [0xd0, 0]);

    let mut second = TcpStream::connect(address).await.unwrap();
    second.write_all(&connect("alias-second", 5)).await.unwrap();
    read_packet(&mut second).await;
    second
        .write_all(&publish_v5("", 1, b"not-shared"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut second).await, [0xe0, 2, 0x82, 0]);

    drop(first);
    drop(second);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn mqtt_v5_packs_repeated_outbound_topics_with_client_alias_limit() {
    let (running, address) = start().await;

    let mut subscriber = TcpStream::connect(address).await.unwrap();
    subscriber
        .write_all(&connect_v5_with_topic_alias_maximum("outbound-alias", 1))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;
    subscriber
        .write_all(&subscribe_v5(1, "outbound/#"))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;

    let mut publisher = TcpStream::connect(address).await.unwrap();
    publisher
        .write_all(&connect("outbound-publisher", 4))
        .await
        .unwrap();
    read_packet(&mut publisher).await;

    publisher
        .write_all(&publish_v311("outbound/topic", b"first"))
        .await
        .unwrap();
    let first = read_packet(&mut subscriber).await;
    assert_eq!(publish_topic(&first), "outbound/topic");
    assert_eq!(publish_topic_alias(&first), Some(1));

    publisher
        .write_all(&publish_v311("outbound/topic", b"second"))
        .await
        .unwrap();
    let second = read_packet(&mut subscriber).await;
    assert_eq!(publish_topic(&second), "");
    assert_eq!(publish_topic_alias(&second), Some(1));

    publisher
        .write_all(&publish_v311("outbound/other", b"limit"))
        .await
        .unwrap();
    let limit = read_packet(&mut subscriber).await;
    assert_eq!(publish_topic(&limit), "outbound/other");
    assert_eq!(publish_topic_alias(&limit), None);

    drop(subscriber);
    drop(publisher);
    running.shutdown().await.unwrap();
}
