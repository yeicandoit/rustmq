use std::{net::SocketAddr, time::Duration};

use rustmq::{broker::Broker, config::Config, server::spawn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn frame(header: u8, body: Vec<u8>) -> Vec<u8> {
    let mut packet = vec![header, body.len() as u8];
    packet.extend(body);
    packet
}

fn connect_v5(client: &str) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 5, 2, 0, 30, 0];
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    frame(0x10, body)
}

fn connect_v311(client: &str) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 2, 0, 30];
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    frame(0x10, body)
}

fn subscribe_v5(packet_id: u16, filter: &str, identifier: u32) -> Vec<u8> {
    let mut props = vec![0x0b];
    put_varint(identifier, &mut props);
    let mut body = packet_id.to_be_bytes().to_vec();
    body.push(props.len() as u8);
    body.extend(props);
    body.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    body.extend_from_slice(filter.as_bytes());
    body.push(0);
    frame(0x82, body)
}

fn publish_v311(topic: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    body.extend_from_slice(payload);
    frame(0x30, body)
}

fn put_varint(mut value: u32, output: &mut Vec<u8>) {
    loop {
        let mut byte = (value % 128) as u8;
        value /= 128;
        if value > 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn read_varint(data: &[u8], index: &mut usize) -> usize {
    let mut value = 0_usize;
    let mut multiplier = 1_usize;
    loop {
        let byte = data[*index];
        *index += 1;
        value += usize::from(byte & 0x7f) * multiplier;
        if byte & 0x80 == 0 {
            return value;
        }
        multiplier *= 128;
    }
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

fn subscription_identifiers(packet: &[u8]) -> Vec<u32> {
    let mut index = 1;
    let _remaining = read_varint(packet, &mut index);
    let topic_len = usize::from(u16::from_be_bytes([packet[index], packet[index + 1]]));
    index += 2 + topic_len;
    let properties_len = read_varint(packet, &mut index);
    let end = index + properties_len;
    let mut identifiers = Vec::new();
    while index < end {
        let property = read_varint(packet, &mut index);
        assert_eq!(property, 0x0b);
        identifiers.push(read_varint(packet, &mut index) as u32);
    }
    identifiers
}

async fn start() -> (rustmq::server::RunningServer, SocketAddr) {
    let mut config = Config::default();
    config.mqtt.bind = "127.0.0.1:0".into();
    config.http.bind = "127.0.0.1:0".into();
    let running = spawn(config, Broker::new()).await.unwrap();
    let address = running.mqtt_addr;
    (running, address)
}

#[tokio::test]
async fn overlapping_subscriptions_emit_all_identifiers_once() {
    let (running, address) = start().await;
    let mut subscriber = TcpStream::connect(address).await.unwrap();
    subscriber
        .write_all(&connect_v5("sid-e2e-sub"))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;
    subscriber
        .write_all(&subscribe_v5(1, "sid/#", 7))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;
    subscriber
        .write_all(&subscribe_v5(2, "sid/topic", 321))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;

    let mut publisher = TcpStream::connect(address).await.unwrap();
    publisher
        .write_all(&connect_v311("sid-e2e-pub"))
        .await
        .unwrap();
    read_packet(&mut publisher).await;
    publisher
        .write_all(&publish_v311("sid/topic", b"identified"))
        .await
        .unwrap();

    let publish = read_packet(&mut subscriber).await;
    assert!(publish.ends_with(b"identified"));
    assert_eq!(subscription_identifiers(&publish), vec![7, 321]);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), read_packet(&mut subscriber))
            .await
            .is_err()
    );

    drop(subscriber);
    drop(publisher);
    running.shutdown().await.unwrap();
}
