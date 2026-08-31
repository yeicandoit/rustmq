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

fn connect_v5(client: &str, receive_maximum: u16) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 5, 2, 0, 30, 3, 0x21];
    body.extend_from_slice(&receive_maximum.to_be_bytes());
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

fn subscribe_v5(id: u16, filter: &str, qos: u8) -> Vec<u8> {
    let mut body = id.to_be_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    body.extend_from_slice(filter.as_bytes());
    body.push(qos);
    frame(0x82, body)
}

fn publish_qos2(topic: &str, payload: &[u8], id: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    body.extend_from_slice(&id.to_be_bytes());
    body.extend_from_slice(payload);
    frame(0x34, body)
}

async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut header))
        .await
        .expect("packet timeout")
        .unwrap();
    let mut body = vec![0; usize::from(header[1])];
    stream.read_exact(&mut body).await.unwrap();
    let mut packet = header.to_vec();
    packet.extend(body);
    packet
}

fn publish_id(packet: &[u8]) -> u16 {
    let topic_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let offset = 4 + topic_len;
    u16::from_be_bytes([packet[offset], packet[offset + 1]])
}

async fn start() -> (rustmq::server::RunningServer, SocketAddr) {
    let mut config = Config::default();
    config.mqtt.bind = "127.0.0.1:0".into();
    config.http.bind = "127.0.0.1:0".into();
    config.mqtt.retry_interval_ms = 10_000;
    let running = spawn(config, Broker::with_limits(10, 10)).await.unwrap();
    let address = running.mqtt_addr;
    (running, address)
}

async fn complete_inbound_qos2(stream: &mut TcpStream, topic: &str, payload: &[u8], id: u16) {
    stream
        .write_all(&publish_qos2(topic, payload, id))
        .await
        .unwrap();
    assert_eq!(
        read_packet(stream).await,
        frame(0x50, id.to_be_bytes().to_vec())
    );
    stream
        .write_all(&frame(0x62, id.to_be_bytes().to_vec()))
        .await
        .unwrap();
    assert_eq!(
        read_packet(stream).await,
        frame(0x70, id.to_be_bytes().to_vec())
    );
}

#[tokio::test]
async fn receive_maximum_one_releases_slot_on_pubrec() {
    let (running, address) = start().await;
    let mut subscriber = TcpStream::connect(address).await.unwrap();
    subscriber
        .write_all(&connect_v5("rm-sub", 1))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;
    subscriber
        .write_all(&subscribe_v5(1, "rm/topic", 2))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;

    let mut publisher = TcpStream::connect(address).await.unwrap();
    publisher.write_all(&connect_v311("rm-pub")).await.unwrap();
    read_packet(&mut publisher).await;
    complete_inbound_qos2(&mut publisher, "rm/topic", b"first", 10).await;
    complete_inbound_qos2(&mut publisher, "rm/topic", b"second", 11).await;

    let first = read_packet(&mut subscriber).await;
    assert!(first.ends_with(b"first"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), read_packet(&mut subscriber))
            .await
            .is_err()
    );

    let first_id = publish_id(&first);
    subscriber
        .write_all(&frame(0x50, first_id.to_be_bytes().to_vec()))
        .await
        .unwrap();
    assert_eq!(
        read_packet(&mut subscriber).await,
        frame(0x62, first_id.to_be_bytes().to_vec())
    );

    let second = read_packet(&mut subscriber).await;
    assert!(second.ends_with(b"second"));
    let second_id = publish_id(&second);
    subscriber
        .write_all(&frame(0x50, second_id.to_be_bytes().to_vec()))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;
    subscriber
        .write_all(&frame(0x70, first_id.to_be_bytes().to_vec()))
        .await
        .unwrap();
    subscriber
        .write_all(&frame(0x70, second_id.to_be_bytes().to_vec()))
        .await
        .unwrap();

    drop(subscriber);
    drop(publisher);
    running.shutdown().await.unwrap();
}
