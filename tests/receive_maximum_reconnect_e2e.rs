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

fn connect_v5(client: &str, clean: bool, receive_maximum: u16, expiry: u32) -> Vec<u8> {
    let mut properties = vec![0x21];
    properties.extend_from_slice(&receive_maximum.to_be_bytes());
    properties.push(0x11);
    properties.extend_from_slice(&expiry.to_be_bytes());
    let mut body = vec![
        0,
        4,
        b'M',
        b'Q',
        b'T',
        b'T',
        5,
        if clean { 2 } else { 0 },
        0,
        30,
        properties.len() as u8,
    ];
    body.extend(properties);
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

fn subscribe_v5(id: u16, filter: &str) -> Vec<u8> {
    let mut body = id.to_be_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    body.extend_from_slice(filter.as_bytes());
    body.push(1);
    frame(0x82, body)
}

fn publish_qos1(topic: &str, payload: &[u8], id: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    body.extend_from_slice(&id.to_be_bytes());
    body.extend_from_slice(payload);
    frame(0x32, body)
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

async fn open_v5(
    address: SocketAddr,
    client: &str,
    clean: bool,
    receive_maximum: u16,
) -> (TcpStream, Vec<u8>) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(&connect_v5(client, clean, receive_maximum, 60))
        .await
        .unwrap();
    let connack = read_packet(&mut stream).await;
    (stream, connack)
}

#[tokio::test]
async fn reconnect_with_smaller_receive_maximum_replays_incrementally() {
    let (running, address) = start().await;
    let (mut subscriber, _) = open_v5(address, "rm-resume", true, 3).await;
    subscriber
        .write_all(&subscribe_v5(1, "rm/resume"))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;

    let mut publisher = TcpStream::connect(address).await.unwrap();
    publisher
        .write_all(&connect_v311("rm-resume-pub"))
        .await
        .unwrap();
    read_packet(&mut publisher).await;
    for (id, payload) in [(10, b"one".as_slice()), (11, b"two"), (12, b"three")] {
        publisher
            .write_all(&publish_qos1("rm/resume", payload, id))
            .await
            .unwrap();
        assert_eq!(
            read_packet(&mut publisher).await,
            frame(0x40, id.to_be_bytes().to_vec())
        );
    }

    let first_original = read_packet(&mut subscriber).await;
    let second_original = read_packet(&mut subscriber).await;
    let third_original = read_packet(&mut subscriber).await;
    assert!(first_original.ends_with(b"one"));
    assert!(second_original.ends_with(b"two"));
    assert!(third_original.ends_with(b"three"));
    subscriber
        .write_all(&frame(0xe0, Vec::new()))
        .await
        .unwrap();
    drop(subscriber);
    tokio::time::sleep(Duration::from_millis(30)).await;

    let (mut resumed, connack) = open_v5(address, "rm-resume", false, 1).await;
    assert_eq!(connack, vec![0x20, 6, 1, 0, 3, 0x22, 0xff, 0xff]);
    let first = read_packet(&mut resumed).await;
    assert!(first.ends_with(b"one"));
    assert_ne!(first[0] & 0x08, 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), read_packet(&mut resumed))
            .await
            .is_err()
    );

    let first_id = publish_id(&first);
    resumed
        .write_all(&frame(0x40, first_id.to_be_bytes().to_vec()))
        .await
        .unwrap();
    let second = read_packet(&mut resumed).await;
    assert!(second.ends_with(b"two"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), read_packet(&mut resumed))
            .await
            .is_err()
    );

    let second_id = publish_id(&second);
    resumed
        .write_all(&frame(0x40, second_id.to_be_bytes().to_vec()))
        .await
        .unwrap();
    let third = read_packet(&mut resumed).await;
    assert!(third.ends_with(b"three"));

    let third_id = publish_id(&third);
    resumed
        .write_all(&frame(0x40, third_id.to_be_bytes().to_vec()))
        .await
        .unwrap();
    drop(resumed);
    drop(publisher);
    running.shutdown().await.unwrap();
}
