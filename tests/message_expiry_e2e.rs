use std::{net::SocketAddr, time::Duration};

use rustmq::{broker::Broker, config::Config, server::spawn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn frame(header: u8, body: Vec<u8>) -> Vec<u8> {
    assert!(body.len() < 128);
    let mut packet = vec![header, body.len() as u8];
    packet.extend(body);
    packet
}

fn connect_v5(client: &str, clean: bool, session_expiry: u32) -> Vec<u8> {
    let mut properties = vec![0x11];
    properties.extend_from_slice(&session_expiry.to_be_bytes());
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
    ];
    body.push(properties.len() as u8);
    body.extend(properties);
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    frame(0x10, body)
}

fn subscribe(id: u16, filter: &str, qos: u8) -> Vec<u8> {
    let mut body = id.to_be_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    body.extend_from_slice(filter.as_bytes());
    body.push(qos);
    frame(0x82, body)
}

fn publish(topic: &str, payload: &[u8], id: u16, retain: bool, expiry: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    body.extend_from_slice(&id.to_be_bytes());
    body.extend_from_slice(&[5, 0x02]);
    body.extend_from_slice(&expiry.to_be_bytes());
    body.extend_from_slice(payload);
    frame(0x32 | u8::from(retain), body)
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

async fn start() -> (rustmq::server::RunningServer, SocketAddr) {
    let mut config = Config::default();
    config.mqtt.bind = "127.0.0.1:0".into();
    config.http.bind = "127.0.0.1:0".into();
    config.mqtt.retry_interval_ms = 10_000;
    let running = spawn(config, Broker::new()).await.unwrap();
    let address = running.mqtt_addr;
    (running, address)
}

async fn open(address: SocketAddr, client: &str, clean: bool, expiry: u32) -> (TcpStream, Vec<u8>) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(&connect_v5(client, clean, expiry))
        .await
        .unwrap();
    let connack = read_packet(&mut stream).await;
    (stream, connack)
}

#[tokio::test]
async fn expired_offline_message_is_not_replayed() {
    let (running, address) = start().await;
    let (mut subscriber, _) = open(address, "expiry-offline", true, 60).await;
    subscriber
        .write_all(&subscribe(1, "expiry/offline", 1))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;
    subscriber
        .write_all(&frame(0xe0, Vec::new()))
        .await
        .unwrap();
    drop(subscriber);
    tokio::time::sleep(Duration::from_millis(30)).await;

    let (mut publisher, _) = open(address, "expiry-publisher", true, 0).await;
    publisher
        .write_all(&publish("expiry/offline", b"expired", 7, false, 1))
        .await
        .unwrap();
    read_packet(&mut publisher).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let (mut resumed, connack) = open(address, "expiry-offline", false, 60).await;
    assert_eq!(connack, vec![0x20, 6, 1, 0, 3, 0x22, 0xff, 0xff]);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), read_packet(&mut resumed))
            .await
            .is_err()
    );

    drop(resumed);
    drop(publisher);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn expired_retained_message_is_not_replayed() {
    let (running, address) = start().await;
    let (mut publisher, _) = open(address, "expiry-retained-pub", true, 0).await;
    publisher
        .write_all(&publish("expiry/retained", b"retained", 8, true, 1))
        .await
        .unwrap();
    read_packet(&mut publisher).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let (mut subscriber, _) = open(address, "expiry-retained-sub", true, 0).await;
    subscriber
        .write_all(&subscribe(2, "expiry/#", 1))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), read_packet(&mut subscriber))
            .await
            .is_err()
    );

    drop(subscriber);
    drop(publisher);
    running.shutdown().await.unwrap();
}
