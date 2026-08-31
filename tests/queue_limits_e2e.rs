use std::{net::SocketAddr, sync::atomic::Ordering, time::Duration};

use rustmq::{broker::Broker, config::Config, server::spawn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn connect_v311(client: &str, clean: bool) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, if clean { 2 } else { 0 }];
    body.extend_from_slice(&30_u16.to_be_bytes());
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    frame(0x10, body)
}

fn connect_v5(client: &str, clean: bool, expiry: u32) -> Vec<u8> {
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
        5,
        0x11,
    ];
    body.extend_from_slice(&expiry.to_be_bytes());
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    frame(0x10, body)
}

fn subscribe(id: u16, filter: &str, qos: u8, v5: bool) -> Vec<u8> {
    let mut body = id.to_be_bytes().to_vec();
    if v5 {
        body.push(0);
    }
    body.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    body.extend_from_slice(filter.as_bytes());
    body.push(qos);
    frame(0x82, body)
}

fn publish(topic: &str, payload: &[u8], qos: u8, id: Option<u16>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    if let Some(id) = id {
        body.extend_from_slice(&id.to_be_bytes());
    }
    body.extend_from_slice(payload);
    frame(0x30 | (qos << 1), body)
}

fn frame(header: u8, body: Vec<u8>) -> Vec<u8> {
    assert!(body.len() < 128);
    let mut packet = vec![header, body.len() as u8];
    packet.extend(body);
    packet
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

async fn open_v311(address: SocketAddr, id: &str, clean: bool) -> (TcpStream, Vec<u8>) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&connect_v311(id, clean)).await.unwrap();
    let connack = read_packet(&mut stream).await;
    (stream, connack)
}

async fn open_v5(address: SocketAddr, id: &str, clean: bool, expiry: u32) -> (TcpStream, Vec<u8>) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(&connect_v5(id, clean, expiry))
        .await
        .unwrap();
    let connack = read_packet(&mut stream).await;
    (stream, connack)
}

async fn start(
    inflight: usize,
    queue: usize,
) -> (rustmq::server::RunningServer, Broker, SocketAddr) {
    let mut config = Config::default();
    config.mqtt.bind = "127.0.0.1:0".into();
    config.http.bind = "127.0.0.1:0".into();
    config.mqtt.retry_interval_ms = 1_000;
    let broker = Broker::with_limits(inflight, queue);
    let running = spawn(config, broker.clone()).await.unwrap();
    let address = running.mqtt_addr;
    (running, broker, address)
}

#[tokio::test]
async fn puback_advances_online_message_waiting_for_inflight_slot() {
    let (running, _broker, address) = start(2, 8).await;
    let (mut subscriber, _) = open_v311(address, "window-sub", true).await;
    subscriber
        .write_all(&subscribe(1, "window/topic", 1, false))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;
    let (mut publisher, _) = open_v311(address, "window-pub", true).await;

    for (id, payload) in [(10, b"one".as_slice()), (11, b"two"), (12, b"three")] {
        publisher
            .write_all(&publish("window/topic", payload, 1, Some(id)))
            .await
            .unwrap();
        read_packet(&mut publisher).await;
    }

    let first = read_packet(&mut subscriber).await;
    let second = read_packet(&mut subscriber).await;
    assert!(first.ends_with(b"one"));
    assert!(second.ends_with(b"two"));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), read_packet(&mut subscriber))
            .await
            .is_err()
    );

    let id = publish_id(&first);
    subscriber
        .write_all(&[0x40, 2, (id >> 8) as u8, id as u8])
        .await
        .unwrap();
    assert!(read_packet(&mut subscriber).await.ends_with(b"three"));

    drop(subscriber);
    drop(publisher);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn bounded_offline_queue_drops_oldest_message() {
    let (running, broker, address) = start(1, 1).await;
    let (mut subscriber, _) = open_v311(address, "bounded-sub", false).await;
    subscriber
        .write_all(&subscribe(2, "bounded/topic", 1, false))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;
    subscriber.write_all(&[0xe0, 0]).await.unwrap();
    drop(subscriber);
    tokio::time::sleep(Duration::from_millis(30)).await;

    let (mut publisher, _) = open_v311(address, "bounded-pub", true).await;
    for (id, payload) in [(20, b"old".as_slice()), (21, b"new")] {
        publisher
            .write_all(&publish("bounded/topic", payload, 1, Some(id)))
            .await
            .unwrap();
        read_packet(&mut publisher).await;
    }

    let (mut resumed, connack) = open_v311(address, "bounded-sub", false).await;
    assert_eq!(connack, vec![0x20, 2, 1, 0]);
    assert!(read_packet(&mut resumed).await.ends_with(b"new"));
    assert_eq!(broker.metrics().dropped.load(Ordering::Relaxed), 1);

    drop(resumed);
    drop(publisher);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn expired_session_does_not_queue_late_messages() {
    let (running, _broker, address) = start(1, 8).await;
    let (mut subscriber, _) = open_v5(address, "expired-sub", true, 1).await;
    subscriber
        .write_all(&subscribe(3, "expired/topic", 1, true))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;
    subscriber.write_all(&[0xe0, 0]).await.unwrap();
    drop(subscriber);
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let (mut publisher, _) = open_v311(address, "late-pub", true).await;
    publisher
        .write_all(&publish("expired/topic", b"late", 1, Some(30)))
        .await
        .unwrap();
    read_packet(&mut publisher).await;

    let (mut resumed, connack) = open_v5(address, "expired-sub", false, 1).await;
    assert_eq!(connack, vec![0x20, 6, 0, 0, 3, 0x22, 0xff, 0xff]);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), read_packet(&mut resumed))
            .await
            .is_err()
    );

    drop(resumed);
    drop(publisher);
    running.shutdown().await.unwrap();
}
