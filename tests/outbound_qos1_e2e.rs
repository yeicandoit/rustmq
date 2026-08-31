use std::{net::SocketAddr, time::Duration};

use rustmq::{broker::Broker, config::Config, server::spawn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn connect(client: &str, clean: bool) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, if clean { 2 } else { 0 }];
    body.extend_from_slice(&30_u16.to_be_bytes());
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    let mut packet = vec![0x10, body.len() as u8];
    packet.extend(body);
    packet
}

fn subscribe(id: u16, filter: &str, qos: u8) -> Vec<u8> {
    let length = 2 + 2 + filter.len() + 1;
    let mut packet = vec![0x82, length as u8];
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    packet.extend_from_slice(filter.as_bytes());
    packet.push(qos);
    packet
}

fn publish(topic: &str, payload: &[u8], qos: u8, packet_id: Option<u16>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    if let Some(id) = packet_id {
        body.extend_from_slice(&id.to_be_bytes());
    }
    body.extend_from_slice(payload);
    let mut packet = vec![0x30 | (qos << 1), body.len() as u8];
    packet.extend(body);
    packet
}

async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
    let mut first = [0_u8; 1];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut first))
        .await
        .expect("packet timeout")
        .unwrap();
    let mut packet = vec![first[0]];
    let mut remaining = 0_usize;
    let mut multiplier = 1_usize;
    loop {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        packet.push(byte[0]);
        remaining += usize::from(byte[0] & 0x7f) * multiplier;
        if byte[0] & 0x80 == 0 {
            break;
        }
        multiplier *= 128;
    }
    let mut body = vec![0; remaining];
    stream.read_exact(&mut body).await.unwrap();
    packet.extend(body);
    packet
}

fn publish_packet_id(packet: &[u8]) -> u16 {
    assert_eq!(packet[0] & 0x06, 0x02, "expected QoS 1 PUBLISH");
    let topic_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let offset = 4 + topic_length;
    u16::from_be_bytes([packet[offset], packet[offset + 1]])
}

async fn open(address: SocketAddr, client: &str, clean: bool) -> (TcpStream, Vec<u8>) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&connect(client, clean)).await.unwrap();
    let connack = read_packet(&mut stream).await;
    (stream, connack)
}

async fn start() -> (rustmq::server::RunningServer, SocketAddr) {
    let mut config = Config::default();
    config.mqtt.bind = "127.0.0.1:0".into();
    config.http.bind = "127.0.0.1:0".into();
    config.mqtt.retry_interval_ms = 100;
    let running = spawn(config, Broker::with_limits(2, 8)).await.unwrap();
    let address = running.mqtt_addr;
    (running, address)
}

#[tokio::test]
async fn unacked_qos1_is_retried_with_same_packet_id_and_dup() {
    let (running, address) = start().await;
    let (mut subscriber, _) = open(address, "retry-sub", true).await;
    subscriber
        .write_all(&subscribe(1, "retry/topic", 1))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;

    let (mut publisher, _) = open(address, "retry-pub", true).await;
    publisher
        .write_all(&publish("retry/topic", b"message", 1, Some(7)))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut publisher).await[0], 0x40);

    let first = read_packet(&mut subscriber).await;
    assert_eq!(first[0] & 0x08, 0, "first delivery must not set DUP");
    let packet_id = publish_packet_id(&first);
    let retry = read_packet(&mut subscriber).await;
    assert_ne!(retry[0] & 0x08, 0, "retry must set DUP");
    assert_eq!(publish_packet_id(&retry), packet_id);

    subscriber
        .write_all(&[0x40, 2, (packet_id >> 8) as u8, packet_id as u8])
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(250), read_packet(&mut subscriber))
            .await
            .is_err()
    );

    drop(subscriber);
    drop(publisher);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn persistent_session_replays_inflight_then_offline_queue() {
    let (running, address) = start().await;
    let (mut subscriber, _) = open(address, "offline-sub", false).await;
    subscriber
        .write_all(&subscribe(2, "offline/topic", 1))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;

    let (mut publisher, _) = open(address, "offline-pub", true).await;
    publisher
        .write_all(&publish("offline/topic", b"inflight", 1, Some(8)))
        .await
        .unwrap();
    read_packet(&mut publisher).await;
    let inflight = read_packet(&mut subscriber).await;
    let inflight_id = publish_packet_id(&inflight);
    subscriber.write_all(&[0xe0, 0]).await.unwrap();
    drop(subscriber);
    tokio::time::sleep(Duration::from_millis(30)).await;

    publisher
        .write_all(&publish("offline/topic", b"queued", 1, Some(9)))
        .await
        .unwrap();
    read_packet(&mut publisher).await;

    let (mut resumed, connack) = open(address, "offline-sub", false).await;
    assert_eq!(connack, vec![0x20, 0x02, 1, 0]);
    let replay = read_packet(&mut resumed).await;
    assert_ne!(replay[0] & 0x08, 0);
    assert_eq!(publish_packet_id(&replay), inflight_id);
    assert!(replay.ends_with(b"inflight"));
    resumed
        .write_all(&[0x40, 2, (inflight_id >> 8) as u8, inflight_id as u8])
        .await
        .unwrap();

    let queued = read_packet(&mut resumed).await;
    assert!(queued.ends_with(b"queued"));
    let queued_id = publish_packet_id(&queued);
    resumed
        .write_all(&[0x40, 2, (queued_id >> 8) as u8, queued_id as u8])
        .await
        .unwrap();

    drop(resumed);
    drop(publisher);
    running.shutdown().await.unwrap();
}
