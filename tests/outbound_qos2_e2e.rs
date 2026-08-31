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

fn connect(client: &str, clean: bool) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, if clean { 2 } else { 0 }];
    body.extend_from_slice(&30_u16.to_be_bytes());
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    frame(0x10, body)
}

fn subscribe(id: u16, filter: &str, qos: u8) -> Vec<u8> {
    let mut body = id.to_be_bytes().to_vec();
    body.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    body.extend_from_slice(filter.as_bytes());
    body.push(qos);
    frame(0x82, body)
}

fn publish(topic: &str, payload: &[u8], qos: u8, id: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    body.extend_from_slice(&id.to_be_bytes());
    body.extend_from_slice(payload);
    frame(0x30 | (qos << 1), body)
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

fn publish_id(packet: &[u8]) -> u16 {
    assert_eq!(packet[0] & 0x06, 0x04, "expected QoS 2 PUBLISH");
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
    let running = spawn(config, Broker::with_limits(4, 8)).await.unwrap();
    let address = running.mqtt_addr;
    (running, address)
}

async fn publish_inbound_qos2(
    publisher: &mut TcpStream,
    topic: &str,
    payload: &[u8],
    packet_id: u16,
) {
    publisher
        .write_all(&publish(topic, payload, 2, packet_id))
        .await
        .unwrap();
    assert_eq!(
        read_packet(publisher).await,
        frame(0x50, packet_id.to_be_bytes().to_vec())
    );
    publisher
        .write_all(&frame(0x62, packet_id.to_be_bytes().to_vec()))
        .await
        .unwrap();
    assert_eq!(
        read_packet(publisher).await,
        frame(0x70, packet_id.to_be_bytes().to_vec())
    );
}

#[tokio::test]
async fn outbound_qos2_retries_publish_then_pubrel_until_pubcomp() {
    let (running, address) = start().await;
    let (mut subscriber, _) = open(address, "qos2-sub", false).await;
    subscriber
        .write_all(&subscribe(1, "qos2/out", 2))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;
    let (mut publisher, _) = open(address, "qos2-pub", true).await;
    publish_inbound_qos2(&mut publisher, "qos2/out", b"two-phase", 10).await;

    let first = read_packet(&mut subscriber).await;
    assert_eq!(first[0] & 0x0e, 0x04);
    assert_eq!(first[0] & 0x08, 0);
    let id = publish_id(&first);

    let retry_publish = read_packet(&mut subscriber).await;
    assert_ne!(retry_publish[0] & 0x08, 0);
    assert_eq!(publish_id(&retry_publish), id);

    subscriber
        .write_all(&frame(0x50, id.to_be_bytes().to_vec()))
        .await
        .unwrap();
    assert_eq!(
        read_packet(&mut subscriber).await,
        frame(0x62, id.to_be_bytes().to_vec())
    );
    assert_eq!(
        read_packet(&mut subscriber).await,
        frame(0x62, id.to_be_bytes().to_vec())
    );

    subscriber
        .write_all(&frame(0x70, id.to_be_bytes().to_vec()))
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
async fn reconnect_in_wait_comp_replays_pubrel_not_publish() {
    let (running, address) = start().await;
    let (mut subscriber, _) = open(address, "qos2-resume", false).await;
    subscriber
        .write_all(&subscribe(2, "qos2/resume", 2))
        .await
        .unwrap();
    read_packet(&mut subscriber).await;
    let (mut publisher, _) = open(address, "qos2-resume-pub", true).await;
    publish_inbound_qos2(&mut publisher, "qos2/resume", b"resume", 11).await;

    let outgoing = read_packet(&mut subscriber).await;
    let id = publish_id(&outgoing);
    subscriber
        .write_all(&frame(0x50, id.to_be_bytes().to_vec()))
        .await
        .unwrap();
    assert_eq!(
        read_packet(&mut subscriber).await,
        frame(0x62, id.to_be_bytes().to_vec())
    );
    subscriber
        .write_all(&frame(0xe0, Vec::new()))
        .await
        .unwrap();
    drop(subscriber);
    tokio::time::sleep(Duration::from_millis(30)).await;

    let (mut resumed, connack) = open(address, "qos2-resume", false).await;
    assert_eq!(connack, vec![0x20, 2, 1, 0]);
    let replay = read_packet(&mut resumed).await;
    assert_eq!(replay, frame(0x62, id.to_be_bytes().to_vec()));
    resumed
        .write_all(&frame(0x70, id.to_be_bytes().to_vec()))
        .await
        .unwrap();

    drop(resumed);
    drop(publisher);
    running.shutdown().await.unwrap();
}
