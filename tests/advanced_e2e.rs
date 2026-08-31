use std::{net::SocketAddr, time::Duration};

use rustmq::{broker::Broker, config::Config, server::spawn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn connect(client: &str, clean: bool, keepalive: u16, version: u8) -> Vec<u8> {
    let mut body = vec![
        0,
        4,
        b'M',
        b'Q',
        b'T',
        b'T',
        version,
        if clean { 2 } else { 0 },
    ];
    body.extend_from_slice(&keepalive.to_be_bytes());
    if version == 5 {
        body.push(0);
    }
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    let mut packet = vec![0x10, body.len() as u8];
    packet.extend(body);
    packet
}

fn subscribe(id: u16, filter: &str, qos: u8, version: u8) -> Vec<u8> {
    let property_bytes = usize::from(version == 5);
    let length = 2 + property_bytes + 2 + filter.len() + 1;
    let mut packet = vec![0x82, length as u8];
    packet.extend_from_slice(&id.to_be_bytes());
    if version == 5 {
        packet.push(0);
    }
    packet.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    packet.extend_from_slice(filter.as_bytes());
    packet.push(qos);
    packet
}

fn publish(topic: &str, payload: &[u8]) -> Vec<u8> {
    let length = 2 + topic.len() + payload.len();
    let mut packet = vec![0x30, length as u8];
    packet.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    packet.extend_from_slice(topic.as_bytes());
    packet.extend_from_slice(payload);
    packet
}

async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut header))
        .await
        .expect("packet read timed out")
        .expect("packet header read failed");
    let mut length = usize::from(header[1] & 0x7f);
    let mut multiplier = 128_usize;
    let mut encoded = vec![header[0], header[1]];
    let mut byte = header[1];
    while byte & 0x80 != 0 {
        let mut next = [0_u8; 1];
        stream.read_exact(&mut next).await.unwrap();
        byte = next[0];
        encoded.push(byte);
        length += usize::from(byte & 0x7f) * multiplier;
        multiplier *= 128;
    }
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).await.unwrap();
    encoded.extend(body);
    encoded
}

async fn start() -> (rustmq::server::RunningServer, SocketAddr) {
    let mut config = Config::default();
    config.mqtt.bind = "127.0.0.1:0".into();
    config.http.bind = "127.0.0.1:0".into();
    let running = spawn(config, Broker::new()).await.unwrap();
    let address = running.mqtt_addr;
    (running, address)
}

async fn open(
    address: SocketAddr,
    id: &str,
    clean: bool,
    version: u8,
    keepalive: u16,
) -> (TcpStream, Vec<u8>) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(&connect(id, clean, keepalive, version))
        .await
        .unwrap();
    let connack = read_packet(&mut stream).await;
    (stream, connack)
}

#[tokio::test]
async fn mqtt_v5_connect_subscribe_publish_and_ping() {
    let (running, address) = start().await;
    let (mut stream, connack) = open(address, "v5", true, 5, 30).await;
    assert_eq!(connack, vec![0x20, 6, 0, 0, 3, 0x22, 0xff, 0xff]);

    stream
        .write_all(&subscribe(9, "v5/topic", 0, 5))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut stream).await, vec![0x90, 4, 0, 9, 0, 0]);

    // V5 PUBLISH: topic + zero-length properties + payload.
    stream
        .write_all(&[
            0x30, 12, 0, 8, b'v', b'5', b'/', b't', b'o', b'p', b'i', b'c', 0, b'x',
        ])
        .await
        .unwrap();
    assert!(read_packet(&mut stream).await.ends_with(&[0, b'x']));
    stream.write_all(&[0xc0, 0]).await.unwrap();
    assert_eq!(read_packet(&mut stream).await, vec![0xd0, 0]);
    drop(stream);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn persistent_session_restores_subscription_after_reconnect() {
    let (running, address) = start().await;
    let (mut first, first_connack) = open(address, "persistent", false, 4, 30).await;
    assert_eq!(first_connack, vec![0x20, 2, 0, 0]);
    first
        .write_all(&subscribe(11, "restore/#", 0, 4))
        .await
        .unwrap();
    read_packet(&mut first).await;
    first.write_all(&[0xe0, 0]).await.unwrap();
    drop(first);
    tokio::time::sleep(Duration::from_millis(30)).await;

    let (mut restored, second_connack) = open(address, "persistent", false, 4, 30).await;
    assert_eq!(second_connack, vec![0x20, 2, 1, 0]);
    let (mut publisher, _) = open(address, "publisher", true, 4, 30).await;
    publisher
        .write_all(&publish("restore/topic", b"restored"))
        .await
        .unwrap();
    assert!(read_packet(&mut restored).await.ends_with(b"restored"));
    drop(restored);
    drop(publisher);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn keepalive_disconnects_idle_client_after_one_and_a_half_intervals() {
    let (running, address) = start().await;
    let (mut stream, _) = open(address, "idle", true, 4, 1).await;
    let mut byte = [0_u8; 1];
    let bytes_read = tokio::time::timeout(Duration::from_millis(2200), stream.read(&mut byte))
        .await
        .expect("broker did not enforce keepalive")
        .unwrap();
    assert_eq!(bytes_read, 0);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn graceful_shutdown_closes_existing_connections() {
    let (running, address) = start().await;
    let (mut stream, _) = open(address, "shutdown", true, 4, 30).await;
    running.shutdown().await.unwrap();
    let mut byte = [0_u8; 1];
    let bytes_read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
        .await
        .expect("connection remained open after shutdown")
        .unwrap();
    assert_eq!(bytes_read, 0);
}

#[tokio::test]
async fn partial_static_auth_configuration_fails_closed() {
    let mut config = Config::default();
    config.mqtt.bind = "127.0.0.1:0".into();
    config.http.bind = "127.0.0.1:0".into();
    config.auth.password = Some("configured-without-username".into());
    let running = spawn(config, Broker::new()).await.unwrap();
    let mut stream = TcpStream::connect(running.mqtt_addr).await.unwrap();
    stream
        .write_all(&connect("unauthenticated", true, 30, 4))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut stream).await, vec![0x20, 2, 0, 4]);
    drop(stream);
    running.shutdown().await.unwrap();
}
