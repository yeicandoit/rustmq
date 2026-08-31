use std::{net::SocketAddr, time::Duration};

use rustmq::{broker::Broker, config::Config, server::spawn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn connect_v5(client: &str, clean: bool, expiry: Option<u32>) -> Vec<u8> {
    let mut properties = Vec::new();
    if let Some(seconds) = expiry {
        properties.push(0x11);
        properties.extend_from_slice(&seconds.to_be_bytes());
    }
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
    let mut packet = vec![0x10, body.len() as u8];
    packet.extend(body);
    packet
}

fn subscribe(id: u16, filter: &str) -> Vec<u8> {
    let length = 2 + 1 + 2 + filter.len() + 1;
    let mut packet = vec![0x82, length as u8];
    packet.extend_from_slice(&id.to_be_bytes());
    packet.push(0);
    packet.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    packet.extend_from_slice(filter.as_bytes());
    packet.push(0);
    packet
}

async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut header))
        .await
        .unwrap()
        .unwrap();
    let mut body = vec![0_u8; usize::from(header[1])];
    stream.read_exact(&mut body).await.unwrap();
    let mut packet = header.to_vec();
    packet.extend(body);
    packet
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
    client: &str,
    clean: bool,
    expiry: Option<u32>,
) -> (TcpStream, Vec<u8>) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(&connect_v5(client, clean, expiry))
        .await
        .unwrap();
    let connack = read_packet(&mut stream).await;
    (stream, connack)
}

#[tokio::test]
async fn finite_session_expiry_controls_session_present() {
    let (running, address) = start().await;
    let (mut first, connack) = open(address, "expiring", true, Some(1)).await;
    assert_eq!(connack, vec![0x20, 6, 0, 0, 3, 0x22, 0xff, 0xff]);
    first.write_all(&subscribe(12, "expiry/#")).await.unwrap();
    read_packet(&mut first).await;
    first.write_all(&[0xe0, 0]).await.unwrap();
    drop(first);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (mut resumed, connack) = open(address, "expiring", false, Some(1)).await;
    assert_eq!(connack, vec![0x20, 6, 1, 0, 3, 0x22, 0xff, 0xff]);
    resumed.write_all(&[0xe0, 0]).await.unwrap();
    drop(resumed);
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let (expired, connack) = open(address, "expiring", false, Some(1)).await;
    assert_eq!(connack, vec![0x20, 6, 0, 0, 3, 0x22, 0xff, 0xff]);
    drop(expired);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn default_zero_expiry_removes_session_on_disconnect() {
    let (running, address) = start().await;
    let (mut first, connack) = open(address, "zero-expiry", true, None).await;
    assert_eq!(connack, vec![0x20, 6, 0, 0, 3, 0x22, 0xff, 0xff]);
    first.write_all(&subscribe(13, "zero/#")).await.unwrap();
    read_packet(&mut first).await;
    first.write_all(&[0xe0, 0]).await.unwrap();
    drop(first);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (second, connack) = open(address, "zero-expiry", false, None).await;
    assert_eq!(connack, vec![0x20, 6, 0, 0, 3, 0x22, 0xff, 0xff]);
    drop(second);
    running.shutdown().await.unwrap();
}
