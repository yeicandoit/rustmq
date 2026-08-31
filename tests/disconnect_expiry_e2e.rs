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

fn connect(client: &str, clean: bool, expiry: u32) -> Vec<u8> {
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

fn subscribe(id: u16, filter: &str) -> Vec<u8> {
    let mut body = id.to_be_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    body.extend_from_slice(filter.as_bytes());
    body.push(0);
    frame(0x82, body)
}

fn disconnect_with_expiry(expiry: u32) -> Vec<u8> {
    let mut body = vec![0, 5, 0x11];
    body.extend_from_slice(&expiry.to_be_bytes());
    frame(0xe0, body)
}

async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut header))
        .await
        .unwrap()
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
    let running = spawn(config, Broker::new()).await.unwrap();
    let address = running.mqtt_addr;
    (running, address)
}

async fn open(address: SocketAddr, client: &str, clean: bool, expiry: u32) -> (TcpStream, Vec<u8>) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(&connect(client, clean, expiry))
        .await
        .unwrap();
    let connack = read_packet(&mut stream).await;
    (stream, connack)
}

#[tokio::test]
async fn disconnect_can_reduce_nonzero_session_expiry_to_zero() {
    let (running, address) = start().await;
    let (mut first, _) = open(address, "override-zero", true, 60).await;
    first
        .write_all(&subscribe(1, "override/topic"))
        .await
        .unwrap();
    read_packet(&mut first).await;
    first.write_all(&disconnect_with_expiry(0)).await.unwrap();
    drop(first);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (second, connack) = open(address, "override-zero", false, 60).await;
    assert_eq!(connack, vec![0x20, 6, 0, 0, 3, 0x22, 0xff, 0xff]);
    drop(second);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn disconnect_cannot_raise_zero_connect_expiry() {
    let (running, address) = start().await;
    let (mut first, _) = open(address, "cannot-raise", true, 0).await;
    first
        .write_all(&subscribe(2, "cannot/topic"))
        .await
        .unwrap();
    read_packet(&mut first).await;
    first.write_all(&disconnect_with_expiry(60)).await.unwrap();
    let mut byte = [0_u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(1), first.read(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(closed, 0);
    drop(first);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (second, connack) = open(address, "cannot-raise", false, 60).await;
    assert_eq!(connack, vec![0x20, 6, 0, 0, 3, 0x22, 0xff, 0xff]);
    drop(second);
    running.shutdown().await.unwrap();
}
