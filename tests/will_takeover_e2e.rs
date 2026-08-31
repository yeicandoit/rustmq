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

fn connect_v5(client: &str, clean: bool, will: Option<(&str, &[u8], u32)>) -> Vec<u8> {
    let mut connect_properties = vec![0x11];
    connect_properties.extend_from_slice(&5_u32.to_be_bytes());
    let flags = if clean { 2 } else { 0 } | if will.is_some() { 4 } else { 0 };
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 5, flags, 0, 30];
    body.push(connect_properties.len() as u8);
    body.extend(connect_properties);
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    if let Some((topic, payload, delay)) = will {
        body.extend_from_slice(&[5, 0x18]);
        body.extend_from_slice(&delay.to_be_bytes());
        body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        body.extend_from_slice(topic.as_bytes());
        body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        body.extend_from_slice(payload);
    }
    frame(0x10, body)
}

fn connect_v311(client: &str) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 2, 0, 30];
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    frame(0x10, body)
}

fn subscribe(filter: &str) -> Vec<u8> {
    let mut body = vec![0, 1];
    body.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    body.extend_from_slice(filter.as_bytes());
    body.push(0);
    frame(0x82, body)
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
    let running = spawn(config, Broker::new()).await.unwrap();
    let address = running.mqtt_addr;
    (running, address)
}

async fn observer(address: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(&connect_v311("takeover-observer"))
        .await
        .unwrap();
    read_packet(&mut stream).await;
    stream.write_all(&subscribe("will/takeover")).await.unwrap();
    read_packet(&mut stream).await;
    stream
}

#[tokio::test]
async fn clean_start_takeover_publishes_old_will_immediately() {
    let (running, address) = start().await;
    let mut observer = observer(address).await;
    let mut old = TcpStream::connect(address).await.unwrap();
    old.write_all(&connect_v5(
        "takeover-client",
        true,
        Some(("will/takeover", b"clean-start", 5)),
    ))
    .await
    .unwrap();
    read_packet(&mut old).await;

    let mut replacement = TcpStream::connect(address).await.unwrap();
    replacement
        .write_all(&connect_v5("takeover-client", true, None))
        .await
        .unwrap();
    read_packet(&mut replacement).await;
    let will = tokio::time::timeout(Duration::from_millis(500), read_packet(&mut observer))
        .await
        .expect("Clean Start takeover did not publish old Will");
    assert!(will.ends_with(b"clean-start"));

    replacement
        .write_all(&frame(0xe0, Vec::new()))
        .await
        .unwrap();
    drop(old);
    drop(replacement);
    drop(observer);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn resume_takeover_cancels_delayed_old_will() {
    let (running, address) = start().await;
    let mut observer = observer(address).await;
    let mut old = TcpStream::connect(address).await.unwrap();
    old.write_all(&connect_v5(
        "resume-client",
        true,
        Some(("will/takeover", b"must-cancel", 1)),
    ))
    .await
    .unwrap();
    read_packet(&mut old).await;

    let mut replacement = TcpStream::connect(address).await.unwrap();
    replacement
        .write_all(&connect_v5("resume-client", false, None))
        .await
        .unwrap();
    let connack = read_packet(&mut replacement).await;
    assert_eq!(connack[2], 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(1200), read_packet(&mut observer))
            .await
            .is_err()
    );

    replacement
        .write_all(&frame(0xe0, Vec::new()))
        .await
        .unwrap();
    drop(old);
    drop(replacement);
    drop(observer);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn resume_takeover_publishes_zero_delay_old_will() {
    let (running, address) = start().await;
    let mut observer = observer(address).await;
    let mut old = TcpStream::connect(address).await.unwrap();
    old.write_all(&connect_v5(
        "zero-delay-takeover",
        true,
        Some(("will/takeover", b"zero-delay", 0)),
    ))
    .await
    .unwrap();
    read_packet(&mut old).await;

    let mut replacement = TcpStream::connect(address).await.unwrap();
    replacement
        .write_all(&connect_v5("zero-delay-takeover", false, None))
        .await
        .unwrap();
    read_packet(&mut replacement).await;
    let will = tokio::time::timeout(Duration::from_millis(500), read_packet(&mut observer))
        .await
        .expect("zero-delay takeover did not publish old Will");
    assert!(will.ends_with(b"zero-delay"));

    replacement
        .write_all(&frame(0xe0, Vec::new()))
        .await
        .unwrap();
    drop(old);
    drop(replacement);
    drop(observer);
    running.shutdown().await.unwrap();
}
