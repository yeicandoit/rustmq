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

fn connect_v5(
    client: &str,
    clean: bool,
    session_expiry: u32,
    will: Option<(&str, &[u8], u32, Option<u32>)>,
) -> Vec<u8> {
    let mut connect_properties = vec![0x11];
    connect_properties.extend_from_slice(&session_expiry.to_be_bytes());
    let flags = if clean { 2 } else { 0 } | if will.is_some() { 4 } else { 0 };
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 5, flags, 0, 30];
    body.push(connect_properties.len() as u8);
    body.extend(connect_properties);
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    if let Some((topic, payload, delay, message_expiry)) = will {
        let mut will_properties = vec![0x18];
        will_properties.extend_from_slice(&delay.to_be_bytes());
        if let Some(expiry) = message_expiry {
            will_properties.push(0x02);
            will_properties.extend_from_slice(&expiry.to_be_bytes());
        }
        body.push(will_properties.len() as u8);
        body.extend(will_properties);
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
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut header))
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
        .write_all(&connect_v311("will-delay-observer"))
        .await
        .unwrap();
    read_packet(&mut stream).await;
    stream.write_all(&subscribe("will/delay")).await.unwrap();
    read_packet(&mut stream).await;
    stream
}

#[tokio::test]
async fn will_is_published_after_delay() {
    let (running, address) = start().await;
    let mut observer = observer(address).await;
    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(&connect_v5(
            "delayed-client",
            true,
            5,
            Some(("will/delay", b"delayed", 1, Some(5))),
        ))
        .await
        .unwrap();
    read_packet(&mut client).await;
    drop(client);

    assert!(
        tokio::time::timeout(Duration::from_millis(300), read_packet(&mut observer))
            .await
            .is_err()
    );
    let will = tokio::time::timeout(Duration::from_millis(1200), read_packet(&mut observer))
        .await
        .expect("will was not published after delay");
    assert!(will.ends_with(b"delayed"));

    drop(observer);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn reconnect_before_delay_cancels_pending_will() {
    let (running, address) = start().await;
    let mut observer = observer(address).await;
    let mut first = TcpStream::connect(address).await.unwrap();
    first
        .write_all(&connect_v5(
            "recovering-client",
            true,
            5,
            Some(("will/delay", b"must-cancel", 1, None)),
        ))
        .await
        .unwrap();
    read_packet(&mut first).await;
    drop(first);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut resumed = TcpStream::connect(address).await.unwrap();
    resumed
        .write_all(&connect_v5("recovering-client", false, 5, None))
        .await
        .unwrap();
    let connack = read_packet(&mut resumed).await;
    assert_eq!(connack[2], 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(1100), read_packet(&mut observer))
            .await
            .is_err()
    );
    resumed.write_all(&frame(0xe0, Vec::new())).await.unwrap();

    drop(resumed);
    drop(observer);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn session_expiry_shorter_than_will_delay_publishes_at_session_end() {
    let (running, address) = start().await;
    let mut observer = observer(address).await;
    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(&connect_v5(
            "session-end-client",
            true,
            1,
            Some(("will/delay", b"session-ended", 5, None)),
        ))
        .await
        .unwrap();
    read_packet(&mut client).await;
    drop(client);

    assert!(
        tokio::time::timeout(Duration::from_millis(300), read_packet(&mut observer))
            .await
            .is_err()
    );
    let will = tokio::time::timeout(Duration::from_millis(1200), read_packet(&mut observer))
        .await
        .expect("will was not published when session expired");
    assert!(will.ends_with(b"session-ended"));

    drop(observer);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn disconnect_with_will_reason_publishes_will_immediately() {
    let (running, address) = start().await;
    let mut observer = observer(address).await;
    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(&connect_v5(
            "disconnect-with-will",
            true,
            5,
            Some(("will/delay", b"explicit-will", 5, None)),
        ))
        .await
        .unwrap();
    read_packet(&mut client).await;
    client.write_all(&frame(0xe0, vec![0x04, 0])).await.unwrap();

    let will = tokio::time::timeout(Duration::from_millis(500), read_packet(&mut observer))
        .await
        .expect("Disconnect with Will Message did not publish Will");
    assert!(will.ends_with(b"explicit-will"));

    drop(client);
    drop(observer);
    running.shutdown().await.unwrap();
}
