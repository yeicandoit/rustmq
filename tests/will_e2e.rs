use std::{net::SocketAddr, time::Duration};

use rustmq::{broker::Broker, config::Config, server::spawn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn connect(client: &str, flags: u8, will: Option<(&str, &[u8])>) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, flags];
    body.extend_from_slice(&30_u16.to_be_bytes());
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    if let Some((topic, payload)) = will {
        body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        body.extend_from_slice(topic.as_bytes());
        body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        body.extend_from_slice(payload);
    }
    let mut packet = vec![0x10, body.len() as u8];
    packet.extend(body);
    packet
}

fn subscribe(filter: &str) -> Vec<u8> {
    let length = 2 + 2 + filter.len() + 1;
    let mut packet = vec![0x82, length as u8, 0, 1];
    packet.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    packet.extend_from_slice(filter.as_bytes());
    packet.push(0);
    packet
}

async fn packet(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut header))
        .await
        .unwrap()
        .unwrap();
    let mut body = vec![0_u8; usize::from(header[1])];
    stream.read_exact(&mut body).await.unwrap();
    let mut result = header.to_vec();
    result.extend(body);
    result
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
        .write_all(&connect("observer", 2, None))
        .await
        .unwrap();
    packet(&mut stream).await;
    stream.write_all(&subscribe("last/will")).await.unwrap();
    packet(&mut stream).await;
    stream
}

#[tokio::test]
async fn abnormal_disconnect_publishes_will() {
    let (running, address) = start().await;
    let mut observer = observer(address).await;
    let mut publisher = TcpStream::connect(address).await.unwrap();
    publisher
        .write_all(&connect("will-client", 6, Some(("last/will", b"gone"))))
        .await
        .unwrap();
    packet(&mut publisher).await;
    drop(publisher);
    assert!(packet(&mut observer).await.ends_with(b"gone"));
    drop(observer);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn normal_disconnect_suppresses_will() {
    let (running, address) = start().await;
    let mut observer = observer(address).await;
    let mut publisher = TcpStream::connect(address).await.unwrap();
    publisher
        .write_all(&connect("will-client", 6, Some(("last/will", b"gone"))))
        .await
        .unwrap();
    packet(&mut publisher).await;
    publisher.write_all(&[0xe0, 0]).await.unwrap();
    drop(publisher);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), packet(&mut observer))
            .await
            .is_err()
    );
    drop(observer);
    running.shutdown().await.unwrap();
}
