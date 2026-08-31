use std::time::Duration;

use rustmq::{broker::Broker, config::Config, server::spawn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn connect(client: &str, clean: bool, keepalive: u16) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, if clean { 2 } else { 0 }];
    body.extend_from_slice(&keepalive.to_be_bytes());
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    let mut out = vec![0x10, body.len() as u8];
    out.extend(body);
    out
}

fn subscribe(id: u16, filter: &str, qos: u8) -> Vec<u8> {
    let len = 2 + 2 + filter.len() + 1;
    let mut out = vec![0x82, len as u8];
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    out.extend_from_slice(filter.as_bytes());
    out.push(qos);
    out
}

fn publish(topic: &str, payload: &[u8], qos: u8, id: Option<u16>, retain: bool) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    if let Some(id) = id {
        body.extend_from_slice(&id.to_be_bytes());
    }
    body.extend_from_slice(payload);
    let header = 0x30 | (qos << 1) | u8::from(retain);
    let mut out = vec![header, body.len() as u8];
    out.extend(body);
    out
}

async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut head))
        .await
        .unwrap()
        .unwrap();
    let mut len = usize::from(head[1] & 0x7f);
    let mut multiplier = 128_usize;
    let mut prefix = vec![head[0], head[1]];
    let mut byte = head[1];
    while byte & 0x80 != 0 {
        let mut b = [0_u8; 1];
        stream.read_exact(&mut b).await.unwrap();
        byte = b[0];
        prefix.push(byte);
        len += usize::from(byte & 0x7f) * multiplier;
        multiplier *= 128;
    }
    let mut body = vec![0; len];
    stream.read_exact(&mut body).await.unwrap();
    prefix.extend(body);
    prefix
}

async fn client(addr: std::net::SocketAddr, id: &str) -> TcpStream {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(&connect(id, true, 30)).await.unwrap();
    assert_eq!(&read_packet(&mut s).await[..4], &[0x20, 2, 0, 0]);
    s
}

#[tokio::test]
async fn publish_subscribe_qos1_retain_shared_and_qos2_once() {
    let broker = Broker::new();
    let mut cfg = Config::default();
    cfg.mqtt.bind = "127.0.0.1:0".into();
    cfg.http.bind = "127.0.0.1:0".into();
    let running = spawn(cfg, broker).await.unwrap();
    let addr = running.mqtt_addr;

    let mut sub = client(addr, "sub").await;
    sub.write_all(&subscribe(1, "demo/#", 1)).await.unwrap();
    assert_eq!(read_packet(&mut sub).await[0], 0x90);
    let mut publisher = client(addr, "pub").await;
    publisher
        .write_all(&publish("demo/x", b"hello", 1, Some(7), true))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut publisher).await[0], 0x40);
    let delivered = read_packet(&mut sub).await;
    assert_eq!(delivered[0] & 0xf0, 0x30);
    assert!(delivered.ends_with(b"hello"));

    let mut retained = client(addr, "retained").await;
    retained
        .write_all(&subscribe(2, "demo/#", 0))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut retained).await[0], 0x90);
    assert!(read_packet(&mut retained).await.ends_with(b"hello"));

    let mut a = client(addr, "shared-a").await;
    let mut b = client(addr, "shared-b").await;
    a.write_all(&subscribe(3, "$share/g/work/+", 0))
        .await
        .unwrap();
    read_packet(&mut a).await;
    b.write_all(&subscribe(4, "$share/g/work/+", 0))
        .await
        .unwrap();
    read_packet(&mut b).await;
    publisher
        .write_all(&publish("work/1", b"one", 0, None, false))
        .await
        .unwrap();
    publisher
        .write_all(&publish("work/2", b"two", 0, None, false))
        .await
        .unwrap();
    let (pa, pb) = tokio::join!(read_packet(&mut a), read_packet(&mut b));
    assert_ne!(pa, pb);

    let mut q2sub = client(addr, "q2sub").await;
    q2sub.write_all(&subscribe(5, "q2", 0)).await.unwrap();
    read_packet(&mut q2sub).await;
    publisher
        .write_all(&publish("q2", b"once", 2, Some(42), false))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut publisher).await[0], 0x50);
    publisher.write_all(&[0x62, 2, 0, 42]).await.unwrap();
    assert_eq!(read_packet(&mut publisher).await[0], 0x70);
    assert!(read_packet(&mut q2sub).await.ends_with(b"once"));
    publisher.write_all(&[0x62, 2, 0, 42]).await.unwrap();
    assert_eq!(read_packet(&mut publisher).await[0], 0x70);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), read_packet(&mut q2sub))
            .await
            .is_err()
    );

    // A completed packet identifier may be reused for a new QoS 2 transaction.
    publisher
        .write_all(&publish("q2", b"reused", 2, Some(42), false))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut publisher).await[0], 0x50);
    publisher.write_all(&[0x62, 2, 0, 42]).await.unwrap();
    assert_eq!(read_packet(&mut publisher).await[0], 0x70);
    assert!(read_packet(&mut q2sub).await.ends_with(b"reused"));

    running.shutdown().await.unwrap();
}
