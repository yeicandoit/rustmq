use std::{net::SocketAddr, time::Duration};

use rustmq::{broker::Broker, config::Config, server::spawn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn connect_packet(client_id: &str) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 2, 0, 30];
    body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    let mut packet = vec![0x10, body.len() as u8];
    packet.extend(body);
    packet
}

async fn read_http_response(stream: &mut TcpStream) -> String {
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut byte))
            .await
            .expect("HTTP response timeout")
            .unwrap();
        response.push(byte[0]);
    }
    String::from_utf8(response).unwrap()
}

async fn websocket_upgrade(
    address: SocketAddr,
    path: &str,
    subprotocols: Option<&str>,
) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let protocol_header = subprotocols
        .map(|value| format!("Sec-WebSocket-Protocol: {value}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{protocol_header}\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let response = read_http_response(&mut stream).await;
    (stream, response)
}

async fn send_masked_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) {
    assert!(payload.len() < 126);
    let mask = [0x12, 0x34, 0x56, 0x78];
    let mut frame = vec![0x80 | opcode, 0x80 | payload.len() as u8];
    frame.extend_from_slice(&mask);
    frame.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % mask.len()]),
    );
    stream.write_all(&frame).await.unwrap();
}

async fn read_frame(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut header))
        .await
        .expect("WebSocket frame timeout")
        .unwrap();
    assert_eq!(header[0] & 0x80, 0x80, "server frame must be final");
    assert_eq!(header[1] & 0x80, 0, "server frame must not be masked");
    let length = match header[1] & 0x7f {
        length @ 0..=125 => usize::from(length),
        126 => {
            let mut bytes = [0_u8; 2];
            stream.read_exact(&mut bytes).await.unwrap();
            usize::from(u16::from_be_bytes(bytes))
        }
        127 => {
            let mut bytes = [0_u8; 8];
            stream.read_exact(&mut bytes).await.unwrap();
            usize::try_from(u64::from_be_bytes(bytes)).unwrap()
        }
        _ => unreachable!(),
    };
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await.unwrap();
    (header[0] & 0x0f, payload)
}

async fn start() -> rustmq::server::RunningServer {
    let mut config = Config::default();
    config.mqtt.bind = "127.0.0.1:0".into();
    config.http.bind = "127.0.0.1:0".into();
    config.mqtt_ws.enabled = true;
    config.mqtt_ws.bind = "127.0.0.1:0".into();
    spawn(config, Broker::new()).await.unwrap()
}

#[tokio::test]
async fn websocket_listener_runs_the_mqtt_state_machine_and_control_ping() {
    let running = start().await;
    let address = running.mqtt_ws_addr.expect("WebSocket listener address");
    let (mut stream, response) = websocket_upgrade(address, "/mqtt", Some("mqtt-v5, mqtt")).await;
    assert!(response.starts_with("HTTP/1.1 101"), "{response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("sec-websocket-protocol: mqtt-v5\r\n"),
        "{response}"
    );

    send_masked_frame(&mut stream, 2, &connect_packet("websocket-client")).await;
    assert_eq!(read_frame(&mut stream).await, (2, vec![0x20, 2, 0, 0]));

    send_masked_frame(&mut stream, 9, b"probe").await;
    assert_eq!(read_frame(&mut stream).await, (10, b"probe".to_vec()));

    send_masked_frame(&mut stream, 2, &[0xc0, 0]).await;
    assert_eq!(read_frame(&mut stream).await, (2, vec![0xd0, 0]));

    drop(stream);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn websocket_listener_accepts_emqx_subprotocols_and_rejects_invalid_handshakes() {
    let running = start().await;
    let address = running.mqtt_ws_addr.unwrap();

    for protocol in ["mqtt", "mqtt-v3", "mqtt-v3.1.1", "mqtt-v5"] {
        let (stream, response) = websocket_upgrade(address, "/mqtt", Some(protocol)).await;
        assert!(response.starts_with("HTTP/1.1 101"), "{response}");
        assert!(
            response
                .to_ascii_lowercase()
                .contains(&format!("sec-websocket-protocol: {protocol}\r\n")),
            "{response}"
        );
        drop(stream);
    }

    for protocols in [None, Some("not-mqtt")] {
        let (stream, response) = websocket_upgrade(address, "/mqtt", protocols).await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        drop(stream);
    }

    let (stream, response) = websocket_upgrade(address, "/wrong", Some("mqtt")).await;
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    drop(stream);

    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_does_not_wait_for_idle_websocket_clients() {
    let running = start().await;
    let address = running.mqtt_ws_addr.unwrap();
    let (stream, response) = websocket_upgrade(address, "/mqtt", Some("mqtt")).await;
    assert!(response.starts_with("HTTP/1.1 101"), "{response}");

    tokio::time::timeout(Duration::from_secs(1), running.shutdown())
        .await
        .expect("shutdown must not wait for idle WebSocket clients")
        .unwrap();
    drop(stream);
}
