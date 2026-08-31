use std::{net::SocketAddr, sync::Arc, time::Duration};

use quinn::{crypto::rustls::QuicClientConfig, Endpoint};
use rustmq::{broker::Broker, config::Config, server::spawn};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::rustls::{pki_types::CertificateDer, RootCertStore};

struct QuicFixture {
    _directory: tempfile::TempDir,
    config: Config,
    certificate_der: Vec<u8>,
}

fn quic_config() -> QuicFixture {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate_der = certified.cert.der().to_vec();
    let directory = tempfile::tempdir().unwrap();
    let certificate = directory.path().join("server-cert.pem");
    let private_key = directory.path().join("server-key.pem");
    std::fs::write(&certificate, certified.cert.pem()).unwrap();
    std::fs::write(&private_key, certified.key_pair.serialize_pem()).unwrap();

    let mut config = Config::default();
    config.mqtt.bind = "127.0.0.1:0".into();
    config.http.bind = "127.0.0.1:0".into();
    config.mqtt_quic.enabled = true;
    config.mqtt_quic.bind = "127.0.0.1:0".into();
    config.mqtt_quic.certfile = Some(certificate);
    config.mqtt_quic.keyfile = Some(private_key);
    config.mqtt_quic.idle_timeout_ms = 5_000;
    QuicFixture {
        _directory: directory,
        config,
        certificate_der,
    }
}

fn connect_packet(client_id: &str) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 2, 0, 30];
    body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    let mut packet = vec![0x10, body.len() as u8];
    packet.extend(body);
    packet
}

fn subscribe_packet(packet_id: u16, topic: &str) -> Vec<u8> {
    let mut body = packet_id.to_be_bytes().to_vec();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    body.push(0);
    let mut packet = vec![0x82, body.len() as u8];
    packet.extend(body);
    packet
}

fn publish_qos1(packet_id: u16, topic: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = (topic.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(topic.as_bytes());
    body.extend_from_slice(&packet_id.to_be_bytes());
    body.extend_from_slice(payload);
    let mut packet = vec![0x32, body.len() as u8];
    packet.extend(body);
    packet
}

async fn read_packet<R>(reader: &mut R) -> Vec<u8>
where
    R: AsyncRead + Unpin,
{
    let mut first = [0_u8; 1];
    tokio::time::timeout(Duration::from_secs(2), reader.read_exact(&mut first))
        .await
        .expect("packet timeout")
        .unwrap();
    let mut packet = first.to_vec();
    let mut remaining = 0_usize;
    let mut multiplier = 1_usize;
    loop {
        let mut byte = [0_u8; 1];
        reader.read_exact(&mut byte).await.unwrap();
        packet.push(byte[0]);
        remaining += usize::from(byte[0] & 0x7f) * multiplier;
        if byte[0] & 0x80 == 0 {
            break;
        }
        multiplier *= 128;
    }
    let mut body = vec![0; remaining];
    reader.read_exact(&mut body).await.unwrap();
    packet.extend(body);
    packet
}

fn quic_client(certificate_der: &[u8], alpn: &[u8]) -> Endpoint {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate_der.to_vec()))
        .unwrap();
    let mut crypto = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![alpn.to_vec()];
    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}

async fn connect_quic(
    address: SocketAddr,
    certificate_der: &[u8],
) -> (Endpoint, quinn::Connection) {
    let endpoint = quic_client(certificate_der, b"mqtt");
    let connection = endpoint
        .connect(address, "localhost")
        .unwrap()
        .await
        .unwrap();
    let protocol = connection
        .handshake_data()
        .unwrap()
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .unwrap()
        .protocol;
    assert_eq!(protocol.as_deref(), Some(b"mqtt".as_slice()));
    (endpoint, connection)
}

#[tokio::test]
async fn quic_control_stream_runs_mqtt_and_receives_tcp_publish() {
    let fixture = quic_config();
    let running = spawn(fixture.config, Broker::new()).await.unwrap();
    let quic_address = running.mqtt_quic_addr.expect("QUIC listener address");
    let (_endpoint, connection) = connect_quic(quic_address, &fixture.certificate_der).await;
    let (mut send, mut receive) = connection.open_bi().await.unwrap();

    send.write_all(&connect_packet("quic-subscriber"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut receive).await, [0x20, 2, 0, 0]);
    send.write_all(&subscribe_packet(1, "quic/topic"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut receive).await, [0x90, 3, 0, 1, 0]);

    let mut publisher = TcpStream::connect(running.mqtt_addr).await.unwrap();
    publisher
        .write_all(&connect_packet("tcp-publisher"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut publisher).await, [0x20, 2, 0, 0]);
    publisher
        .write_all(&publish_qos1(7, "quic/topic", b"quic-delivery"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut publisher).await, [0x40, 2, 0, 7]);
    assert!(read_packet(&mut receive).await.ends_with(b"quic-delivery"));

    send.write_all(&[0xc0, 0]).await.unwrap();
    assert_eq!(read_packet(&mut receive).await, [0xd0, 0]);
    connection.close(0_u32.into(), b"done");
    drop(publisher);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn quic_rejects_clients_without_mqtt_alpn() {
    let fixture = quic_config();
    let running = spawn(fixture.config, Broker::new()).await.unwrap();
    let address = running.mqtt_quic_addr.unwrap();
    let endpoint = quic_client(&fixture.certificate_der, b"not-mqtt");

    let result = endpoint.connect(address, "localhost").unwrap().await;
    assert!(result.is_err(), "unsupported ALPN must fail the handshake");

    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn enabled_quic_listener_requires_certificate_and_private_key() {
    let mut config = Config::default();
    config.mqtt.bind = "127.0.0.1:0".into();
    config.http.bind = "127.0.0.1:0".into();
    config.mqtt_quic.enabled = true;
    config.mqtt_quic.bind = "127.0.0.1:0".into();

    let error = match spawn(config, Broker::new()).await {
        Ok(_) => panic!("QUIC without credentials must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("QUIC certificate"));
}

#[tokio::test]
async fn shutdown_cancels_quic_connection_without_a_control_stream() {
    let fixture = quic_config();
    let running = spawn(fixture.config, Broker::new()).await.unwrap();
    let address = running.mqtt_quic_addr.unwrap();
    let (_endpoint, _connection) = connect_quic(address, &fixture.certificate_der).await;

    tokio::time::timeout(Duration::from_secs(1), running.shutdown())
        .await
        .expect("shutdown must not wait for a QUIC control stream")
        .unwrap();
}
