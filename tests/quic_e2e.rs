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

fn connect_v5_packet(client_id: &str) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 5, 2, 0, 30, 0];
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

fn subscribe_qos1_packet(packet_id: u16, topic: &str) -> Vec<u8> {
    let mut packet = subscribe_packet(packet_id, topic);
    *packet.last_mut().unwrap() = 1;
    packet
}

fn subscribe_v5_packet(packet_id: u16, topic: &str) -> Vec<u8> {
    let mut body = packet_id.to_be_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    body.push(0);
    let mut packet = vec![0x82, body.len() as u8];
    packet.extend(body);
    packet
}

fn unsubscribe_packet(packet_id: u16, topic: &str) -> Vec<u8> {
    let mut body = packet_id.to_be_bytes().to_vec();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    let mut packet = vec![0xa2, body.len() as u8];
    packet.extend(body);
    packet
}

fn unsubscribe_v5_packet(packet_id: u16, topic: &str) -> Vec<u8> {
    let mut body = packet_id.to_be_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    let mut packet = vec![0xa2, body.len() as u8];
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

fn publish_qos0(topic: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = (topic.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(topic.as_bytes());
    body.extend_from_slice(payload);
    let mut packet = vec![0x30, body.len() as u8];
    packet.extend(body);
    packet
}

fn publish_qos2(packet_id: u16, topic: &str, payload: &[u8]) -> Vec<u8> {
    let mut packet = publish_qos1(packet_id, topic, payload);
    packet[0] = 0x34;
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

fn quic_early_data_client(certificate_der: &[u8]) -> Endpoint {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate_der.to_vec()))
        .unwrap();
    let mut crypto = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"mqtt".to_vec()];
    crypto.enable_early_data = true;
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
async fn quic_listener_rejects_zero_bidirectional_stream_limit() {
    let mut fixture = quic_config();
    fixture.config.mqtt_quic.peer_bidi_stream_count = 0;

    let error = match spawn(fixture.config, Broker::new()).await {
        Ok(_) => panic!("QUIC with no control-stream capacity must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("peer_bidi_stream_count"));
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

#[tokio::test]
async fn quic_data_streams_publish_in_parallel_without_head_of_line_blocking() {
    let fixture = quic_config();
    let running = spawn(fixture.config, Broker::new()).await.unwrap();
    let quic_address = running.mqtt_quic_addr.unwrap();

    let mut subscriber = TcpStream::connect(running.mqtt_addr).await.unwrap();
    subscriber
        .write_all(&connect_packet("tcp-multistream-subscriber"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut subscriber).await, [0x20, 2, 0, 0]);
    subscriber
        .write_all(&subscribe_packet(1, "quic/multistream"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut subscriber).await, [0x90, 3, 0, 1, 0]);

    let (_endpoint, connection) = connect_quic(quic_address, &fixture.certificate_der).await;
    let (mut control_send, mut control_receive) = connection.open_bi().await.unwrap();
    control_send
        .write_all(&connect_packet("quic-multistream-publisher"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut control_receive).await, [0x20, 2, 0, 0]);

    let (mut blocked_send, _blocked_receive) =
        tokio::time::timeout(Duration::from_secs(2), connection.open_bi())
            .await
            .expect("first QUIC data stream must be available")
            .unwrap();
    blocked_send.write_all(&[0x32]).await.unwrap();

    let (mut publish_send, mut publish_receive) =
        tokio::time::timeout(Duration::from_secs(2), connection.open_bi())
            .await
            .expect("second QUIC data stream must not wait for the first")
            .unwrap();
    publish_send
        .write_all(&publish_qos1(
            7,
            "quic/multistream",
            b"parallel-data-stream",
        ))
        .await
        .unwrap();

    assert_eq!(read_packet(&mut publish_receive).await, [0x40, 2, 0, 7]);
    assert!(read_packet(&mut subscriber)
        .await
        .ends_with(b"parallel-data-stream"));

    blocked_send.write_all(&[0, 0]).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), blocked_send.stopped())
        .await
        .expect("malformed data stream must be reset")
        .unwrap()
        .expect("malformed data stream must have an application error code");

    let (mut recovery_send, mut recovery_receive) =
        tokio::time::timeout(Duration::from_secs(2), connection.open_bi())
            .await
            .expect("a new data stream must remain available after a malformed stream")
            .unwrap();
    recovery_send
        .write_all(&publish_qos1(
            8,
            "quic/multistream",
            b"stream-error-isolated",
        ))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut recovery_receive).await, [0x40, 2, 0, 8]);
    assert!(read_packet(&mut subscriber)
        .await
        .ends_with(b"stream-error-isolated"));

    recovery_send
        .write_all(&publish_qos0("quic/multistream", b"qos0-data-stream"))
        .await
        .unwrap();
    assert!(read_packet(&mut subscriber)
        .await
        .ends_with(b"qos0-data-stream"));

    recovery_send
        .write_all(&publish_qos2(9, "quic/multistream", b"qos2-data-stream"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut recovery_receive).await, [0x50, 2, 0, 9]);
    recovery_send.write_all(&[0x62, 2, 0, 9]).await.unwrap();
    assert_eq!(read_packet(&mut recovery_receive).await, [0x70, 2, 0, 9]);
    assert!(read_packet(&mut subscriber)
        .await
        .ends_with(b"qos2-data-stream"));

    control_send.write_all(&[0xc0, 0]).await.unwrap();
    assert_eq!(read_packet(&mut control_receive).await, [0xd0, 0]);

    connection.close(0_u32.into(), b"done");
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn quic_subscriptions_are_affine_to_their_data_streams() {
    let fixture = quic_config();
    let running = spawn(fixture.config, Broker::new()).await.unwrap();
    let quic_address = running.mqtt_quic_addr.unwrap();
    let (_endpoint, connection) = connect_quic(quic_address, &fixture.certificate_der).await;
    let (mut control_send, mut control_receive) = connection.open_bi().await.unwrap();
    control_send
        .write_all(&connect_packet("quic-stream-affinity"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut control_receive).await, [0x20, 2, 0, 0]);

    let (mut first_send, mut first_receive) = connection.open_bi().await.unwrap();
    first_send
        .write_all(&subscribe_packet(1, "quic/affinity"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut first_receive).await, [0x90, 3, 0, 1, 0]);

    let (mut second_send, mut second_receive) = connection.open_bi().await.unwrap();
    second_send
        .write_all(&subscribe_packet(2, "quic/affinity"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut second_receive).await, [0x90, 3, 0, 2, 0]);

    let mut publisher = TcpStream::connect(running.mqtt_addr).await.unwrap();
    publisher
        .write_all(&connect_packet("affinity-publisher"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut publisher).await, [0x20, 2, 0, 0]);
    publisher
        .write_all(&publish_qos0("quic/affinity", b"both-streams"))
        .await
        .unwrap();
    assert!(read_packet(&mut first_receive)
        .await
        .ends_with(b"both-streams"));
    assert!(read_packet(&mut second_receive)
        .await
        .ends_with(b"both-streams"));
    let mut unexpected = [0_u8; 1];
    assert!(tokio::time::timeout(
        Duration::from_millis(100),
        control_receive.read(&mut unexpected),
    )
    .await
    .is_err());

    first_send.finish().unwrap();
    drop(first_receive);
    tokio::time::sleep(Duration::from_millis(50)).await;
    publisher
        .write_all(&publish_qos0("quic/affinity", b"second-only"))
        .await
        .unwrap();
    assert!(read_packet(&mut second_receive)
        .await
        .ends_with(b"second-only"));

    second_send
        .write_all(&unsubscribe_packet(3, "quic/affinity"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut second_receive).await, [0xb0, 2, 0, 3]);
    publisher
        .write_all(&publish_qos0("quic/affinity", b"after-unsubscribe"))
        .await
        .unwrap();
    assert!(tokio::time::timeout(
        Duration::from_millis(100),
        second_receive.read(&mut unexpected),
    )
    .await
    .is_err());

    control_send.write_all(&[0xc0, 0]).await.unwrap();
    assert_eq!(read_packet(&mut control_receive).await, [0xd0, 0]);
    connection.close(0_u32.into(), b"done");
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn quic_v5_unsubscribe_only_removes_the_calling_stream_subscription() {
    let fixture = quic_config();
    let running = spawn(fixture.config, Broker::new()).await.unwrap();
    let quic_address = running.mqtt_quic_addr.unwrap();
    let (_endpoint, connection) = connect_quic(quic_address, &fixture.certificate_der).await;
    let (mut control_send, mut control_receive) = connection.open_bi().await.unwrap();
    control_send
        .write_all(&connect_v5_packet("quic-v5-stream-affinity"))
        .await
        .unwrap();
    assert_eq!(
        read_packet(&mut control_receive).await,
        [0x20, 6, 0, 0, 3, 0x22, 0xff, 0xff]
    );

    let (mut subscribed_send, mut subscribed_receive) = connection.open_bi().await.unwrap();
    subscribed_send
        .write_all(&subscribe_v5_packet(1, "quic/v5-affinity"))
        .await
        .unwrap();
    assert_eq!(
        read_packet(&mut subscribed_receive).await,
        [0x90, 4, 0, 1, 0, 0]
    );

    let (mut other_send, mut other_receive) = connection.open_bi().await.unwrap();
    other_send
        .write_all(&unsubscribe_v5_packet(2, "quic/v5-affinity"))
        .await
        .unwrap();
    assert_eq!(
        read_packet(&mut other_receive).await,
        [0xb0, 4, 0, 2, 0, 0x11]
    );

    let mut publisher = TcpStream::connect(running.mqtt_addr).await.unwrap();
    publisher
        .write_all(&connect_packet("v5-affinity-publisher"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut publisher).await, [0x20, 2, 0, 0]);
    publisher
        .write_all(&publish_qos0("quic/v5-affinity", b"still-subscribed"))
        .await
        .unwrap();
    assert!(read_packet(&mut subscribed_receive)
        .await
        .ends_with(b"still-subscribed"));

    subscribed_send
        .write_all(&unsubscribe_v5_packet(3, "quic/v5-affinity"))
        .await
        .unwrap();
    assert_eq!(
        read_packet(&mut subscribed_receive).await,
        [0xb0, 4, 0, 3, 0, 0]
    );

    control_send.write_all(&[0xe0, 0]).await.unwrap();
    connection.close(0_u32.into(), b"done");
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn quic_qos1_ack_is_scoped_to_the_delivery_stream() {
    let mut fixture = quic_config();
    fixture.config.mqtt.retry_interval_ms = 50;
    let running = spawn(fixture.config, Broker::new()).await.unwrap();
    let quic_address = running.mqtt_quic_addr.unwrap();
    let (_endpoint, connection) = connect_quic(quic_address, &fixture.certificate_der).await;
    let (mut control_send, mut control_receive) = connection.open_bi().await.unwrap();
    control_send
        .write_all(&connect_packet("quic-qos1-stream-affinity"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut control_receive).await, [0x20, 2, 0, 0]);

    let (mut subscribed_send, mut subscribed_receive) = connection.open_bi().await.unwrap();
    subscribed_send
        .write_all(&subscribe_qos1_packet(1, "quic/qos1-affinity"))
        .await
        .unwrap();
    assert_eq!(
        read_packet(&mut subscribed_receive).await,
        [0x90, 3, 0, 1, 1]
    );

    let mut publisher = TcpStream::connect(running.mqtt_addr).await.unwrap();
    publisher
        .write_all(&connect_packet("qos1-affinity-publisher"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut publisher).await, [0x20, 2, 0, 0]);
    publisher
        .write_all(&publish_qos1(7, "quic/qos1-affinity", b"scoped-ack"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut publisher).await, [0x40, 2, 0, 7]);

    let first_delivery = read_packet(&mut subscribed_receive).await;
    assert_eq!(first_delivery[0], 0x32);
    assert!(first_delivery.ends_with(b"scoped-ack"));
    let packet_id_offset = 4 + "quic/qos1-affinity".len();
    let outbound_packet_id = u16::from_be_bytes([
        first_delivery[packet_id_offset],
        first_delivery[packet_id_offset + 1],
    ]);

    let (mut wrong_send, _wrong_receive) = connection.open_bi().await.unwrap();
    wrong_send
        .write_all(&[
            0x40,
            2,
            (outbound_packet_id >> 8) as u8,
            outbound_packet_id as u8,
        ])
        .await
        .unwrap();

    let retry = read_packet(&mut subscribed_receive).await;
    assert_eq!(
        retry[0], 0x3a,
        "the original stream must receive a DUP retry"
    );
    assert_eq!(
        &retry[packet_id_offset..=packet_id_offset + 1],
        &outbound_packet_id.to_be_bytes()
    );
    subscribed_send
        .write_all(&[
            0x40,
            2,
            (outbound_packet_id >> 8) as u8,
            outbound_packet_id as u8,
        ])
        .await
        .unwrap();

    control_send.write_all(&[0xe0, 0]).await.unwrap();
    connection.close(0_u32.into(), b"done");
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn quic_accepts_resumed_early_control_and_continuing_data_stream() {
    let fixture = quic_config();
    let running = spawn(fixture.config, Broker::new()).await.unwrap();
    let address = running.mqtt_quic_addr.unwrap();
    let endpoint = quic_early_data_client(&fixture.certificate_der);

    let first = endpoint
        .connect(address, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut first_send, mut first_receive) = first.open_bi().await.unwrap();
    first_send
        .write_all(&connect_packet("quic-ticket-primer"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut first_receive).await, [0x20, 2, 0, 0]);
    first_send.write_all(&[0xe0, 0]).await.unwrap();
    first.close(0_u32.into(), b"ticket primed");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let connecting = endpoint.connect(address, "localhost").unwrap();
    let (connection, accepted) = connecting
        .into_0rtt()
        .expect("the first handshake must cache a resumable session ticket");
    let (mut control_send, mut control_receive) = connection.open_bi().await.unwrap();
    control_send
        .write_all(&connect_packet("quic-early-publisher"))
        .await
        .unwrap();
    let (mut data_send, mut data_receive) = connection.open_bi().await.unwrap();
    data_send
        .write_all(&publish_qos1(7, "quic/early", b"before-handshake"))
        .await
        .unwrap();

    assert!(accepted.await, "the server must accept resumed 0-RTT data");
    assert_eq!(read_packet(&mut control_receive).await, [0x20, 2, 0, 0]);
    assert_eq!(read_packet(&mut data_receive).await, [0x40, 2, 0, 7]);
    data_send
        .write_all(&publish_qos1(8, "quic/early", b"after-handshake"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut data_receive).await, [0x40, 2, 0, 8]);

    control_send.write_all(&[0xe0, 0]).await.unwrap();
    connection.close(0_u32.into(), b"done");
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn quic_connection_and_stream_survive_client_udp_rebind() {
    let fixture = quic_config();
    let running = spawn(fixture.config, Broker::new()).await.unwrap();
    let address = running.mqtt_quic_addr.unwrap();
    let (endpoint, connection) = connect_quic(address, &fixture.certificate_der).await;
    let (mut control_send, mut control_receive) = connection.open_bi().await.unwrap();
    control_send
        .write_all(&connect_packet("quic-migrating-client"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut control_receive).await, [0x20, 2, 0, 0]);
    let (mut data_send, mut data_receive) = connection.open_bi().await.unwrap();
    data_send
        .write_all(&subscribe_packet(9, "quic/migration/delivery"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut data_receive).await, [0x90, 3, 0, 9, 0]);
    data_send
        .write_all(&publish_qos1(1, "quic/migration", b"before-rebind"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut data_receive).await, [0x40, 2, 0, 1]);

    let old_address = endpoint.local_addr().unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let new_address = socket.local_addr().unwrap();
    assert_ne!(old_address, new_address);
    endpoint.rebind(socket).unwrap();

    let mut publisher = TcpStream::connect(running.mqtt_addr).await.unwrap();
    publisher
        .write_all(&connect_packet("migration-publisher"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut publisher).await, [0x20, 2, 0, 0]);
    publisher
        .write_all(&publish_qos0(
            "quic/migration/delivery",
            b"subscription-survived-rebind",
        ))
        .await
        .unwrap();
    assert!(read_packet(&mut data_receive)
        .await
        .ends_with(b"subscription-survived-rebind"));

    data_send
        .write_all(&publish_qos1(2, "quic/migration", b"after-rebind"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut data_receive).await, [0x40, 2, 0, 2]);
    control_send.write_all(&[0xc0, 0]).await.unwrap();
    assert_eq!(read_packet(&mut control_receive).await, [0xd0, 0]);

    control_send.write_all(&[0xe0, 0]).await.unwrap();
    connection.close(0_u32.into(), b"done");
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn quic_does_not_issue_early_data_ticket_when_0rtt_is_disabled() {
    let mut fixture = quic_config();
    fixture.config.mqtt_quic.enable_0rtt = false;
    let running = spawn(fixture.config, Broker::new()).await.unwrap();
    let address = running.mqtt_quic_addr.unwrap();
    let endpoint = quic_early_data_client(&fixture.certificate_der);

    let first = endpoint
        .connect(address, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut receive) = first.open_bi().await.unwrap();
    send.write_all(&connect_packet("quic-no-early-data"))
        .await
        .unwrap();
    assert_eq!(read_packet(&mut receive).await, [0x20, 2, 0, 0]);
    send.write_all(&[0xe0, 0]).await.unwrap();
    first.close(0_u32.into(), b"ticket primed");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let connecting = endpoint.connect(address, "localhost").unwrap();
    assert!(
        connecting.into_0rtt().is_err(),
        "disabled 0-RTT must not issue an early-data-capable session"
    );

    running.shutdown().await.unwrap();
}
