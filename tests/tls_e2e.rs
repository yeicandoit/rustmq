use std::{net::SocketAddr, sync::Arc, time::Duration};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustmq::{broker::Broker, config::Config, server::spawn};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    rustls::{
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
        ClientConfig, RootCertStore,
    },
    TlsConnector,
};

struct MtlsFixture {
    _directory: tempfile::TempDir,
    config: Config,
    server_certificate_der: Vec<u8>,
    client_certificate_der: Vec<u8>,
    client_private_key_der: Vec<u8>,
    untrusted_certificate_der: Vec<u8>,
    untrusted_private_key_der: Vec<u8>,
}

fn connect(client: &str) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 2, 0, 30];
    body.extend_from_slice(&(client.len() as u16).to_be_bytes());
    body.extend_from_slice(client.as_bytes());
    let mut packet = vec![0x10, body.len() as u8];
    packet.extend(body);
    packet
}

async fn read_packet<S>(stream: &mut S) -> Vec<u8>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut header))
        .await
        .expect("packet timeout")
        .unwrap();
    let mut packet = header.to_vec();
    let mut body = vec![0; usize::from(header[1])];
    stream.read_exact(&mut body).await.unwrap();
    packet.extend(body);
    packet
}

fn tls_config() -> (tempfile::TempDir, Config, Vec<u8>) {
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
    config.mqtt_tls.enabled = true;
    config.mqtt_tls.bind = "127.0.0.1:0".into();
    config.mqtt_tls.certfile = Some(certificate);
    config.mqtt_tls.keyfile = Some(private_key);
    (directory, config, certificate_der)
}

fn mtls_config() -> MtlsFixture {
    let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let server_certificate = directory.path().join("server-cert.pem");
    let server_private_key = directory.path().join("server-key.pem");
    std::fs::write(&server_certificate, server.cert.pem()).unwrap();
    std::fs::write(&server_private_key, server.key_pair.serialize_pem()).unwrap();

    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
    let ca_path = directory.path().join("client-ca.pem");
    std::fs::write(&ca_path, ca_certificate.pem()).unwrap();

    let mut client_params = CertificateParams::new(vec!["trusted-client".into()]).unwrap();
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().unwrap();
    let client_certificate = client_params
        .signed_by(&client_key, &ca_certificate, &ca_key)
        .unwrap();

    let untrusted = rcgen::generate_simple_self_signed(vec!["untrusted-client".into()]).unwrap();
    let mut config = Config::default();
    config.mqtt.bind = "127.0.0.1:0".into();
    config.http.bind = "127.0.0.1:0".into();
    config.mqtt_tls.enabled = true;
    config.mqtt_tls.bind = "127.0.0.1:0".into();
    config.mqtt_tls.certfile = Some(server_certificate);
    config.mqtt_tls.keyfile = Some(server_private_key);
    config.mqtt_tls.verify_peer = true;
    config.mqtt_tls.cacertfile = Some(ca_path);

    MtlsFixture {
        _directory: directory,
        config,
        server_certificate_der: server.cert.der().to_vec(),
        client_certificate_der: client_certificate.der().to_vec(),
        client_private_key_der: client_key.serialize_der(),
        untrusted_certificate_der: untrusted.cert.der().to_vec(),
        untrusted_private_key_der: untrusted.key_pair.serialize_der(),
    }
}

async fn connect_tls(
    address: SocketAddr,
    certificate_der: Vec<u8>,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut roots = RootCertStore::empty();
    roots
        .add(certificate_der.into())
        .expect("add test certificate");
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(address).await.unwrap();
    connector
        .connect(
            ServerName::try_from("localhost").unwrap().to_owned(),
            stream,
        )
        .await
        .unwrap()
}

async fn connect_mtls(
    address: SocketAddr,
    server_certificate_der: Vec<u8>,
    client_identity: Option<(Vec<u8>, Vec<u8>)>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, std::io::Error> {
    let mut roots = RootCertStore::empty();
    roots.add(server_certificate_der.into()).unwrap();
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let config = match client_identity {
        Some((certificate, private_key)) => builder
            .with_client_auth_cert(
                vec![certificate.into()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key)),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(address).await?;
    connector
        .connect(
            ServerName::try_from("localhost").unwrap().to_owned(),
            stream,
        )
        .await
}

async fn mtls_connection_is_rejected(
    address: SocketAddr,
    server_certificate_der: Vec<u8>,
    client_identity: Option<(Vec<u8>, Vec<u8>)>,
) -> bool {
    let mut stream = match connect_mtls(address, server_certificate_der, client_identity).await {
        Ok(stream) => stream,
        Err(_) => return true,
    };
    if stream.write_all(&connect("rejected-client")).await.is_err() {
        return true;
    }
    let mut byte = [0_u8; 1];
    match tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte)).await {
        Ok(Ok(0) | Err(_)) => true,
        Ok(Ok(_)) | Err(_) => false,
    }
}

#[tokio::test]
async fn tls_and_plain_tcp_listeners_serve_the_same_mqtt_state_machine() {
    let (_directory, config, certificate_der) = tls_config();
    let running = spawn(config, Broker::new()).await.unwrap();
    let tls_address = running.mqtt_tls_addr.expect("TLS listener address");

    let mut tls = connect_tls(tls_address, certificate_der).await;
    tls.write_all(&connect("tls-client")).await.unwrap();
    assert_eq!(read_packet(&mut tls).await, [0x20, 2, 0, 0]);
    tls.write_all(&[0xc0, 0]).await.unwrap();
    assert_eq!(read_packet(&mut tls).await, [0xd0, 0]);

    let mut plain = TcpStream::connect(running.mqtt_addr).await.unwrap();
    plain.write_all(&connect("plain-client")).await.unwrap();
    assert_eq!(read_packet(&mut plain).await, [0x20, 2, 0, 0]);

    drop(tls);
    drop(plain);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn enabled_tls_listener_requires_certificate_and_private_key() {
    let mut config = Config::default();
    config.mqtt.bind = "127.0.0.1:0".into();
    config.http.bind = "127.0.0.1:0".into();
    config.mqtt_tls.enabled = true;
    config.mqtt_tls.bind = "127.0.0.1:0".into();

    let error = match spawn(config, Broker::new()).await {
        Ok(_) => panic!("TLS without credentials must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("TLS certificate"));
}

#[tokio::test]
async fn shutdown_cancels_incomplete_tls_handshake() {
    let (_directory, config, _certificate_der) = tls_config();
    let running = spawn(config, Broker::new()).await.unwrap();
    let tls_address = running.mqtt_tls_addr.expect("TLS listener address");
    let stalled_client = TcpStream::connect(tls_address).await.unwrap();

    tokio::time::timeout(Duration::from_secs(1), running.shutdown())
        .await
        .expect("shutdown must not wait for TLS ClientHello")
        .unwrap();
    drop(stalled_client);
}

#[tokio::test]
async fn mtls_accepts_client_certificate_signed_by_configured_ca() {
    let fixture = mtls_config();
    let running = spawn(fixture.config, Broker::new()).await.unwrap();
    let address = running.mqtt_tls_addr.unwrap();
    let mut client = connect_mtls(
        address,
        fixture.server_certificate_der,
        Some((
            fixture.client_certificate_der,
            fixture.client_private_key_der,
        )),
    )
    .await
    .unwrap();

    client.write_all(&connect("mtls-client")).await.unwrap();
    assert_eq!(read_packet(&mut client).await, [0x20, 2, 0, 0]);
    drop(client);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn mtls_rejects_missing_and_untrusted_client_certificates() {
    let fixture = mtls_config();
    let running = spawn(fixture.config, Broker::new()).await.unwrap();
    let address = running.mqtt_tls_addr.unwrap();

    assert!(
        mtls_connection_is_rejected(address, fixture.server_certificate_der.clone(), None,).await
    );
    assert!(
        mtls_connection_is_rejected(
            address,
            fixture.server_certificate_der,
            Some((
                fixture.untrusted_certificate_der,
                fixture.untrusted_private_key_der,
            )),
        )
        .await
    );

    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn mtls_requires_a_client_ca_file() {
    let (_directory, mut config, _server_certificate) = tls_config();
    config.mqtt_tls.verify_peer = true;

    let error = match spawn(config, Broker::new()).await {
        Ok(_) => panic!("mTLS without a client CA must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("client CA"));
}
