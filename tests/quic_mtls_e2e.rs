use std::{net::SocketAddr, sync::Arc, time::Duration};

use quinn::{crypto::rustls::QuicClientConfig, Endpoint};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustmq::{broker::Broker, config::Config, server::spawn};
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    RootCertStore,
};

struct QuicMtlsFixture {
    _directory: tempfile::TempDir,
    config: Config,
    server_certificate_der: Vec<u8>,
    client_certificate_der: Vec<u8>,
    client_private_key_der: Vec<u8>,
    untrusted_certificate_der: Vec<u8>,
    untrusted_private_key_der: Vec<u8>,
}

fn connect_packet(client_id: &str) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 2, 0, 30];
    body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    let mut packet = vec![0x10, body.len() as u8];
    packet.extend(body);
    packet
}

fn quic_mtls_config() -> QuicMtlsFixture {
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

    let config_path = directory.path().join("rustmq.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
[mqtt]
bind = "127.0.0.1:0"

[http]
bind = "127.0.0.1:0"

[mqtt_quic]
enabled = true
bind = "127.0.0.1:0"
certfile = "{}"
keyfile = "{}"
verify_peer = true
cacertfile = "{}"
"#,
            server_certificate.display(),
            server_private_key.display(),
            ca_path.display(),
        ),
    )
    .unwrap();

    QuicMtlsFixture {
        _directory: directory,
        config: Config::load(config_path).unwrap(),
        server_certificate_der: server.cert.der().to_vec(),
        client_certificate_der: client_certificate.der().to_vec(),
        client_private_key_der: client_key.serialize_der(),
        untrusted_certificate_der: untrusted.cert.der().to_vec(),
        untrusted_private_key_der: untrusted.key_pair.serialize_der(),
    }
}

fn quic_client(server_certificate_der: &[u8], client_identity: Option<(&[u8], &[u8])>) -> Endpoint {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_certificate_der.to_vec()))
        .unwrap();
    let builder = tokio_rustls::rustls::ClientConfig::builder().with_root_certificates(roots);
    let mut crypto = match client_identity {
        Some((certificate, private_key)) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from(certificate.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key.to_vec())),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    crypto.alpn_protocols = vec![b"mqtt".to_vec()];
    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}

async fn connection_is_rejected(
    address: SocketAddr,
    server_certificate_der: &[u8],
    client_identity: Option<(&[u8], &[u8])>,
) -> bool {
    let endpoint = quic_client(server_certificate_der, client_identity);
    let connection = match endpoint.connect(address, "localhost").unwrap().await {
        Ok(connection) => connection,
        Err(_) => return true,
    };
    let (mut send, mut receive) = match connection.open_bi().await {
        Ok(stream) => stream,
        Err(_) => return true,
    };
    if send
        .write_all(&connect_packet("rejected-client"))
        .await
        .is_err()
    {
        return true;
    }
    let mut byte = [0_u8; 1];
    match tokio::time::timeout(Duration::from_secs(1), receive.read(&mut byte)).await {
        Ok(Ok(None) | Err(_)) => true,
        Ok(Ok(_)) | Err(_) => false,
    }
}

#[tokio::test]
async fn quic_mtls_accepts_trusted_and_rejects_missing_or_untrusted_certificates() {
    let fixture = quic_mtls_config();
    let running = spawn(fixture.config, Broker::new()).await.unwrap();
    let address = running.mqtt_quic_addr.unwrap();

    let endpoint = quic_client(
        &fixture.server_certificate_der,
        Some((
            &fixture.client_certificate_der,
            &fixture.client_private_key_der,
        )),
    );
    let connection = endpoint
        .connect(address, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut receive) = connection.open_bi().await.unwrap();
    send.write_all(&connect_packet("trusted-quic-client"))
        .await
        .unwrap();
    let mut connack = [0_u8; 4];
    receive.read_exact(&mut connack).await.unwrap();
    assert_eq!(connack, [0x20, 2, 0, 0]);

    assert!(
        connection_is_rejected(address, &fixture.server_certificate_der, None).await,
        "a missing QUIC client certificate must be rejected"
    );
    assert!(
        connection_is_rejected(
            address,
            &fixture.server_certificate_der,
            Some((
                &fixture.untrusted_certificate_der,
                &fixture.untrusted_private_key_der,
            )),
        )
        .await,
        "an untrusted QUIC client certificate must be rejected"
    );

    connection.close(0_u32.into(), b"done");
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn quic_mtls_requires_a_client_ca_file() {
    let fixture = quic_mtls_config();
    let mut config = fixture.config;
    config.mqtt_quic.cacertfile = None;

    let error = match spawn(config, Broker::new()).await {
        Ok(_) => panic!("QUIC mTLS without a client CA must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("QUIC client CA"));
}
