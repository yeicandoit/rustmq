use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::BufReader,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use bytes::BytesMut;
use quinn::{crypto::rustls::QuicServerConfig, Endpoint, IdleTimeout, TransportConfig};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::{broadcast, mpsc},
    task::JoinHandle,
};
use tokio_rustls::{
    rustls::{server::WebPkiClientVerifier, RootCertStore, ServerConfig},
    TlsAcceptor,
};

use crate::{
    broker::{Broker, ConnectionOptions, Outbound, SubscriptionOptions},
    config::{AuthConfig, Config},
    protocol::{decode_packet, encode_packet, Connect, Packet, ProtocolVersion, Publish},
};

pub struct RunningServer {
    pub mqtt_addr: SocketAddr,
    pub mqtt_tls_addr: Option<SocketAddr>,
    pub mqtt_ws_addr: Option<SocketAddr>,
    pub mqtt_quic_addr: Option<SocketAddr>,
    pub http_addr: SocketAddr,
    shutdown: broadcast::Sender<()>,
    tasks: Vec<JoinHandle<Result<()>>>,
}

impl RunningServer {
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown.send(());
        for task in self.tasks {
            task.await.context("server task join")??;
        }
        Ok(())
    }
}

pub async fn spawn(config: Config, broker: Broker) -> Result<RunningServer> {
    let tls_acceptor = if config.mqtt_tls.enabled {
        Some(load_tls_acceptor(&config)?)
    } else {
        None
    };
    let quic_endpoint = if config.mqtt_quic.enabled {
        Some(load_quic_endpoint(&config)?)
    } else {
        None
    };
    let mqtt_listener = TcpListener::bind(&config.mqtt.bind)
        .await
        .with_context(|| format!("bind MQTT {}", config.mqtt.bind))?;
    let mqtt_tls_listener = if tls_acceptor.is_some() {
        Some(
            TcpListener::bind(&config.mqtt_tls.bind)
                .await
                .with_context(|| format!("bind MQTT TLS {}", config.mqtt_tls.bind))?,
        )
    } else {
        None
    };
    if config.mqtt_ws.enabled && !config.mqtt_ws.path.starts_with('/') {
        bail!("MQTT WebSocket path must start with '/'")
    }
    let mqtt_ws_listener = if config.mqtt_ws.enabled {
        Some(
            TcpListener::bind(&config.mqtt_ws.bind)
                .await
                .with_context(|| format!("bind MQTT WebSocket {}", config.mqtt_ws.bind))?,
        )
    } else {
        None
    };
    let http_listener = TcpListener::bind(&config.http.bind)
        .await
        .with_context(|| format!("bind HTTP {}", config.http.bind))?;
    let mqtt_addr = mqtt_listener.local_addr()?;
    let mqtt_tls_addr = mqtt_tls_listener
        .as_ref()
        .map(TcpListener::local_addr)
        .transpose()?;
    let mqtt_ws_addr = mqtt_ws_listener
        .as_ref()
        .map(TcpListener::local_addr)
        .transpose()?;
    let mqtt_quic_addr = quic_endpoint
        .as_ref()
        .map(Endpoint::local_addr)
        .transpose()?;
    let http_addr = http_listener.local_addr()?;
    let (shutdown, _) = broadcast::channel(4);

    let mut mqtt_shutdown = shutdown.subscribe();
    let connection_shutdown = shutdown.clone();
    let mqtt_broker = broker.clone();
    let mqtt_config = config.clone();
    let mqtt_task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = mqtt_listener.accept() => {
                    let (stream, peer) = accepted.context("accept MQTT client")?;
                    mqtt_broker.metrics().accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let connection_broker = mqtt_broker.clone();
                    let connection_config = mqtt_config.clone();
                    let connection_rx = connection_shutdown.subscribe();
                    connections.spawn(async move {
                        if let Err(error) = handle_connection(
                            stream,
                            connection_config,
                            connection_broker,
                            connection_rx,
                        ).await {
                            tracing::debug!(%peer, %error, "MQTT connection closed");
                        }
                    });
                }
                completed = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = completed {
                        tracing::warn!(%error, "MQTT connection task failed");
                    }
                }
                _ = mqtt_shutdown.recv() => break,
            }
        }
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                tracing::warn!(%error, "MQTT connection task failed during shutdown");
            }
        }
        Ok(())
    });

    let tls_task = if let (Some(listener), Some(acceptor)) = (mqtt_tls_listener, tls_acceptor) {
        let mut tls_shutdown = shutdown.subscribe();
        let tls_connection_shutdown = shutdown.clone();
        let tls_broker = broker.clone();
        let tls_config = config.clone();
        Some(tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let mut handshake_shutdown = tls_connection_shutdown.subscribe();
                let connection_rx = tls_connection_shutdown.subscribe();
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, peer) = accepted.context("accept MQTT TLS client")?;
                        tls_broker.metrics().accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let connection_acceptor = acceptor.clone();
                        let connection_broker = tls_broker.clone();
                        let connection_config = tls_config.clone();
                        connections.spawn(async move {
                            let stream = tokio::select! {
                                result = connection_acceptor.accept(stream) => {
                                    match result {
                                        Ok(stream) => stream,
                                        Err(error) => {
                                            tracing::debug!(%peer, %error, "MQTT TLS handshake failed");
                                            return;
                                        }
                                    }
                                }
                                _ = handshake_shutdown.recv() => return,
                            };
                            if let Err(error) = handle_connection(
                                stream,
                                connection_config,
                                connection_broker,
                                connection_rx,
                            ).await {
                                tracing::debug!(%peer, %error, "MQTT TLS connection closed");
                            }
                        });
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        if let Some(Err(error)) = completed {
                            tracing::warn!(%error, "MQTT TLS connection task failed");
                        }
                    }
                    _ = tls_shutdown.recv() => break,
                }
            }
            while let Some(result) = connections.join_next().await {
                if let Err(error) = result {
                    tracing::warn!(%error, "MQTT TLS connection task failed during shutdown");
                }
            }
            Ok(())
        }))
    } else {
        None
    };

    let websocket_task = if let Some(listener) = mqtt_ws_listener {
        let websocket_state = WebSocketState {
            broker: broker.clone(),
            config: config.clone(),
            shutdown: shutdown.clone(),
        };
        let websocket_app = Router::new()
            .route(&config.mqtt_ws.path, get(mqtt_websocket))
            .with_state(websocket_state);
        let mut websocket_shutdown = shutdown.subscribe();
        Some(tokio::spawn(async move {
            axum::serve(listener, websocket_app)
                .with_graceful_shutdown(async move {
                    let _ = websocket_shutdown.recv().await;
                })
                .await
                .context("MQTT WebSocket server")
        }))
    } else {
        None
    };

    let quic_task = if let Some(endpoint) = quic_endpoint {
        let mut listener_shutdown = shutdown.subscribe();
        let connection_shutdown = shutdown.clone();
        let quic_broker = broker.clone();
        let quic_config = config.clone();
        Some(tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming = endpoint.accept() => {
                        let Some(incoming) = incoming else { break; };
                        let connection_broker = quic_broker.clone();
                        let connection_config = quic_config.clone();
                        let connection_rx = connection_shutdown.subscribe();
                        connections.spawn(async move {
                            if let Err(error) = handle_quic_connection(
                                incoming,
                                connection_config,
                                connection_broker,
                                connection_rx,
                            ).await {
                                tracing::debug!(%error, "MQTT QUIC connection closed");
                            }
                        });
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        if let Some(Err(error)) = completed {
                            tracing::warn!(%error, "MQTT QUIC connection task failed");
                        }
                    }
                    _ = listener_shutdown.recv() => {
                        endpoint.close(0_u32.into(), b"server shutdown");
                        break;
                    }
                }
            }
            while let Some(result) = connections.join_next().await {
                if let Err(error) = result {
                    tracing::warn!(%error, "MQTT QUIC connection task failed during shutdown");
                }
            }
            let _ = tokio::time::timeout(Duration::from_millis(250), endpoint.wait_idle()).await;
            Ok(())
        }))
    } else {
        None
    };

    let app = Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/api/v1/status", get(status))
        .route("/metrics", get(metrics))
        .with_state(broker);
    let mut http_shutdown = shutdown.subscribe();
    let http_task = tokio::spawn(async move {
        axum::serve(http_listener, app)
            .with_graceful_shutdown(async move {
                let _ = http_shutdown.recv().await;
            })
            .await
            .context("HTTP server")
    });

    let mut tasks = vec![mqtt_task, http_task];
    tasks.extend(tls_task);
    tasks.extend(websocket_task);
    tasks.extend(quic_task);
    Ok(RunningServer {
        mqtt_addr,
        mqtt_tls_addr,
        mqtt_ws_addr,
        mqtt_quic_addr,
        http_addr,
        shutdown,
        tasks,
    })
}

async fn handle_quic_connection(
    incoming: quinn::Incoming,
    config: Config,
    broker: Broker,
    mut shutdown: broadcast::Receiver<()>,
) -> Result<()> {
    let connection = tokio::select! {
        result = incoming => result.context("accept MQTT QUIC handshake")?,
        _ = shutdown.recv() => return Ok(()),
    };
    let peer = connection.remote_address();
    let (send, receive) = tokio::select! {
        result = connection.accept_bi() => result.context("accept MQTT QUIC control stream")?,
        _ = shutdown.recv() => {
            connection.close(0_u32.into(), b"server shutdown");
            return Ok(());
        }
    };
    broker
        .metrics()
        .accepted
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let stream = tokio::io::join(receive, send);
    let result = handle_connection(stream, config, broker, shutdown).await;
    connection.close(0_u32.into(), b"control stream closed");
    result.with_context(|| format!("MQTT QUIC client {peer}"))
}

#[derive(Clone)]
struct WebSocketState {
    broker: Broker,
    config: Config,
    shutdown: broadcast::Sender<()>,
}

async fn mqtt_websocket(
    State(state): State<WebSocketState>,
    headers: HeaderMap,
    websocket: WebSocketUpgrade,
) -> Response {
    const SUPPORTED: [&str; 4] = ["mqtt", "mqtt-v3", "mqtt-v3.1.1", "mqtt-v5"];
    let selected = headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(',')
                .map(str::trim)
                .find(|candidate| SUPPORTED.contains(candidate))
        });
    let Some(selected) = selected else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let protocol = selected.to_owned();
    websocket
        .max_message_size(state.config.mqtt.max_packet_size.saturating_add(5))
        .protocols([protocol])
        .on_upgrade(move |socket| run_websocket_connection(socket, state))
}

async fn run_websocket_connection(socket: WebSocket, state: WebSocketState) {
    state
        .broker
        .metrics()
        .accepted
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (mqtt_stream, websocket_stream) = tokio::io::duplex(64 * 1024);
    let mut connection = tokio::spawn(handle_connection(
        mqtt_stream,
        state.config.clone(),
        state.broker,
        state.shutdown.subscribe(),
    ));
    let mut bridge = Box::pin(bridge_websocket(
        socket,
        websocket_stream,
        state.config.mqtt.max_packet_size,
    ));
    tokio::select! {
        result = &mut connection => {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::debug!(%error, "MQTT WebSocket connection closed"),
                Err(error) => tracing::warn!(%error, "MQTT WebSocket connection task failed"),
            }
        }
        result = &mut bridge => {
            if let Err(error) = result {
                tracing::debug!(%error, "MQTT WebSocket transport closed");
            }
            drop(bridge);
            match connection.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::debug!(%error, "MQTT WebSocket connection closed"),
                Err(error) => tracing::warn!(%error, "MQTT WebSocket connection task failed"),
            }
        }
    }
}

async fn bridge_websocket(
    mut socket: WebSocket,
    stream: tokio::io::DuplexStream,
    max_packet_size: usize,
) -> Result<()> {
    let (mut mqtt_reader, mut mqtt_writer) = tokio::io::split(stream);
    let mut outbound = BytesMut::with_capacity(8192);
    loop {
        tokio::select! {
            message = socket.recv() => {
                match message {
                    Some(Ok(Message::Binary(payload))) => {
                        mqtt_writer.write_all(&payload).await.context("forward WebSocket MQTT data")?;
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    Some(Ok(Message::Text(_) | Message::Close(_))) | None => break,
                    Some(Err(error)) => return Err(error).context("read MQTT WebSocket frame"),
                }
            }
            read = mqtt_reader.read_buf(&mut outbound) => {
                if read.context("read MQTT WebSocket bridge")? == 0 {
                    break;
                }
                while let Some(packet_length) = mqtt_packet_length(&outbound, max_packet_size)? {
                    let packet = outbound.split_to(packet_length).freeze();
                    socket
                        .send(Message::Binary(packet))
                        .await
                        .context("write MQTT WebSocket frame")?;
                }
            }
        }
    }
    Ok(())
}

fn mqtt_packet_length(buffer: &[u8], max_packet_size: usize) -> Result<Option<usize>> {
    if buffer.len() < 2 {
        return Ok(None);
    }
    let mut remaining = 0_usize;
    let mut multiplier = 1_usize;
    for index in 1..=4 {
        let Some(byte) = buffer.get(index).copied() else {
            return Ok(None);
        };
        remaining = remaining
            .checked_add(usize::from(byte & 0x7f).saturating_mul(multiplier))
            .context("MQTT WebSocket packet length overflow")?;
        if byte & 0x80 == 0 {
            if remaining > max_packet_size {
                bail!("MQTT WebSocket packet exceeds configured maximum")
            }
            let total = 1_usize
                .checked_add(index)
                .and_then(|header| header.checked_add(remaining))
                .context("MQTT WebSocket packet length overflow")?;
            return Ok((buffer.len() >= total).then_some(total));
        }
        multiplier = multiplier
            .checked_mul(128)
            .context("MQTT WebSocket packet length overflow")?;
    }
    bail!("malformed MQTT WebSocket Remaining Length")
}

fn load_tls_acceptor(config: &Config) -> Result<TlsAcceptor> {
    let certificate_path = config
        .mqtt_tls
        .certfile
        .as_ref()
        .context("MQTT TLS certificate file is required")?;
    let key_path = config
        .mqtt_tls
        .keyfile
        .as_ref()
        .context("MQTT TLS private key file is required")?;
    let mut certificate_reader =
        BufReader::new(File::open(certificate_path).with_context(|| {
            format!("open MQTT TLS certificate {}", certificate_path.display())
        })?);
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<std::io::Result<Vec<_>>>()
        .context("read MQTT TLS certificate")?;
    if certificates.is_empty() {
        bail!("MQTT TLS certificate file contains no certificates")
    }
    let mut key_reader = BufReader::new(
        File::open(key_path)
            .with_context(|| format!("open MQTT TLS private key {}", key_path.display()))?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .context("read MQTT TLS private key")?
        .context("MQTT TLS private key file contains no private key")?;
    let server_config = if config.mqtt_tls.verify_peer {
        let ca_path = config
            .mqtt_tls
            .cacertfile
            .as_ref()
            .context("MQTT TLS client CA file is required when verify_peer is enabled")?;
        let mut ca_reader = BufReader::new(
            File::open(ca_path)
                .with_context(|| format!("open MQTT TLS client CA {}", ca_path.display()))?,
        );
        let mut roots = RootCertStore::empty();
        for certificate in rustls_pemfile::certs(&mut ca_reader) {
            roots
                .add(certificate.context("read MQTT TLS client CA certificate")?)
                .context("add MQTT TLS client CA certificate")?;
        }
        if roots.is_empty() {
            bail!("MQTT TLS client CA file contains no certificates")
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .context("configure MQTT TLS client certificate verification")?;
        ServerConfig::builder().with_client_cert_verifier(verifier)
    } else {
        ServerConfig::builder().with_no_client_auth()
    }
    .with_single_cert(certificates, private_key)
    .context("configure MQTT TLS certificate and private key")?;
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

fn load_quic_endpoint(config: &Config) -> Result<Endpoint> {
    let certificate_path = config
        .mqtt_quic
        .certfile
        .as_ref()
        .context("MQTT QUIC certificate file is required")?;
    let key_path = config
        .mqtt_quic
        .keyfile
        .as_ref()
        .context("MQTT QUIC private key file is required")?;
    let mut certificate_reader =
        BufReader::new(File::open(certificate_path).with_context(|| {
            format!("open MQTT QUIC certificate {}", certificate_path.display())
        })?);
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<std::io::Result<Vec<_>>>()
        .context("read MQTT QUIC certificate")?;
    if certificates.is_empty() {
        bail!("MQTT QUIC certificate file contains no certificates")
    }
    let mut key_reader = BufReader::new(
        File::open(key_path)
            .with_context(|| format!("open MQTT QUIC private key {}", key_path.display()))?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .context("read MQTT QUIC private key")?
        .context("MQTT QUIC private key file contains no private key")?;
    let mut crypto = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .context("configure MQTT QUIC certificate and private key")?;
    crypto.alpn_protocols = vec![b"mqtt".to_vec()];
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(crypto).context("configure MQTT QUIC TLS")?,
    ));
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(1_u8.into());
    transport.max_concurrent_uni_streams(0_u8.into());
    if config.mqtt_quic.idle_timeout_ms > 0 {
        transport.max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_millis(config.mqtt_quic.idle_timeout_ms))
                .context("MQTT QUIC idle timeout is too large")?,
        ));
    } else {
        transport.max_idle_timeout(None);
    }
    server_config.transport_config(Arc::new(transport));
    let bind = config
        .mqtt_quic
        .bind
        .parse::<SocketAddr>()
        .with_context(|| format!("parse MQTT QUIC bind {}", config.mqtt_quic.bind))?;
    Endpoint::server(server_config, bind)
        .with_context(|| format!("bind MQTT QUIC {}", config.mqtt_quic.bind))
}

async fn status(State(broker): State<Broker>) -> Json<crate::broker::Status> {
    Json(broker.status())
}

async fn metrics(State(broker): State<Broker>) -> impl IntoResponse {
    let mut response = broker.prometheus().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

struct ConnectionState {
    client_id: String,
    token: u64,
    version: ProtocolVersion,
    session_expiry_interval: u32,
    keep_alive: u16,
    will: Option<crate::protocol::Will>,
    inbound_topic_aliases: HashMap<u16, String>,
    outbound_topic_alias_maximum: u16,
    outbound_topic_aliases: HashMap<String, u16>,
}

async fn handle_connection<S>(
    stream: S,
    config: Config,
    broker: Broker,
    mut shutdown: broadcast::Receiver<()>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (outbound_tx, mut outbound_rx) = mpsc::channel(config.mqtt.outbound_queue.max(1));
    let (disconnect_tx, mut disconnect_rx) = mpsc::channel(1);
    let mut buffer = BytesMut::with_capacity(8192);
    let mut state: Option<ConnectionState> = None;
    let mut normal_disconnect = false;
    let mut protocol_close = false;
    let mut qos2_pending: HashMap<u16, Publish> = HashMap::new();
    let mut qos2_complete: HashSet<u16> = HashSet::new();
    let mut last_inbound = tokio::time::Instant::now();
    let retry_interval = Duration::from_millis(config.mqtt.retry_interval_ms.max(1));
    let mut retry_tick = tokio::time::interval(retry_interval);
    retry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let keepalive = state.as_ref().map_or(0, |current| current.keep_alive);
        let timeout = if keepalive == 0 {
            Duration::from_secs(24 * 60 * 60)
        } else {
            Duration::from_millis(u64::from(keepalive) * 1500)
        };
        let read_deadline = last_inbound + timeout;
        tokio::select! {
            read = tokio::time::timeout_at(read_deadline, reader.read_buf(&mut buffer)) => {
                let bytes_read = match read {
                    Ok(result) => result.context("read MQTT socket")?,
                    Err(_) => break,
                };
                if bytes_read == 0 { break; }
                last_inbound = tokio::time::Instant::now();
                loop {
                    let parse_version = state.as_ref().map_or(ProtocolVersion::V311, |current| current.version);
                    let Some(packet) = decode_packet(&mut buffer, parse_version, config.mqtt.max_packet_size)? else { break; };
                    match packet {
                        Packet::Connect(connect) if state.is_none() => {
                            if !authenticate(&connect, &config.auth) {
                                let code = if connect.version == ProtocolVersion::V5 { 0x86 } else { 4 };
                                write_packet(
                                    &mut writer,
                                    &Packet::ConnAck {
                                        session_present: false,
                                        code,
                                        topic_alias_maximum: None,
                                    },
                                    connect.version,
                                ).await?;
                                normal_disconnect = true;
                                break;
                            }
                            let (token, present) = broker.register_with_expiry(
                                &connect.client_id,
                                ConnectionOptions {
                                    clean_start: connect.clean_start,
                                    expiry_interval: connect.session_expiry_interval,
                                    receive_maximum: connect.receive_maximum,
                                    will: connect.will.clone(),
                                },
                                outbound_tx.clone(),
                                disconnect_tx.clone(),
                            );
                            write_packet(
                                &mut writer,
                                &Packet::ConnAck {
                                    session_present: present,
                                    code: 0,
                                    topic_alias_maximum: (connect.version == ProtocolVersion::V5)
                                        .then_some(config.mqtt.max_topic_alias),
                                },
                                connect.version,
                            ).await?;
                            state = Some(ConnectionState {
                                client_id: connect.client_id,
                                token,
                                version: connect.version,
                                session_expiry_interval: connect.session_expiry_interval,
                                keep_alive: connect.keep_alive,
                                will: connect.will,
                                inbound_topic_aliases: HashMap::new(),
                                outbound_topic_alias_maximum: connect.topic_alias_maximum,
                                outbound_topic_aliases: HashMap::new(),
                            });
                        }
                        Packet::Connect(_) => bail!("duplicate CONNECT"),
                        _ if state.is_none() => bail!("CONNECT must be the first packet"),
                        Packet::PingReq => {
                            let version = state.as_ref().expect("state checked").version;
                            write_packet(&mut writer, &Packet::PingResp, version).await?;
                        }
                        Packet::Subscribe {
                            packet_id,
                            subscription_identifier,
                            filters,
                        } => {
                            let current = state.as_ref().expect("state checked");
                            let mut codes = Vec::with_capacity(filters.len());
                            let mut retained = Vec::new();
                            for subscription in filters {
                                match broker.subscribe_with_options(
                                    &current.client_id,
                                    &subscription.filter,
                                    SubscriptionOptions {
                                        qos: subscription.qos,
                                        no_local: subscription.no_local,
                                        retain_as_published: subscription.retain_as_published,
                                        retain_handling: subscription.retain_handling,
                                        subscription_identifier,
                                    },
                                ) {
                                    Ok(messages) => { codes.push(subscription.qos.min(2)); retained.extend(messages); }
                                    Err(_) => codes.push(if current.version == ProtocolVersion::V5 { 0x8f } else { 0x80 }),
                                }
                            }
                            write_packet(&mut writer, &Packet::SubAck { packet_id, codes }, current.version).await?;
                            for publish in retained {
                                broker.deliver_prepared(&current.client_id, publish);
                            }
                        }
                        Packet::Unsubscribe { packet_id, filters } => {
                            let current = state.as_ref().expect("state checked");
                            let filter_count = filters.len();
                            for filter in filters { broker.unsubscribe(&current.client_id, &filter); }
                            write_packet(
                                &mut writer,
                                &Packet::UnsubAck {
                                    packet_id,
                                    codes: vec![0; filter_count],
                                },
                                current.version,
                            ).await?;
                        }
                        Packet::Publish(mut publish) if publish.qos < 2 => {
                            let alias_result = resolve_topic_alias(
                                &mut publish,
                                state.as_mut().expect("state checked"),
                                config.mqtt.max_topic_alias,
                            );
                            if let Err(reason_code) = alias_result {
                                let version = state.as_ref().expect("state checked").version;
                                if version == ProtocolVersion::V5 {
                                    write_packet(
                                        &mut writer,
                                        &Packet::Disconnect {
                                            reason_code,
                                            session_expiry_interval: None,
                                        },
                                        version,
                                    ).await?;
                                }
                                protocol_close = true;
                                break;
                            }
                            let current = state.as_ref().expect("state checked");
                            let packet_id = publish.packet_id;
                            broker.publish_from(Some(&current.client_id), publish);
                            if let Some(id) = packet_id {
                                write_packet(&mut writer, &Packet::PubAck(id), current.version).await?;
                            }
                        }
                        Packet::Publish(mut publish) => {
                            let alias_result = resolve_topic_alias(
                                &mut publish,
                                state.as_mut().expect("state checked"),
                                config.mqtt.max_topic_alias,
                            );
                            if let Err(reason_code) = alias_result {
                                let version = state.as_ref().expect("state checked").version;
                                if version == ProtocolVersion::V5 {
                                    write_packet(
                                        &mut writer,
                                        &Packet::Disconnect {
                                            reason_code,
                                            session_expiry_interval: None,
                                        },
                                        version,
                                    ).await?;
                                }
                                protocol_close = true;
                                break;
                            }
                            let current = state.as_ref().expect("state checked");
                            let id = publish.packet_id.context("QoS2 packet missing id")?;
                            if qos2_complete.contains(&id) && !publish.dup {
                                qos2_complete.remove(&id);
                            }
                            if !qos2_complete.contains(&id) {
                                qos2_pending.entry(id).or_insert(publish);
                            }
                            write_packet(&mut writer, &Packet::PubRec(id), current.version).await?;
                        }
                        Packet::PubRel(id) => {
                            let current = state.as_ref().expect("state checked");
                            if let Some(publish) = qos2_pending.remove(&id) {
                                broker.publish_from(Some(&current.client_id), publish);
                                qos2_complete.insert(id);
                            }
                            write_packet(&mut writer, &Packet::PubComp(id), current.version).await?;
                        }
                        Packet::Disconnect {
                            reason_code,
                            session_expiry_interval,
                        } => {
                            let current = state.as_mut().expect("state checked");
                            if let Some(expiry) = session_expiry_interval {
                                if current.session_expiry_interval == 0 && expiry != 0 {
                                    protocol_close = true;
                                    break;
                                }
                                current.session_expiry_interval = expiry;
                                broker.set_session_expiry(&current.client_id, expiry);
                            }
                            if reason_code == 0x04 {
                                if let Some(will) = current.will.take() {
                                    broker.schedule_will(&current.client_id, will, 0);
                                }
                            }
                            normal_disconnect = true;
                            break;
                        }
                        Packet::PubAck(packet_id) => {
                            let current = state.as_ref().expect("state checked");
                            broker.puback(&current.client_id, packet_id);
                        }
                        Packet::PubRec(packet_id) => {
                            let current = state.as_ref().expect("state checked");
                            broker.pubrec(&current.client_id, packet_id);
                        }
                        Packet::PubComp(packet_id) => {
                            let current = state.as_ref().expect("state checked");
                            broker.pubcomp(&current.client_id, packet_id);
                        }
                        _ => bail!("packet is not valid from a client in this state"),
                    }
                }
                if normal_disconnect || protocol_close { break; }
            }
            outbound = outbound_rx.recv(), if state.is_some() => {
                match outbound {
                    Some(Outbound::Packet(mut packet)) => {
                        let current = state.as_mut().expect("state checked");
                        pack_outbound_topic_alias(&mut packet, current);
                        let version = current.version;
                        write_packet(&mut writer, &packet, version).await?;
                    }
                    None => break,
                }
            }
            _ = disconnect_rx.recv() => break,
            _ = retry_tick.tick(), if state.is_some() => {
                let current = state.as_ref().expect("state checked");
                broker.retry_due(&current.client_id, retry_interval);
            }
            _ = shutdown.recv() => break,
        }
    }

    if let Some(current) = state {
        let unregistered = broker.unregister(&current.client_id, current.token);
        if unregistered && !normal_disconnect {
            if let Some(will) = current.will {
                broker.schedule_will(&current.client_id, will, current.session_expiry_interval);
            }
        }
    }
    Ok(())
}

fn resolve_topic_alias(
    publish: &mut Publish,
    state: &mut ConnectionState,
    maximum: u16,
) -> std::result::Result<(), u8> {
    match (publish.topic.is_empty(), publish.topic_alias) {
        (false, Some(alias)) => {
            if alias > maximum {
                return Err(0x94);
            }
            state
                .inbound_topic_aliases
                .insert(alias, publish.topic.clone());
        }
        (true, Some(alias)) => {
            if alias > maximum {
                return Err(0x94);
            }
            publish.topic = state
                .inbound_topic_aliases
                .get(&alias)
                .cloned()
                .ok_or(0x82)?;
        }
        (true, None) => return Err(0x82),
        (false, None) => {}
    }
    publish.topic_alias = None;
    Ok(())
}

fn pack_outbound_topic_alias(packet: &mut Packet, state: &mut ConnectionState) {
    if state.version != ProtocolVersion::V5 || state.outbound_topic_alias_maximum == 0 {
        return;
    }
    let Packet::Publish(publish) = packet else {
        return;
    };
    if let Some(alias) = state.outbound_topic_aliases.get(&publish.topic).copied() {
        publish.topic.clear();
        publish.topic_alias = Some(alias);
        return;
    }
    let Ok(alias) = u16::try_from(state.outbound_topic_aliases.len() + 1) else {
        return;
    };
    if alias > state.outbound_topic_alias_maximum {
        return;
    }
    state
        .outbound_topic_aliases
        .insert(publish.topic.clone(), alias);
    publish.topic_alias = Some(alias);
}

fn authenticate(connect: &Connect, config: &AuthConfig) -> bool {
    let (expected_user, expected_password) = match (&config.username, &config.password) {
        (None, None) => return true,
        (Some(username), Some(password)) => (username, password),
        _ => return false,
    };
    let Some(username) = &connect.username else {
        return false;
    };
    let Some(password) = &connect.password else {
        return false;
    };
    bool::from(username.as_bytes().ct_eq(expected_user.as_bytes()))
        & bool::from(password.as_ref().ct_eq(expected_password.as_bytes()))
}

async fn write_packet<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    packet: &Packet,
    version: ProtocolVersion,
) -> Result<()> {
    let encoded = encode_packet(packet, version)?;
    writer
        .write_all(&encoded)
        .await
        .context("write MQTT packet")
}
