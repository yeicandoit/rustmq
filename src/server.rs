use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::BufReader,
    net::SocketAddr,
    sync::{Arc, Mutex},
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
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::{broadcast, mpsc, watch},
    task::JoinHandle,
};
use tokio_rustls::{
    rustls::{server::WebPkiClientVerifier, RootCertStore, ServerConfig},
    TlsAcceptor,
};

use crate::{
    auth::{
        AuthCache, AuthCredential, AuthOutcome, AuthenticationProvider,
        StaticAuthenticationProvider, BAD_AUTHENTICATION_METHOD,
    },
    authorization::{
        AuthorizationEngine, AuthorizationSession, DenyAction, SubscriptionAuthorization,
    },
    broker::{
        AdministrativeDisconnect, Broker, ConnectionOptions, DeliveryTarget, Outbound,
        SubscriptionOptions,
    },
    config::Config,
    management,
    protocol::{decode_packet, encode_packet, Auth, Connect, Packet, ProtocolVersion, Publish},
};

pub struct RunningServer {
    pub mqtt_addr: SocketAddr,
    pub mqtt_tls_addr: Option<SocketAddr>,
    pub mqtt_ws_addr: Option<SocketAddr>,
    pub mqtt_quic_addr: Option<SocketAddr>,
    pub http_addr: SocketAddr,
    shutdown: broadcast::Sender<()>,
    tasks: Vec<JoinHandle<Result<()>>>,
    broker: Broker,
}

impl RunningServer {
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown.send(());
        let mut first_error = None;
        for task in self.tasks {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    if first_error.is_none() {
                        first_error = Some(error.context("server task"));
                    }
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(anyhow::Error::new(error).context("server task join"));
                    }
                }
            }
        }
        let flush_result = self.broker.prepare_shutdown();
        if let Some(error) = first_error {
            flush_result?;
            return Err(error);
        }
        flush_result
    }
}

pub async fn spawn(config: Config, broker: Broker) -> Result<RunningServer> {
    config.validate_management()?;
    let authorization = AuthorizationEngine::compile(&config.authorization)
        .context("compile authorization configuration")?;
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
    let mqtt_authorization = authorization.clone();
    let mqtt_task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = mqtt_listener.accept() => {
                    let (stream, peer) = accepted.context("accept MQTT client")?;
                    mqtt_broker.metrics().accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let connection_broker = mqtt_broker.clone();
                    let connection_config = mqtt_config.clone();
                    let connection_authorization = mqtt_authorization.clone();
                    let connection_rx = connection_shutdown.subscribe();
                    connections.spawn(async move {
                        if let Err(error) = handle_connection(
                            stream,
                            connection_config,
                            connection_broker,
                            connection_authorization,
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
        let tls_authorization = authorization.clone();
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
                        let connection_authorization = tls_authorization.clone();
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
                                connection_authorization,
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
            authorization: authorization.clone(),
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
        let quic_authorization = authorization.clone();
        Some(tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming = endpoint.accept() => {
                        let Some(incoming) = incoming else { break; };
                        let connection_broker = quic_broker.clone();
                        let connection_config = quic_config.clone();
                        let connection_authorization = quic_authorization.clone();
                        let connection_rx = connection_shutdown.subscribe();
                        connections.spawn(async move {
                            if let Err(error) = handle_quic_connection(
                                incoming,
                                connection_config,
                                connection_broker,
                                connection_authorization,
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

    let management_state =
        management::ApiState::new(broker.clone(), config.node.id.clone(), &config.management);
    let management_app = management::router(management_state, config.management.enabled);
    let app = Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/api/v1/status", get(status))
        .route("/metrics", get(metrics))
        .with_state(broker.clone())
        .merge(management_app);
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
        broker,
    })
}

async fn handle_quic_connection(
    incoming: quinn::Incoming,
    config: Config,
    broker: Broker,
    authorization: Arc<AuthorizationEngine>,
    mut shutdown: broadcast::Receiver<()>,
) -> Result<()> {
    let connecting = incoming.accept().context("accept MQTT QUIC connection")?;
    let connection = if config.mqtt_quic.enable_0rtt && !config.mqtt_quic.verify_peer {
        connecting
            .into_0rtt()
            .expect("server-side QUIC 0-RTT conversion always succeeds")
            .0
    } else {
        tokio::select! {
            result = connecting => result.context("accept MQTT QUIC handshake")?,
            _ = shutdown.recv() => return Ok(()),
        }
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
    let (activation_tx, activation_rx) = watch::channel(None);
    let mut control = Box::pin(handle_connection_with_activation(
        stream,
        config.clone(),
        broker.clone(),
        authorization,
        shutdown.resubscribe(),
        Some(activation_tx),
    ));
    let mut data_streams = tokio::task::JoinSet::new();
    let result = loop {
        tokio::select! {
            result = &mut control => break result,
            accepted = connection.accept_bi() => {
                match accepted {
                    Ok((send, receive)) => {
                        data_streams.spawn(run_quic_data_stream(
                            send,
                            receive,
                            config.clone(),
                            broker.clone(),
                            activation_rx.clone(),
                            shutdown.resubscribe(),
                        ));
                    }
                    Err(error) => {
                        tracing::debug!(%peer, %error, "MQTT QUIC stopped accepting data streams");
                        break control.as_mut().await;
                    }
                }
            }
            completed = data_streams.join_next(), if !data_streams.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::warn!(%peer, %error, "MQTT QUIC data stream task failed");
                }
            }
        }
    };
    connection.close(0_u32.into(), b"control stream closed");
    while let Some(completed) = data_streams.join_next().await {
        if let Err(error) = completed {
            tracing::warn!(%peer, %error, "MQTT QUIC data stream task failed during shutdown");
        }
    }
    result.with_context(|| format!("MQTT QUIC client {peer}"))
}

#[derive(Clone)]
struct QuicDataContext {
    client_id: String,
    connection: u64,
    version: ProtocolVersion,
    authorization: Arc<AuthorizationSession>,
    inbound_topic_aliases: Arc<Mutex<HashMap<u16, String>>>,
    activity: mpsc::Sender<()>,
}

struct QuicDataRuntime {
    config: Config,
    broker: Broker,
    context: QuicDataContext,
    target: DeliveryTarget,
    outbound_rx: mpsc::Receiver<Outbound>,
    disconnect_rx: mpsc::Receiver<()>,
    shutdown: broadcast::Receiver<()>,
}

async fn run_quic_data_stream(
    mut send: quinn::SendStream,
    mut receive: quinn::RecvStream,
    config: Config,
    broker: Broker,
    mut activation: watch::Receiver<Option<QuicDataContext>>,
    mut shutdown: broadcast::Receiver<()>,
) {
    let context = loop {
        if let Some(context) = activation.borrow().clone() {
            break context;
        }
        tokio::select! {
            changed = activation.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            _ = shutdown.recv() => return,
        }
    };
    let stream = send.id().index();
    let target = DeliveryTarget::Data {
        connection: context.connection,
        stream,
    };
    let (outbound_tx, outbound_rx) = mpsc::channel(config.mqtt.outbound_queue.max(1));
    let (disconnect_tx, disconnect_rx) = mpsc::channel(1);
    if !broker.register_data_stream(
        &context.client_id,
        context.connection,
        stream,
        outbound_tx,
        disconnect_tx,
    ) {
        return;
    }
    let runtime = QuicDataRuntime {
        config,
        broker: broker.clone(),
        context: context.clone(),
        target,
        outbound_rx,
        disconnect_rx,
        shutdown,
    };
    let result = handle_quic_data_stream(&mut send, &mut receive, runtime).await;
    broker.unregister_data_stream(&context.client_id, context.connection, stream);
    if let Err(error) = result {
        tracing::debug!(stream = %send.id(), %error, "MQTT QUIC data stream closed");
        let _ = send.reset(1_u8.into());
        let _ = receive.stop(1_u8.into());
    }
}

async fn handle_quic_data_stream(
    send: &mut quinn::SendStream,
    receive: &mut quinn::RecvStream,
    mut runtime: QuicDataRuntime,
) -> Result<()> {
    let mut buffer = BytesMut::with_capacity(8192);
    let mut qos2_pending: HashMap<u16, Publish> = HashMap::new();
    let mut qos2_complete: HashSet<u16> = HashSet::new();
    loop {
        tokio::select! {
            read = receive.read_buf(&mut buffer) => {
                if read.context("read MQTT QUIC data stream")? == 0 {
                    return Ok(());
                }
                let _ = runtime.context.activity.try_send(());
                while let Some(packet) = decode_packet(
                    &mut buffer,
                    runtime.context.version,
                    runtime.config.mqtt.max_packet_size,
                )? {
                    match packet {
                        Packet::Publish(mut publish) if publish.qos < 2 => {
                            resolve_topic_alias(
                                &mut publish,
                                &runtime.context.inbound_topic_aliases,
                                runtime.config.mqtt.max_topic_alias,
                            )
                            .map_err(|reason| anyhow::anyhow!("invalid topic alias: {reason:#04x}"))?;
                            let packet_id = publish.packet_id;
                            if !runtime
                                .context
                                .authorization
                                .authorize_publish(&publish.topic, publish.qos, publish.retain)
                                .is_allowed()
                            {
                                if write_publish_denied(
                                    send,
                                    runtime.context.version,
                                    publish.qos,
                                    packet_id,
                                    runtime.context.authorization.deny_action(),
                                )
                                .await?
                                {
                                    runtime.broker.disconnect_current(
                                        &runtime.context.client_id,
                                        runtime.context.connection,
                                    );
                                    return Ok(());
                                }
                                continue;
                            }
                            runtime
                                .broker
                                .publish_from(Some(&runtime.context.client_id), publish);
                            if let Some(packet_id) = packet_id {
                                write_packet(
                                    send,
                                    &Packet::PubAck(packet_id),
                                    runtime.context.version,
                                ).await?;
                            }
                        }
                        Packet::Publish(mut publish) => {
                            resolve_topic_alias(
                                &mut publish,
                                &runtime.context.inbound_topic_aliases,
                                runtime.config.mqtt.max_topic_alias,
                            )
                            .map_err(|reason| anyhow::anyhow!("invalid topic alias: {reason:#04x}"))?;
                            let packet_id = publish.packet_id.context("QoS2 packet missing id")?;
                            if !runtime
                                .context
                                .authorization
                                .authorize_publish(&publish.topic, publish.qos, publish.retain)
                                .is_allowed()
                            {
                                if write_publish_denied(
                                    send,
                                    runtime.context.version,
                                    publish.qos,
                                    Some(packet_id),
                                    runtime.context.authorization.deny_action(),
                                )
                                .await?
                                {
                                    runtime.broker.disconnect_current(
                                        &runtime.context.client_id,
                                        runtime.context.connection,
                                    );
                                    return Ok(());
                                }
                                continue;
                            }
                            if qos2_complete.contains(&packet_id) && !publish.dup {
                                qos2_complete.remove(&packet_id);
                            }
                            if !qos2_complete.contains(&packet_id) {
                                qos2_pending.entry(packet_id).or_insert(publish);
                            }
                            write_packet(
                                send,
                                &Packet::PubRec(packet_id),
                                runtime.context.version,
                            ).await?;
                        }
                        Packet::PubRel(packet_id) => {
                            if let Some(publish) = qos2_pending.remove(&packet_id) {
                                runtime
                                    .broker
                                    .publish_from(Some(&runtime.context.client_id), publish);
                                qos2_complete.insert(packet_id);
                            }
                            write_packet(
                                send,
                                &Packet::PubComp(packet_id),
                                runtime.context.version,
                            ).await?;
                        }
                        Packet::Subscribe {
                            packet_id,
                            subscription_identifier,
                            filters,
                        } => {
                            if runtime.context.authorization.deny_action()
                                == DenyAction::Disconnect
                            {
                                let mut denied = false;
                                for subscription in &filters {
                                    if runtime
                                        .context
                                        .authorization
                                        .authorize_subscribe(
                                            &subscription.filter,
                                            subscription.qos,
                                        )
                                        == SubscriptionAuthorization::Deny
                                    {
                                        denied = true;
                                        break;
                                    }
                                }
                                if denied {
                                    write_protocol_disconnect(
                                        send,
                                        runtime.context.version,
                                        0x87,
                                    )
                                    .await?;
                                    runtime.broker.disconnect_current(
                                        &runtime.context.client_id,
                                        runtime.context.connection,
                                    );
                                    return Ok(());
                                }
                            }
                            let mut codes = Vec::with_capacity(filters.len());
                            let mut retained = Vec::new();
                            for subscription in filters {
                                if let Some(code) = subscription_failure_code(
                                    runtime
                                        .context
                                        .authorization
                                        .authorize_subscribe(
                                            &subscription.filter,
                                            subscription.qos,
                                        ),
                                    runtime.context.version,
                                ) {
                                    codes.push(code);
                                    continue;
                                }
                                match runtime.broker.subscribe_with_target(
                                    &runtime.context.client_id,
                                    runtime.target,
                                    &subscription.filter,
                                    SubscriptionOptions {
                                        qos: subscription.qos,
                                        no_local: subscription.no_local,
                                        retain_as_published: subscription.retain_as_published,
                                        retain_handling: subscription.retain_handling,
                                        subscription_identifier,
                                    },
                                ) {
                                    Ok(messages) => {
                                        codes.push(subscription.qos.min(2));
                                        retained.extend(messages);
                                    }
                                    Err(_) => codes.push(if runtime.context.version == ProtocolVersion::V5 {
                                        0x8f
                                    } else {
                                        0x80
                                    }),
                                }
                            }
                            write_packet(
                                send,
                                &Packet::SubAck { packet_id, codes },
                                runtime.context.version,
                            ).await?;
                            for publish in retained {
                                runtime.broker.deliver_prepared_target(
                                    &runtime.context.client_id,
                                    runtime.target,
                                    publish,
                                );
                            }
                        }
                        Packet::Unsubscribe { packet_id, filters } => {
                            let codes = filters
                                .into_iter()
                                .map(|filter| {
                                    if runtime.broker.unsubscribe_target(
                                        &runtime.context.client_id,
                                        runtime.target,
                                        &filter,
                                    ) {
                                        0
                                    } else {
                                        0x11
                                    }
                                })
                                .collect();
                            write_packet(
                                send,
                                &Packet::UnsubAck { packet_id, codes },
                                runtime.context.version,
                            ).await?;
                        }
                        Packet::PubAck(packet_id) => {
                            runtime.broker.puback_target(
                                &runtime.context.client_id,
                                runtime.target,
                                packet_id,
                            );
                        }
                        Packet::PubRec(packet_id) => {
                            runtime.broker.pubrec_target(
                                &runtime.context.client_id,
                                runtime.target,
                                packet_id,
                            );
                        }
                        Packet::PubComp(packet_id) => {
                            runtime.broker.pubcomp_target(
                                &runtime.context.client_id,
                                runtime.target,
                                packet_id,
                            );
                        }
                        _ => bail!("packet is not valid on an MQTT QUIC data stream"),
                    }
                }
            }
            outbound = runtime.outbound_rx.recv() => {
                match outbound {
                    Some(Outbound::Packet(packet)) => {
                        write_packet(send, &packet, runtime.context.version).await?;
                    }
                    None => return Ok(()),
                }
            }
            _ = runtime.disconnect_rx.recv() => return Ok(()),
            _ = runtime.shutdown.recv() => return Ok(()),
        }
    }
}

#[derive(Clone)]
struct WebSocketState {
    broker: Broker,
    config: Config,
    authorization: Arc<AuthorizationEngine>,
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
        state.broker.clone(),
        state.authorization.clone(),
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
    let crypto_builder = if config.mqtt_quic.verify_peer {
        let ca_path = config
            .mqtt_quic
            .cacertfile
            .as_ref()
            .context("MQTT QUIC client CA file is required when verify_peer is enabled")?;
        let mut ca_reader = BufReader::new(
            File::open(ca_path)
                .with_context(|| format!("open MQTT QUIC client CA {}", ca_path.display()))?,
        );
        let mut roots = RootCertStore::empty();
        for certificate in rustls_pemfile::certs(&mut ca_reader) {
            roots
                .add(certificate.context("read MQTT QUIC client CA certificate")?)
                .context("add MQTT QUIC client CA certificate")?;
        }
        if roots.is_empty() {
            bail!("MQTT QUIC client CA file contains no certificates")
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .context("configure MQTT QUIC client certificate verification")?;
        ServerConfig::builder().with_client_cert_verifier(verifier)
    } else {
        ServerConfig::builder().with_no_client_auth()
    };
    let mut crypto = crypto_builder
        .with_single_cert(certificates, private_key)
        .context("configure MQTT QUIC certificate and private key")?;
    crypto.alpn_protocols = vec![b"mqtt".to_vec()];
    if config.mqtt_quic.enable_0rtt && !config.mqtt_quic.verify_peer {
        crypto.max_early_data_size = u32::MAX;
    }
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(crypto).context("configure MQTT QUIC TLS")?,
    ));
    server_config.migration(config.mqtt_quic.migration_enabled);
    let mut transport = TransportConfig::default();
    if config.mqtt_quic.peer_bidi_stream_count == 0 {
        bail!("MQTT QUIC peer_bidi_stream_count must be greater than zero")
    }
    transport.max_concurrent_bidi_streams(config.mqtt_quic.peer_bidi_stream_count.into());
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
    authentication_method: Option<String>,
    authorization: Arc<AuthorizationSession>,
    inbound_topic_aliases: Arc<Mutex<HashMap<u16, String>>>,
    outbound_topic_alias_maximum: u16,
    outbound_topic_aliases: HashMap<String, u16>,
}

struct PendingConnect {
    connect: Connect,
    cache: AuthCache,
    deadline: tokio::time::Instant,
}

struct ConnectRuntime<'a> {
    broker: &'a Broker,
    config: &'a Config,
    authorization: &'a Arc<AuthorizationEngine>,
    outbound: &'a mpsc::Sender<Outbound>,
    disconnect: &'a mpsc::Sender<()>,
    administrative_disconnect: &'a mpsc::Sender<AdministrativeDisconnect>,
    data_activity: &'a mpsc::Sender<()>,
    activation: Option<&'a watch::Sender<Option<QuicDataContext>>>,
}

async fn handle_connection<S>(
    stream: S,
    config: Config,
    broker: Broker,
    authorization: Arc<AuthorizationEngine>,
    shutdown: broadcast::Receiver<()>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_connection_with_activation(stream, config, broker, authorization, shutdown, None).await
}

async fn handle_connection_with_activation<S>(
    stream: S,
    config: Config,
    broker: Broker,
    authorization: Arc<AuthorizationEngine>,
    mut shutdown: broadcast::Receiver<()>,
    activation: Option<watch::Sender<Option<QuicDataContext>>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (outbound_tx, mut outbound_rx) = mpsc::channel(config.mqtt.outbound_queue.max(1));
    let (disconnect_tx, mut disconnect_rx) = mpsc::channel(1);
    let (administrative_disconnect_tx, mut administrative_disconnect_rx) = mpsc::channel(1);
    let mut buffer = BytesMut::with_capacity(8192);
    let provider: Arc<dyn AuthenticationProvider> =
        Arc::new(StaticAuthenticationProvider::new(&config.auth));
    let mut state: Option<ConnectionState> = None;
    let mut pending_connect: Option<PendingConnect> = None;
    let mut reauthentication: Option<AuthCache> = None;
    let mut normal_disconnect = false;
    let mut will_on_disconnect = false;
    let mut protocol_close = false;
    let mut administrative_disconnect = None;
    let mut qos2_pending: HashMap<u16, Publish> = HashMap::new();
    let mut qos2_complete: HashSet<u16> = HashSet::new();
    let mut last_inbound = tokio::time::Instant::now();
    let (data_activity_tx, mut data_activity_rx) = mpsc::channel(1);
    let connect_runtime = ConnectRuntime {
        broker: &broker,
        config: &config,
        authorization: &authorization,
        outbound: &outbound_tx,
        disconnect: &disconnect_tx,
        administrative_disconnect: &administrative_disconnect_tx,
        data_activity: &data_activity_tx,
        activation: activation.as_ref(),
    };
    let retry_interval = Duration::from_millis(config.mqtt.retry_interval_ms.max(1));
    let mut retry_tick = tokio::time::interval(retry_interval);
    retry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let connection_result: Result<()> = async {
        loop {
        let keepalive = state.as_ref().map_or(0, |current| current.keep_alive);
        let timeout = if keepalive == 0 {
            Duration::from_secs(24 * 60 * 60)
        } else {
            Duration::from_millis(u64::from(keepalive) * 1500)
        };
        let read_deadline = pending_connect
            .as_ref()
            .map_or(last_inbound + timeout, |pending| {
                pending.deadline.min(last_inbound + timeout)
            });
        tokio::select! {
            read = tokio::time::timeout_at(read_deadline, reader.read_buf(&mut buffer)) => {
                let bytes_read = match read {
                    Ok(result) => result.context("read MQTT socket")?,
                    Err(_) => {
                        if let Some(pending) = &pending_connect {
                            write_failed_connack(&mut writer, 0x82, pending.connect.version).await?;
                        }
                        break;
                    }
                };
                if bytes_read == 0 { break; }
                last_inbound = tokio::time::Instant::now();
                loop {
                    if pending_connect
                        .as_ref()
                        .is_some_and(|pending| pending.deadline <= tokio::time::Instant::now())
                    {
                        let version = pending_connect
                            .as_ref()
                            .expect("pending deadline checked")
                            .connect
                            .version;
                        write_failed_connack(&mut writer, 0x82, version).await?;
                        protocol_close = true;
                        break;
                    }
                    let parse_version = state.as_ref().map_or_else(
                        || pending_connect.as_ref().map_or(ProtocolVersion::V311, |pending| pending.connect.version),
                        |current| current.version,
                    );
                    let packet = match decode_packet(
                        &mut buffer,
                        parse_version,
                        config.mqtt.max_packet_size,
                    ) {
                        Ok(Some(packet)) => packet,
                        Ok(None) => break,
                        Err(error) => {
                            if let Some(pending) = &pending_connect {
                                write_failed_connack(&mut writer, 0x82, pending.connect.version)
                                    .await?;
                                protocol_close = true;
                                tracing::debug!(%error, "invalid MQTT packet during authentication");
                                break;
                            }
                            if let Some(current) = &state {
                                write_protocol_disconnect(&mut writer, current.version, 0x82)
                                    .await?;
                                protocol_close = true;
                                tracing::debug!(%error, "invalid MQTT packet after CONNECT");
                                break;
                            }
                            return Err(error);
                        }
                    };
                    match packet {
                        Packet::Connect(connect)
                            if state.is_none() && pending_connect.is_none() =>
                        {
                            if let Some(method) = connect.authentication_method.clone() {
                                match provider.start(AuthCredential {
                                    method: &method,
                                    data: connect.authentication_data.as_deref(),
                                }) {
                                    AuthOutcome::Continue {
                                        cache,
                                        authentication_data,
                                    } => {
                                        write_auth(
                                            &mut writer,
                                            0x18,
                                            cache.method(),
                                            authentication_data,
                                        )
                                        .await?;
                                        let deadline = tokio::time::Instant::now()
                                            + Duration::from_millis(config.auth.timeout_ms);
                                        pending_connect = Some(PendingConnect {
                                            connect,
                                            cache,
                                            deadline,
                                        });
                                    }
                                    AuthOutcome::Success {
                                        principal,
                                        authentication_data,
                                    } => {
                                        state = Some(
                                            complete_connect(
                                                &mut writer,
                                                &connect_runtime,
                                                connect,
                                                Some(principal),
                                                authentication_data,
                                            )
                                            .await?,
                                        );
                                    }
                                    AuthOutcome::Error { reason_code } => {
                                        write_failed_connack(
                                            &mut writer,
                                            reason_code,
                                            connect.version,
                                        )
                                        .await?;
                                        normal_disconnect = true;
                                        break;
                                    }
                                }
                            } else {
                                match provider.authenticate_standard(
                                    connect.username.as_deref(),
                                    connect.password.as_deref(),
                                ) {
                                    Ok(principal) => {
                                        state = Some(
                                            complete_connect(
                                                &mut writer,
                                                &connect_runtime,
                                                connect,
                                                principal,
                                                None,
                                            )
                                            .await?,
                                        );
                                    }
                                    Err(reason_code) => {
                                        let code = if connect.version == ProtocolVersion::V5 {
                                            reason_code
                                        } else {
                                            4
                                        };
                                        write_failed_connack(&mut writer, code, connect.version)
                                            .await?;
                                        normal_disconnect = true;
                                        break;
                                    }
                                }
                            }
                        }
                        Packet::Auth(auth) if pending_connect.is_some() => {
                            let pending = pending_connect.take().expect("pending checked");
                            if auth.reason_code != 0x18 {
                                write_failed_connack(
                                    &mut writer,
                                    0x82,
                                    pending.connect.version,
                                )
                                .await?;
                                normal_disconnect = true;
                                break;
                            }
                            let Some(method) = auth.authentication_method.as_deref() else {
                                write_failed_connack(
                                    &mut writer,
                                    0x82,
                                    pending.connect.version,
                                )
                                .await?;
                                protocol_close = true;
                                break;
                            };
                            if method != pending.cache.method() {
                                write_failed_connack(
                                    &mut writer,
                                    BAD_AUTHENTICATION_METHOD,
                                    pending.connect.version,
                                )
                                .await?;
                                protocol_close = true;
                                break;
                            }
                            match provider.next(
                                pending.cache,
                                AuthCredential {
                                    method,
                                    data: auth.authentication_data.as_deref(),
                                },
                            ) {
                                AuthOutcome::Continue {
                                    cache,
                                    authentication_data,
                                } => {
                                    write_auth(
                                        &mut writer,
                                        0x18,
                                        cache.method(),
                                        authentication_data,
                                    )
                                    .await?;
                                    pending_connect = Some(PendingConnect {
                                        connect: pending.connect,
                                        cache,
                                        deadline: pending.deadline,
                                    });
                                }
                                AuthOutcome::Success {
                                    principal,
                                    authentication_data,
                                } => {
                                    state = Some(
                                        complete_connect(
                                            &mut writer,
                                            &connect_runtime,
                                            pending.connect,
                                            Some(principal),
                                            authentication_data,
                                        )
                                        .await?,
                                    );
                                }
                                AuthOutcome::Error { reason_code } => {
                                    write_failed_connack(
                                        &mut writer,
                                        reason_code,
                                        pending.connect.version,
                                    )
                                    .await?;
                                    normal_disconnect = true;
                                    break;
                                }
                            }
                        }
                        Packet::Auth(auth) if state.is_some() => {
                            let current = state.as_mut().expect("state checked");
                            let outcome = if let Some(cache) = reauthentication.take() {
                                if auth.reason_code != 0x18 {
                                    write_protocol_disconnect(&mut writer, current.version, 0x82)
                                        .await?;
                                    protocol_close = true;
                                    break;
                                }
                                match auth.authentication_method.as_deref() {
                                    None => AuthOutcome::Error { reason_code: 0x82 },
                                    Some(method) if method != cache.method() => {
                                        AuthOutcome::Error {
                                            reason_code: BAD_AUTHENTICATION_METHOD,
                                        }
                                    }
                                    Some(method) => provider.next(
                                        cache,
                                        AuthCredential {
                                            method,
                                            data: auth.authentication_data.as_deref(),
                                        },
                                    ),
                                }
                            } else {
                                if auth.reason_code != 0x19 {
                                    write_protocol_disconnect(&mut writer, current.version, 0x82)
                                        .await?;
                                    protocol_close = true;
                                    break;
                                }
                                let Some(expected_method) =
                                    current.authentication_method.as_deref()
                                else {
                                    write_protocol_disconnect(
                                        &mut writer,
                                        current.version,
                                        BAD_AUTHENTICATION_METHOD,
                                    )
                                    .await?;
                                    protocol_close = true;
                                    break;
                                };
                                match auth.authentication_method.as_deref() {
                                    None => AuthOutcome::Error { reason_code: 0x82 },
                                    Some(method) if method != expected_method => {
                                        AuthOutcome::Error {
                                            reason_code: BAD_AUTHENTICATION_METHOD,
                                        }
                                    }
                                    Some(method) => provider.start(AuthCredential {
                                        method,
                                        data: auth.authentication_data.as_deref(),
                                    }),
                                }
                            };
                            match outcome {
                                AuthOutcome::Continue {
                                    cache,
                                    authentication_data,
                                } => {
                                    write_auth(
                                        &mut writer,
                                        0x18,
                                        cache.method(),
                                        authentication_data,
                                    )
                                    .await?;
                                    reauthentication = Some(cache);
                                }
                                AuthOutcome::Success {
                                    principal,
                                    authentication_data,
                                } => {
                                    if current.authorization.context().principal.as_deref()
                                        != Some(principal.as_str())
                                    {
                                        write_protocol_disconnect(
                                            &mut writer,
                                            current.version,
                                            0x87,
                                        )
                                        .await?;
                                        protocol_close = true;
                                        break;
                                    }
                                    write_auth_success(
                                        &mut writer,
                                        current
                                            .authentication_method
                                            .as_deref()
                                            .expect("reauthentication method checked"),
                                        authentication_data,
                                    )
                                    .await?;
                                }
                                AuthOutcome::Error { reason_code } => {
                                    write_protocol_disconnect(
                                        &mut writer,
                                        current.version,
                                        reason_code,
                                    )
                                    .await?;
                                    protocol_close = true;
                                    break;
                                }
                            }
                        }
                        Packet::Connect(_) if state.is_some() => {
                            let version = state.as_ref().expect("state checked").version;
                            write_protocol_disconnect(&mut writer, version, 0x82).await?;
                            protocol_close = true;
                            break;
                        }
                        Packet::Connect(_) => {
                            let version = pending_connect
                                .as_ref()
                                .map_or(ProtocolVersion::V5, |pending| pending.connect.version);
                            write_failed_connack(&mut writer, 0x82, version).await?;
                            normal_disconnect = true;
                            break;
                        }
                        _ if pending_connect.is_some() => {
                            let version = pending_connect
                                .as_ref()
                                .expect("pending checked")
                                .connect
                                .version;
                            write_failed_connack(&mut writer, 0x82, version).await?;
                            normal_disconnect = true;
                            break;
                        }
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
                            if current.authorization.deny_action() == DenyAction::Disconnect {
                                let mut denied = false;
                                for subscription in &filters {
                                    if current
                                        .authorization
                                        .authorize_subscribe(
                                            &subscription.filter,
                                            subscription.qos,
                                        )
                                        == SubscriptionAuthorization::Deny
                                    {
                                        denied = true;
                                        break;
                                    }
                                }
                                if denied {
                                    write_protocol_disconnect(
                                        &mut writer,
                                        current.version,
                                        0x87,
                                    )
                                    .await?;
                                    protocol_close = true;
                                    break;
                                }
                            }
                            let mut codes = Vec::with_capacity(filters.len());
                            let mut retained = Vec::new();
                            for subscription in filters {
                                if let Some(code) = subscription_failure_code(
                                    current.authorization.authorize_subscribe(
                                        &subscription.filter,
                                        subscription.qos,
                                    ),
                                    current.version,
                                ) {
                                    codes.push(code);
                                    continue;
                                }
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
                                    Ok(messages) => {
                                        codes.push(subscription.qos.min(2));
                                        retained.extend(messages);
                                    }
                                    Err(_) => codes.push(if current.version == ProtocolVersion::V5 {
                                        0x8f
                                    } else {
                                        0x80
                                    }),
                                }
                            }
                            write_packet(
                                &mut writer,
                                &Packet::SubAck { packet_id, codes },
                                current.version,
                            )
                            .await?;
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
                                &state.as_ref().expect("state checked").inbound_topic_aliases,
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
                            if !current
                                .authorization
                                .authorize_publish(&publish.topic, publish.qos, publish.retain)
                                .is_allowed()
                            {
                                if write_publish_denied(
                                    &mut writer,
                                    current.version,
                                    publish.qos,
                                    packet_id,
                                    current.authorization.deny_action(),
                                )
                                .await?
                                {
                                    protocol_close = true;
                                    break;
                                }
                                continue;
                            }
                            broker.publish_from(Some(&current.client_id), publish);
                            if let Some(id) = packet_id {
                                write_packet(&mut writer, &Packet::PubAck(id), current.version).await?;
                            }
                        }
                        Packet::Publish(mut publish) => {
                            let alias_result = resolve_topic_alias(
                                &mut publish,
                                &state.as_ref().expect("state checked").inbound_topic_aliases,
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
                            if !current
                                .authorization
                                .authorize_publish(&publish.topic, publish.qos, publish.retain)
                                .is_allowed()
                            {
                                if write_publish_denied(
                                    &mut writer,
                                    current.version,
                                    publish.qos,
                                    Some(id),
                                    current.authorization.deny_action(),
                                )
                                .await?
                                {
                                    protocol_close = true;
                                    break;
                                }
                                continue;
                            }
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
                            will_on_disconnect = reason_code == 0x04;
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
            admin = administrative_disconnect_rx.recv(), if state.is_some() => {
                if let Some(command) = admin {
                    let current = state.as_ref().expect("state checked");
                    administrative_disconnect = Some(command);
                    if current.version == ProtocolVersion::V5 {
                        let _ = write_protocol_disconnect(&mut writer, current.version, 0x98).await;
                    }
                    break;
                }
            }
            _ = disconnect_rx.recv() => break,
            _ = retry_tick.tick(), if state.is_some() => {
                let current = state.as_ref().expect("state checked");
                broker.retry_due(&current.client_id, retry_interval);
            }
            activity = data_activity_rx.recv(), if state.is_some() => {
                if activity.is_some() {
                    last_inbound = tokio::time::Instant::now();
                }
            }
            _ = shutdown.recv() => break,
        }
        }
        Ok(())
    }
    .await;

    if let Some(current) = state {
        let is_administrative = administrative_disconnect.is_some();
        broker.finalize_connection(
            &current.client_id,
            current.token,
            is_administrative || !normal_disconnect || will_on_disconnect,
            is_administrative || will_on_disconnect,
            is_administrative,
        );
    }
    if let Some(command) = administrative_disconnect {
        command.complete();
    }
    connection_result
}

fn subscription_failure_code(
    authorization: SubscriptionAuthorization,
    version: ProtocolVersion,
) -> Option<u8> {
    match authorization {
        SubscriptionAuthorization::Allow => None,
        SubscriptionAuthorization::Deny => Some(if version == ProtocolVersion::V5 {
            0x87
        } else {
            0x80
        }),
        SubscriptionAuthorization::InvalidFilter => Some(if version == ProtocolVersion::V5 {
            0x8f
        } else {
            0x80
        }),
    }
}

async fn write_publish_denied<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    version: ProtocolVersion,
    qos: u8,
    packet_id: Option<u16>,
    deny_action: DenyAction,
) -> Result<bool> {
    if deny_action == DenyAction::Disconnect {
        write_protocol_disconnect(writer, version, 0x87).await?;
        return Ok(true);
    }
    match (qos, packet_id) {
        (0, _) => {}
        (1, Some(packet_id)) => {
            let packet = if version == ProtocolVersion::V5 {
                Packet::PubAckReason {
                    packet_id,
                    reason_code: 0x87,
                }
            } else {
                Packet::PubAck(packet_id)
            };
            write_packet(writer, &packet, version).await?;
        }
        (2, Some(packet_id)) => {
            let packet = if version == ProtocolVersion::V5 {
                Packet::PubRecReason {
                    packet_id,
                    reason_code: 0x87,
                }
            } else {
                Packet::PubRec(packet_id)
            };
            write_packet(writer, &packet, version).await?;
        }
        _ => bail!("QoS publish missing packet identifier"),
    }
    Ok(false)
}

fn resolve_topic_alias(
    publish: &mut Publish,
    inbound_topic_aliases: &Mutex<HashMap<u16, String>>,
    maximum: u16,
) -> std::result::Result<(), u8> {
    let mut inbound_topic_aliases = inbound_topic_aliases
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match (publish.topic.is_empty(), publish.topic_alias) {
        (false, Some(alias)) => {
            if alias > maximum {
                return Err(0x94);
            }
            inbound_topic_aliases.insert(alias, publish.topic.clone());
        }
        (true, Some(alias)) => {
            if alias > maximum {
                return Err(0x94);
            }
            publish.topic = inbound_topic_aliases.get(&alias).cloned().ok_or(0x82)?;
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

async fn complete_connect<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    runtime: &ConnectRuntime<'_>,
    mut connect: Connect,
    principal: Option<String>,
    authentication_data: Option<bytes::Bytes>,
) -> Result<ConnectionState> {
    let authorization = runtime
        .authorization
        .session(principal, connect.client_id.clone());
    if connect.will.as_ref().is_some_and(|will| {
        !authorization
            .authorize_publish(&will.topic, will.qos, will.retain)
            .is_allowed()
    }) {
        match authorization.deny_action() {
            DenyAction::Ignore => connect.will = None,
            DenyAction::Disconnect => {
                let code = if connect.version == ProtocolVersion::V5 {
                    0x87
                } else {
                    5
                };
                write_failed_connack(writer, code, connect.version).await?;
                bail!("Will publish is not authorized");
            }
        }
    }
    let (token, present) = runtime.broker.register_authorized_with_admin(
        &connect.client_id,
        authorization.context().principal.as_deref(),
        ConnectionOptions {
            clean_start: connect.clean_start,
            expiry_interval: connect.session_expiry_interval,
            receive_maximum: connect.receive_maximum,
            will: connect.will.clone(),
        },
        runtime.outbound.clone(),
        runtime.disconnect.clone(),
        runtime.administrative_disconnect.clone(),
    );
    let inbound_topic_aliases = Arc::new(Mutex::new(HashMap::new()));
    let data_context = QuicDataContext {
        client_id: connect.client_id.clone(),
        connection: token,
        version: connect.version,
        authorization: authorization.clone(),
        inbound_topic_aliases: inbound_topic_aliases.clone(),
        activity: runtime.data_activity.clone(),
    };
    let authentication_method = connect.authentication_method.clone();
    let state = ConnectionState {
        client_id: connect.client_id,
        token,
        version: connect.version,
        session_expiry_interval: connect.session_expiry_interval,
        keep_alive: connect.keep_alive,
        authentication_method: connect.authentication_method,
        authorization,
        inbound_topic_aliases,
        outbound_topic_alias_maximum: connect.topic_alias_maximum,
        outbound_topic_aliases: HashMap::new(),
    };
    let connack = Packet::ConnAck {
        session_present: present,
        code: 0,
        topic_alias_maximum: (state.version == ProtocolVersion::V5)
            .then_some(runtime.config.mqtt.max_topic_alias),
        authentication_method,
        authentication_data,
    };
    if let Err(error) = write_packet(writer, &connack, state.version).await {
        runtime.broker.unregister(&state.client_id, state.token);
        return Err(error);
    }
    if let Some(activation) = runtime.activation {
        activation.send_replace(Some(data_context));
    }
    Ok(state)
}

async fn write_failed_connack<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    reason_code: u8,
    version: ProtocolVersion,
) -> Result<()> {
    write_packet(
        writer,
        &Packet::ConnAck {
            session_present: false,
            code: reason_code,
            topic_alias_maximum: None,
            authentication_method: None,
            authentication_data: None,
        },
        version,
    )
    .await
}

async fn write_auth<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    reason_code: u8,
    method: &str,
    authentication_data: Option<bytes::Bytes>,
) -> Result<()> {
    write_packet(
        writer,
        &Packet::Auth(Auth {
            reason_code,
            authentication_method: Some(method.to_owned()),
            authentication_data,
        }),
        ProtocolVersion::V5,
    )
    .await
}

async fn write_auth_success<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    method: &str,
    authentication_data: Option<bytes::Bytes>,
) -> Result<()> {
    write_packet(
        writer,
        &Packet::Auth(Auth {
            reason_code: 0,
            authentication_method: Some(method.to_owned()),
            authentication_data,
        }),
        ProtocolVersion::V5,
    )
    .await
}

async fn write_protocol_disconnect<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    version: ProtocolVersion,
    reason_code: u8,
) -> Result<()> {
    if version == ProtocolVersion::V5 {
        write_packet(
            writer,
            &Packet::Disconnect {
                reason_code,
                session_expiry_interval: None,
            },
            version,
        )
        .await?;
    }
    Ok(())
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
