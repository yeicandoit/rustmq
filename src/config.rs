use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub mqtt: MqttConfig,
    pub mqtt_tls: MqttTlsConfig,
    pub mqtt_ws: MqttWsConfig,
    pub mqtt_quic: MqttQuicConfig,
    pub http: HttpConfig,
    pub auth: AuthConfig,
    pub node: NodeConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct MqttConfig {
    pub bind: String,
    pub max_packet_size: usize,
    pub max_topic_alias: u16,
    pub outbound_queue: usize,
    pub inflight_limit: usize,
    pub offline_queue_limit: usize,
    pub retry_interval_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct MqttTlsConfig {
    pub enabled: bool,
    pub bind: String,
    pub certfile: Option<PathBuf>,
    pub keyfile: Option<PathBuf>,
    pub verify_peer: bool,
    pub cacertfile: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct MqttWsConfig {
    pub enabled: bool,
    pub bind: String,
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct MqttQuicConfig {
    pub enabled: bool,
    pub bind: String,
    pub certfile: Option<PathBuf>,
    pub keyfile: Option<PathBuf>,
    pub idle_timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct HttpConfig {
    pub bind: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct AuthConfig {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct NodeConfig {
    pub id: String,
}

impl Default for MqttConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:1883".to_owned(),
            max_packet_size: 1024 * 1024,
            max_topic_alias: u16::MAX,
            outbound_queue: 1024,
            inflight_limit: 32,
            offline_queue_limit: 1024,
            retry_interval_ms: 30_000,
        }
    }
}

impl Default for MqttTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "0.0.0.0:8883".to_owned(),
            certfile: None,
            keyfile: None,
            verify_peer: false,
            cacertfile: None,
        }
    }
}

impl Default for MqttWsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "0.0.0.0:8083".to_owned(),
            path: "/mqtt".to_owned(),
        }
    }
}

impl Default for MqttQuicConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "0.0.0.0:14567".to_owned(),
            certfile: None,
            keyfile: None,
            idle_timeout_ms: 15_000,
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:18083".to_owned(),
        }
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            id: "rustmq@localhost".to_owned(),
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let mut config = if path.exists() {
            let content = fs::read_to_string(path)
                .with_context(|| format!("read config {}", path.display()))?;
            toml::from_str(&content).context("parse TOML config")?
        } else {
            Self::default()
        };
        if let Ok(value) = std::env::var("RUSTMQ_MQTT_BIND") {
            config.mqtt.bind = value;
        }
        if let Ok(value) = std::env::var("RUSTMQ_HTTP_BIND") {
            config.http.bind = value;
        }
        if let Ok(value) = std::env::var("RUSTMQ_MQTT_TLS_ENABLED") {
            config.mqtt_tls.enabled = value.parse().context("RUSTMQ_MQTT_TLS_ENABLED")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_MQTT_TLS_BIND") {
            config.mqtt_tls.bind = value;
        }
        if let Some(value) = std::env::var_os("RUSTMQ_MQTT_TLS_CERTFILE") {
            config.mqtt_tls.certfile = Some(PathBuf::from(value));
        }
        if let Some(value) = std::env::var_os("RUSTMQ_MQTT_TLS_KEYFILE") {
            config.mqtt_tls.keyfile = Some(PathBuf::from(value));
        }
        if let Ok(value) = std::env::var("RUSTMQ_MQTT_TLS_VERIFY_PEER") {
            config.mqtt_tls.verify_peer = value.parse().context("RUSTMQ_MQTT_TLS_VERIFY_PEER")?;
        }
        if let Some(value) = std::env::var_os("RUSTMQ_MQTT_TLS_CACERTFILE") {
            config.mqtt_tls.cacertfile = Some(PathBuf::from(value));
        }
        if let Ok(value) = std::env::var("RUSTMQ_MQTT_WS_ENABLED") {
            config.mqtt_ws.enabled = value.parse().context("RUSTMQ_MQTT_WS_ENABLED")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_MQTT_WS_BIND") {
            config.mqtt_ws.bind = value;
        }
        if let Ok(value) = std::env::var("RUSTMQ_MQTT_WS_PATH") {
            config.mqtt_ws.path = value;
        }
        if let Ok(value) = std::env::var("RUSTMQ_MQTT_QUIC_ENABLED") {
            config.mqtt_quic.enabled = value.parse().context("RUSTMQ_MQTT_QUIC_ENABLED")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_MQTT_QUIC_BIND") {
            config.mqtt_quic.bind = value;
        }
        if let Some(value) = std::env::var_os("RUSTMQ_MQTT_QUIC_CERTFILE") {
            config.mqtt_quic.certfile = Some(PathBuf::from(value));
        }
        if let Some(value) = std::env::var_os("RUSTMQ_MQTT_QUIC_KEYFILE") {
            config.mqtt_quic.keyfile = Some(PathBuf::from(value));
        }
        if let Ok(value) = std::env::var("RUSTMQ_MQTT_QUIC_IDLE_TIMEOUT_MS") {
            config.mqtt_quic.idle_timeout_ms =
                value.parse().context("RUSTMQ_MQTT_QUIC_IDLE_TIMEOUT_MS")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_MAX_PACKET_SIZE") {
            config.mqtt.max_packet_size = value.parse().context("RUSTMQ_MAX_PACKET_SIZE")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_MAX_TOPIC_ALIAS") {
            config.mqtt.max_topic_alias = value.parse().context("RUSTMQ_MAX_TOPIC_ALIAS")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_INFLIGHT_LIMIT") {
            config.mqtt.inflight_limit = value.parse().context("RUSTMQ_INFLIGHT_LIMIT")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_OFFLINE_QUEUE_LIMIT") {
            config.mqtt.offline_queue_limit =
                value.parse().context("RUSTMQ_OFFLINE_QUEUE_LIMIT")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_RETRY_INTERVAL_MS") {
            config.mqtt.retry_interval_ms = value.parse().context("RUSTMQ_RETRY_INTERVAL_MS")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_USERNAME") {
            config.auth.username = Some(value);
        }
        if let Ok(value) = std::env::var("RUSTMQ_PASSWORD") {
            config.auth.password = Some(value);
        }
        if let Ok(value) = std::env::var("RUSTMQ_NODE_ID") {
            config.node.id = value;
        }
        Ok(config)
    }
}
