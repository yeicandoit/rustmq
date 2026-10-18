use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::authorization::{AuthorizationConfig, DenyAction, NoMatch};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub mqtt: MqttConfig,
    pub mqtt_tls: MqttTlsConfig,
    pub mqtt_ws: MqttWsConfig,
    pub mqtt_quic: MqttQuicConfig,
    pub http: HttpConfig,
    pub management: ManagementConfig,
    pub auth: AuthConfig,
    pub authorization: AuthorizationConfig,
    pub persistence: PersistenceConfig,
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
    pub verify_peer: bool,
    pub cacertfile: Option<PathBuf>,
    pub enable_0rtt: bool,
    pub migration_enabled: bool,
    pub peer_bidi_stream_count: u16,
    pub idle_timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct HttpConfig {
    pub bind: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ManagementConfig {
    pub enabled: bool,
    pub api_key: Option<String>,
    pub api_secret: Option<String>,
    pub max_page_limit: usize,
    pub max_body_bytes: usize,
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: None,
            api_secret: None,
            max_page_limit: 10_000,
            max_body_bytes: 1024 * 1024,
        }
    }
}

impl fmt::Debug for ManagementConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagementConfig")
            .field("enabled", &self.enabled)
            .field("api_key_configured", &self.api_key.is_some())
            .field("api_secret_configured", &self.api_secret.is_some())
            .field("max_page_limit", &self.max_page_limit)
            .field("max_body_bytes", &self.max_body_bytes)
            .finish()
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AuthConfig {
    pub username: Option<String>,
    pub password: Option<String>,
    pub timeout_ms: u64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            username: None,
            password: None,
            timeout_ms: 15_000,
        }
    }
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthConfig")
            .field("username_configured", &self.username.is_some())
            .field("password_configured", &self.password.is_some())
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct PersistenceConfig {
    pub enabled: bool,
    pub path: PathBuf,
    pub sync: bool,
    pub writer_queue_capacity: usize,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: PathBuf::from("data/rustmq.redb"),
            sync: true,
            writer_queue_capacity: 1024,
        }
    }
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
            verify_peer: false,
            cacertfile: None,
            enable_0rtt: true,
            migration_enabled: true,
            peer_bidi_stream_count: 10,
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
        if let Ok(value) = std::env::var("RUSTMQ_MANAGEMENT_ENABLED") {
            config.management.enabled = value.parse().context("RUSTMQ_MANAGEMENT_ENABLED")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_MANAGEMENT_API_KEY") {
            config.management.api_key = Some(value);
        }
        if let Ok(value) = std::env::var("RUSTMQ_MANAGEMENT_API_SECRET") {
            config.management.api_secret = Some(value);
        }
        if let Ok(value) = std::env::var("RUSTMQ_MANAGEMENT_MAX_PAGE_LIMIT") {
            config.management.max_page_limit =
                value.parse().context("RUSTMQ_MANAGEMENT_MAX_PAGE_LIMIT")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_MANAGEMENT_MAX_BODY_BYTES") {
            config.management.max_body_bytes =
                value.parse().context("RUSTMQ_MANAGEMENT_MAX_BODY_BYTES")?;
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
        if let Ok(value) = std::env::var("RUSTMQ_MQTT_QUIC_VERIFY_PEER") {
            config.mqtt_quic.verify_peer = value.parse().context("RUSTMQ_MQTT_QUIC_VERIFY_PEER")?;
        }
        if let Some(value) = std::env::var_os("RUSTMQ_MQTT_QUIC_CACERTFILE") {
            config.mqtt_quic.cacertfile = Some(PathBuf::from(value));
        }
        if let Ok(value) = std::env::var("RUSTMQ_MQTT_QUIC_ENABLE_0RTT") {
            config.mqtt_quic.enable_0rtt = value.parse().context("RUSTMQ_MQTT_QUIC_ENABLE_0RTT")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_MQTT_QUIC_MIGRATION_ENABLED") {
            config.mqtt_quic.migration_enabled = value
                .parse()
                .context("RUSTMQ_MQTT_QUIC_MIGRATION_ENABLED")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_MQTT_QUIC_PEER_BIDI_STREAM_COUNT") {
            config.mqtt_quic.peer_bidi_stream_count = value
                .parse()
                .context("RUSTMQ_MQTT_QUIC_PEER_BIDI_STREAM_COUNT")?;
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
        if let Ok(value) = std::env::var("RUSTMQ_AUTH_TIMEOUT_MS") {
            config.auth.timeout_ms = value.parse().context("RUSTMQ_AUTH_TIMEOUT_MS")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_AUTHZ_NO_MATCH") {
            config.authorization.no_match =
                value.parse::<NoMatch>().context("RUSTMQ_AUTHZ_NO_MATCH")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_AUTHZ_DENY_ACTION") {
            config.authorization.deny_action = value
                .parse::<DenyAction>()
                .context("RUSTMQ_AUTHZ_DENY_ACTION")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_AUTHZ_CACHE_CAPACITY") {
            config.authorization.cache_capacity =
                value.parse().context("RUSTMQ_AUTHZ_CACHE_CAPACITY")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_PERSISTENCE_ENABLED") {
            config.persistence.enabled = value.parse().context("RUSTMQ_PERSISTENCE_ENABLED")?;
        }
        if let Some(value) = std::env::var_os("RUSTMQ_PERSISTENCE_PATH") {
            config.persistence.path = PathBuf::from(value);
        }
        if let Ok(value) = std::env::var("RUSTMQ_PERSISTENCE_SYNC") {
            config.persistence.sync = value.parse().context("RUSTMQ_PERSISTENCE_SYNC")?;
        }
        if let Ok(value) = std::env::var("RUSTMQ_PERSISTENCE_WRITER_QUEUE_CAPACITY") {
            config.persistence.writer_queue_capacity = value
                .parse()
                .context("RUSTMQ_PERSISTENCE_WRITER_QUEUE_CAPACITY")?;
        }
        if config.persistence.path.as_os_str().is_empty() {
            anyhow::bail!("persistence path must not be empty");
        }
        if config.persistence.writer_queue_capacity == 0 {
            anyhow::bail!("persistence writer_queue_capacity must be greater than zero");
        }
        if let Ok(value) = std::env::var("RUSTMQ_NODE_ID") {
            config.node.id = value;
        }
        config.validate_management()?;
        Ok(config)
    }

    pub fn validate_management(&self) -> Result<()> {
        if !self.management.enabled {
            return Ok(());
        }
        if self.management.max_page_limit == 0 {
            anyhow::bail!("management max_page_limit must be greater than zero");
        }
        if self.management.max_body_bytes == 0 {
            anyhow::bail!("management max_body_bytes must be greater than zero");
        }
        let (Some(api_key), Some(api_secret)) = (
            self.management.api_key.as_deref(),
            self.management.api_secret.as_deref(),
        ) else {
            anyhow::bail!("management api_key and api_secret are required when enabled");
        };
        if api_key.is_empty() || api_secret.is_empty() {
            anyhow::bail!("management api_key and api_secret must not be empty");
        }
        if api_key.len() > 1024 || api_secret.len() > 1024 {
            anyhow::bail!("management api_key and api_secret must not exceed 1024 bytes");
        }
        Ok(())
    }
}
