use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use rustmq::{broker::Broker, config::Config, server::spawn};
use tokio::sync::Notify;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "rustmq=info".into()))
        .init();

    let config_path = config_path();
    let config = Config::load(&config_path)
        .with_context(|| format!("load configuration {}", config_path.display()))?;
    let broker = Broker::open(&config).context("open and recover broker state")?;
    let running = spawn(config, broker).await?;
    tracing::info!(
        mqtt = %running.mqtt_addr,
        mqtt_tls = ?running.mqtt_tls_addr,
        mqtt_ws = ?running.mqtt_ws_addr,
        mqtt_quic = ?running.mqtt_quic_addr,
        http = %running.http_addr,
        "RustMQ started"
    );

    let signal_result = wait_for_shutdown().await;
    tracing::info!("RustMQ shutting down");
    let shutdown_result = running.shutdown().await;
    signal_result?;
    shutdown_result
}

fn config_path() -> PathBuf {
    let mut arguments = std::env::args_os().skip(1);
    let mut path = std::env::var_os("RUSTMQ_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config/rustmq.toml"));
    while let Some(argument) = arguments.next() {
        if argument == "--config" {
            if let Some(value) = arguments.next() {
                path = PathBuf::from(value);
            }
        }
    }
    path
}

async fn wait_for_shutdown() -> Result<()> {
    let signal = Arc::new(Notify::new());
    let unix_signal = Arc::clone(&signal);
    #[cfg(unix)]
    tokio::spawn(async move {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            terminate.recv().await;
            unix_signal.notify_one();
        }
    });
    #[cfg(not(unix))]
    drop(unix_signal);

    tokio::select! {
        result = tokio::signal::ctrl_c() => result.context("install Ctrl-C handler"),
        () = signal.notified() => Ok(()),
    }
}
