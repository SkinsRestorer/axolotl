#![cfg_attr(
    not(test),
    deny(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::unwrap_used
    )
)]

use std::{error::Error, io, net::SocketAddr, sync::Arc};

use axolotl::{AppConfig, Metrics, build_app, reporter::DiscordReporter};
use tokio::{net::TcpListener, signal};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    dotenvy::dotenv().ok();
    init_tracing()?;

    let config = AppConfig::from_env()?;
    let port = config.port();
    let address = SocketAddr::from(([0, 0, 0, 0], port));
    let metrics = Arc::new(Metrics::default());
    let app = build_app(&config, Arc::clone(&metrics))?;
    let listener = TcpListener::bind(address).await?;
    let reporter = DiscordReporter::start(config.discord_webhook().cloned(), metrics);
    drop(config);

    info!(%address, "Axolotl server started");
    info!(
        url = %format!("http://{address}/swagger"),
        "API documentation available"
    );

    let server_result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await;
    reporter.shutdown().await;
    server_result?;

    Ok(())
}

fn init_tracing() -> Result<(), Box<dyn Error + Send + Sync>> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("axolotl=info,tower_http=info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()?;
    Ok(())
}

async fn shutdown_signal() {
    let result = tokio::select! {
        result = signal::ctrl_c() => result,
        result = terminate_signal() => result,
    };

    match result {
        Ok(()) => info!("Shutdown signal received"),
        Err(error) => error!(%error, "Failed to listen for a shutdown signal"),
    }
}

#[cfg(unix)]
async fn terminate_signal() -> io::Result<()> {
    let mut terminate = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    terminate
        .recv()
        .await
        .ok_or_else(|| io::Error::other("SIGTERM signal stream ended"))
}

#[cfg(not(unix))]
async fn terminate_signal() -> io::Result<()> {
    std::future::pending().await
}
