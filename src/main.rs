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

use std::{env, error::Error, io, net::SocketAddr, sync::Arc};

use axolotl::{AppConfig, Metrics, build_app, reporter::DiscordReporter};
use tokio::{net::TcpListener, signal};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let dotenv = dotenvy::dotenv();
    init_tracing()?;
    if let Err(error) = dotenv
        && !error.not_found()
    {
        warn!(%error, "Failed to load .env");
    }

    let config = AppConfig::from_env()?;
    for warning in config.startup_warnings() {
        warn!("{warning}");
    }
    let port = config.port();
    let metrics = Arc::new(Metrics::default());
    let app = build_app(&config, Arc::clone(&metrics))?;
    let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?;
    // Log the bound address so `PORT=0` shows the port the OS picked.
    let address = listener.local_addr()?;
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
    let (filter, invalid_filter) = match EnvFilter::try_from_default_env() {
        Ok(filter) => (filter, None),
        Err(error) => (
            EnvFilter::new("axolotl=info,tower_http=info"),
            env::var_os(EnvFilter::DEFAULT_ENV).map(|_| error),
        ),
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()?;
    if let Some(error) = invalid_filter {
        warn!(%error, "RUST_LOG is invalid, using the default log filter");
    }
    Ok(())
}

async fn shutdown_signal() {
    tokio::select! {
        () = wait_for_signal("Ctrl+C", signal::ctrl_c()) => {}
        () = wait_for_signal("SIGTERM", terminate_signal()) => {}
    }
    info!("Shutdown signal received");
}

/// Waits for a shutdown signal. If the listener fails, it logs the error and
/// never completes, so the other signal can still stop the server.
async fn wait_for_signal(name: &'static str, signal: impl Future<Output = io::Result<()>>) {
    if let Err(error) = signal.await {
        error!(%error, signal = name, "Failed to listen for a shutdown signal");
        std::future::pending::<()>().await;
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

#[cfg(test)]
mod tests {
    use std::{io, time::Duration};

    use tokio::time::timeout;

    use super::wait_for_signal;

    #[tokio::test]
    async fn completes_when_the_signal_arrives() {
        let result = timeout(
            Duration::from_secs(1),
            wait_for_signal("test", async { Ok(()) }),
        )
        .await;
        assert!(result.is_ok(), "a received signal should start shutdown");
    }

    #[tokio::test]
    async fn keeps_waiting_when_the_signal_listener_fails() {
        let failing = async { Err(io::Error::other("registration failed")) };
        let result = timeout(Duration::from_millis(50), wait_for_signal("test", failing)).await;
        assert!(result.is_err(), "a failed listener must not start shutdown");
    }
}
