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

use std::{
    env,
    error::Error,
    io::{self, IsTerminal},
    net::SocketAddr,
    process::ExitCode,
    sync::Arc,
};

use axolotl::{AppConfig, BUILD_COMMIT, Metrics, build_app, reporter::DiscordReporter};
use tokio::{net::TcpListener, signal};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Returning the error from `main` would print its `Debug` form,
            // which hides the messages written for operators.
            eprintln!("Error: {}", error_chain(&*error));
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn Error + Send + Sync>> {
    let dotenv = dotenvy::dotenv();
    init_tracing()?;
    if let Err(error) = dotenv
        && !error.not_found()
    {
        warn!(error = %dotenv_error_message(&error), "Failed to load .env");
    }

    let config = AppConfig::from_env()?;
    for warning in config.startup_warnings() {
        warn!("{warning}");
    }
    let port = config.port();
    // Client IPs are only read by the Discord report, so skip them without one.
    let metrics = Arc::new(if config.discord_webhook().is_some() {
        Metrics::default()
    } else {
        Metrics::without_client_tracking()
    });
    let app = build_app(&config, Arc::clone(&metrics))?;
    let bind_address = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(bind_address)
        .await
        .map_err(|error| bind_error(bind_address, &error))?;
    // Log the bound address so `PORT=0` shows the port the OS picked.
    let address = listener.local_addr()?;
    // Log only whether each optional feature is on. The values are secrets.
    info!(
        version = env!("CARGO_PKG_VERSION"),
        commit = BUILD_COMMIT,
        %address,
        discord_reporting = config.discord_webhook().is_some(),
        mineskin_api_key = config.has_mineskin_api_key(),
        aes_secret_key = config.has_aes_secret_key(),
        "Axolotl server started"
    );
    info!(
        url = %docs_url(address.port()),
        "API documentation available"
    );
    let reporter = DiscordReporter::start(config.discord_webhook().cloned(), metrics);
    drop(config);

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

/// The server listens on all interfaces, but `0.0.0.0` is not an address a
/// browser can open, so the logged link points at the local machine.
fn docs_url(port: u16) -> String {
    format!("http://localhost:{port}/swagger")
}

/// Adds a hint for the bind failures that operators can fix themselves.
fn bind_error(address: SocketAddr, error: &io::Error) -> io::Error {
    let kind = error.kind();
    let hint = if kind == io::ErrorKind::AddrInUse {
        "; another process uses this port, so stop it or set PORT to a free port"
    } else if kind == io::ErrorKind::PermissionDenied {
        "; ports below 1024 need extra privileges, so set PORT to 1024 or higher"
    } else {
        ""
    };
    io::Error::new(
        error.kind(),
        format!("failed to listen on {address}: {error}{hint}"),
    )
}

/// Describes a `.env` failure. A parse error from `dotenvy` contains the whole
/// line, which can hold a secret, so that line is left out.
fn dotenv_error_message(error: &dotenvy::Error) -> String {
    if let dotenvy::Error::LineParse(_, index) = error {
        format!(
            "a line could not be parsed at character {index}, so it and the lines after it \
             were not loaded (the line is not shown because it can contain a secret)"
        )
    } else {
        error.to_string()
    }
}

/// Formats an error and its sources as `outer: inner`. A source is skipped
/// when the message already ends with it, because some errors repeat their
/// source in their own message.
fn error_chain(error: &(dyn Error + 'static)) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(error) = source {
        let text = error.to_string();
        if !message.ends_with(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
        source = error.source();
    }
    message
}

fn init_tracing() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (filter, invalid_filter) = match EnvFilter::try_from_default_env() {
        Ok(filter) => (filter, None),
        Err(error) => (
            EnvFilter::new("axolotl=info"),
            env::var_os(EnvFilter::DEFAULT_ENV).map(|_| error),
        ),
    };

    // Container log drivers capture stdout as text, so only color a terminal.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(io::stdout().is_terminal())
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
    use std::{
        io,
        net::{Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use axolotl::ConfigError;
    use thiserror::Error;
    use tokio::time::timeout;

    use super::{bind_error, docs_url, dotenv_error_message, error_chain, wait_for_signal};

    fn invalid_port() -> ConfigError {
        ConfigError::InvalidPort {
            value: "abc".to_owned(),
            source: "abc".parse::<u16>().expect_err("abc is not a port"),
        }
    }

    #[test]
    fn startup_errors_show_messages_and_sources() {
        assert_eq!(
            error_chain(&invalid_port()),
            "PORT must be a TCP port number from 0 to 65535, received \"abc\": invalid digit found in string"
        );
    }

    #[test]
    fn startup_errors_skip_sources_already_in_the_message() {
        #[derive(Debug, Error)]
        #[error("startup failed: {0}")]
        struct Wrapper(#[source] ConfigError);

        assert_eq!(
            error_chain(&Wrapper(invalid_port())),
            "startup failed: PORT must be a TCP port number from 0 to 65535, received \"abc\": invalid digit found in string"
        );
    }

    #[test]
    fn links_the_api_docs_on_localhost() {
        assert_eq!(docs_url(3000), "http://localhost:3000/swagger");
    }

    #[test]
    fn bind_errors_explain_how_to_fix_common_causes() {
        let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 80));
        let in_use = bind_error(address, &io::Error::from(io::ErrorKind::AddrInUse));
        assert_eq!(in_use.kind(), io::ErrorKind::AddrInUse);
        assert!(
            in_use
                .to_string()
                .starts_with("failed to listen on 0.0.0.0:80: ")
                && in_use.to_string().ends_with(
                    "; another process uses this port, so stop it or set PORT to a free port"
                ),
            "unexpected message: {in_use}"
        );

        let denied = bind_error(address, &io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(
            denied.to_string().ends_with(
                "; ports below 1024 need extra privileges, so set PORT to 1024 or higher"
            ),
            "unexpected message: {denied}"
        );

        let other = bind_error(address, &io::Error::other("boom"));
        assert_eq!(other.to_string(), "failed to listen on 0.0.0.0:80: boom");
    }

    #[test]
    fn dotenv_parse_errors_hide_the_line() {
        let error = dotenvy::Error::LineParse("AES_SECRET_KEY=hunter2 'x".to_owned(), 22);
        let message = dotenv_error_message(&error);
        assert!(!message.contains("hunter2"), "the line leaked: {message}");
        assert!(
            message.contains("character 22"),
            "unexpected message: {message}"
        );

        let io_error = dotenvy::Error::Io(io::Error::other("disk on fire"));
        assert_eq!(dotenv_error_message(&io_error), "disk on fire");
    }

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
