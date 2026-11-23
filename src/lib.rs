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

mod app;
mod config;
mod crypto;
mod error;
mod http_client;
mod metrics;
mod mineskin;
pub mod reporter;
mod routes;

pub use app::{api_document, build_app};
pub use config::{AppConfig, ConfigError};
pub use metrics::Metrics;

/// The Git commit this binary was built from, taken from the `GIT_SHA`
/// variable at compile time, or `"unknown"` when it was not set.
pub const BUILD_COMMIT: &str = match option_env!("GIT_SHA") {
    Some(commit) if !commit.is_empty() => commit,
    _ => "unknown",
};
