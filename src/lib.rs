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
mod metrics;
mod mineskin;
pub mod reporter;
mod routes;

pub use app::{api_document, build_app};
pub use config::{AppConfig, ConfigError};
pub use metrics::Metrics;
