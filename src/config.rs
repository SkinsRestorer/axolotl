use std::{env, num::ParseIntError, time::Duration};

use thiserror::Error;
use url::Url;

const DEFAULT_PORT: u16 = 3000;
const DEFAULT_MINESKIN_BASE_URL: &str = "https://api.mineskin.org/v2/";
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_MAX_POLL_DURATION: Duration = Duration::from_mins(5);
const DEFAULT_CAPE_CACHE_TTL: Duration = Duration::from_mins(5);
const DEFAULT_MAX_CONCURRENT_UPLOADS: usize = 16;

#[derive(Clone)]
pub struct AppConfig {
    pub(crate) port: u16,
    pub(crate) mineskin_base_url: Url,
    pub(crate) mineskin_api_key: Option<String>,
    pub(crate) aes_secret_key: Option<String>,
    pub(crate) discord_webhook: Option<Url>,
    pub(crate) request_timeout: Duration,
    pub(crate) default_poll_interval: Duration,
    pub(crate) max_poll_duration: Duration,
    pub(crate) cape_cache_ttl: Duration,
    pub(crate) max_concurrent_uploads: usize,
}

impl AppConfig {
    /// Loads application configuration from the process environment.
    ///
    /// # Errors
    ///
    /// Returns an error when an environment variable is not valid Unicode, when
    /// `PORT` is not a valid TCP port, or when an application URL cannot be
    /// parsed.
    pub fn from_env() -> Result<Self, ConfigError> {
        let port = match env::var("PORT") {
            Ok(value) => parse_port(&value)?,
            Err(env::VarError::NotPresent) => DEFAULT_PORT,
            Err(error) => return Err(ConfigError::Environment(error)),
        };

        Ok(Self {
            port,
            mineskin_base_url: Url::parse(DEFAULT_MINESKIN_BASE_URL)
                .map_err(ConfigError::InvalidBaseUrl)?,
            mineskin_api_key: optional_environment_value("MINESKIN_API_KEY")?,
            aes_secret_key: optional_environment_value("AES_SECRET_KEY")?,
            discord_webhook: optional_environment_value("DISCORD_WEBHOOK")?
                .map(|value| Url::parse(&value))
                .transpose()
                .map_err(ConfigError::InvalidDiscordWebhook)?,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            default_poll_interval: DEFAULT_POLL_INTERVAL,
            max_poll_duration: DEFAULT_MAX_POLL_DURATION,
            cape_cache_ttl: DEFAULT_CAPE_CACHE_TTL,
            max_concurrent_uploads: DEFAULT_MAX_CONCURRENT_UPLOADS,
        })
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub const fn discord_webhook(&self) -> Option<&Url> {
        self.discord_webhook.as_ref()
    }

    #[doc(hidden)]
    #[must_use]
    pub fn for_tests(mineskin_base_url: Url) -> Self {
        Self {
            port: DEFAULT_PORT,
            mineskin_base_url,
            mineskin_api_key: Some("test-api-key".to_owned()),
            aes_secret_key: Some("test-secret".to_owned()),
            discord_webhook: None,
            request_timeout: Duration::from_secs(2),
            default_poll_interval: Duration::from_millis(1),
            max_poll_duration: Duration::from_secs(1),
            cape_cache_ttl: DEFAULT_CAPE_CACHE_TTL,
            max_concurrent_uploads: 1,
        }
    }
}

fn optional_environment_value(name: &'static str) -> Result<Option<String>, ConfigError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(ConfigError::Environment(error)),
    }
}

fn parse_port(value: &str) -> Result<u16, ConfigError> {
    value.parse().map_err(|source| ConfigError::InvalidPort {
        value: value.to_owned(),
        source,
    })
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("PORT must be a valid TCP port, received {value:?}")]
    InvalidPort {
        value: String,
        #[source]
        source: ParseIntError,
    },
    #[error("failed to read an environment variable")]
    Environment(#[source] env::VarError),
    #[error("the configured MineSkin base URL is invalid")]
    InvalidBaseUrl(#[source] url::ParseError),
    #[error("DISCORD_WEBHOOK must be a valid URL")]
    InvalidDiscordWebhook(#[source] url::ParseError),
}
