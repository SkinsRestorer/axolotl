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
    /// `PORT` is not a valid TCP port, when an application URL cannot be
    /// parsed, or when `DISCORD_WEBHOOK` does not use HTTPS.
    pub fn from_env() -> Result<Self, ConfigError> {
        let port = match optional_environment_value("PORT")? {
            Some(value) => parse_port(&value)?,
            None => DEFAULT_PORT,
        };

        Ok(Self {
            port,
            mineskin_base_url: Url::parse(DEFAULT_MINESKIN_BASE_URL)
                .map_err(ConfigError::InvalidBaseUrl)?,
            mineskin_api_key: optional_environment_value("MINESKIN_API_KEY")?,
            aes_secret_key: optional_environment_value("AES_SECRET_KEY")?,
            discord_webhook: parse_discord_webhook(optional_environment_value("DISCORD_WEBHOOK")?)?,
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

    /// Describes configuration problems that do not stop startup but make some
    /// requests fail. The messages never include secret values.
    #[must_use]
    pub fn startup_warnings(&self) -> Vec<&'static str> {
        let mut warnings = Vec::new();
        match self.mineskin_api_key.as_deref() {
            key if is_blank(key) => {
                warnings.push("MINESKIN_API_KEY is not set, so MineSkin requests will fail");
            }
            // Use the client's own check so the warning and the requests agree.
            key if crate::mineskin::authorization_header(key).is_none() => warnings.push(
                "MINESKIN_API_KEY is not a usable bearer token, so MineSkin requests will fail",
            ),
            _ => {}
        }
        match self.aes_secret_key.as_deref() {
            secret if is_blank(secret) => {
                warnings.push("AES_SECRET_KEY is not set, so URL encryption will fail");
            }
            Some(secret) if secret.trim() != secret => warnings.push(
                "AES_SECRET_KEY has leading or trailing whitespace, which is part of the derived key",
            ),
            _ => {}
        }
        warnings
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
    read_environment_value(name, env::var(name))
}

fn read_environment_value(
    name: &'static str,
    value: Result<String, env::VarError>,
) -> Result<Option<String>, ConfigError> {
    match value {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        // The error would carry the raw value, which can be a secret.
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::NotUnicode { name }),
    }
}

fn is_blank(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

/// Treats a blank value as unset, matching the other optional variables.
fn parse_discord_webhook(value: Option<String>) -> Result<Option<Url>, ConfigError> {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };
    let url = Url::parse(value.trim()).map_err(ConfigError::InvalidDiscordWebhook)?;
    if url.scheme() != "https" {
        return Err(ConfigError::InsecureDiscordWebhook);
    }
    Ok(Some(url))
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
    #[error("{name} must be valid Unicode")]
    NotUnicode { name: &'static str },
    #[error("the configured MineSkin base URL is invalid")]
    InvalidBaseUrl(#[source] url::ParseError),
    #[error("DISCORD_WEBHOOK must be a valid URL")]
    InvalidDiscordWebhook(#[source] url::ParseError),
    #[error("DISCORD_WEBHOOK must use HTTPS")]
    InsecureDiscordWebhook,
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::{AppConfig, ConfigError, parse_discord_webhook, read_environment_value};

    fn config_with_secrets(api_key: Option<&str>, aes_secret: Option<&str>) -> AppConfig {
        let base_url = Url::parse("https://example.com/").expect("the test URL is valid");
        let mut config = AppConfig::for_tests(base_url);
        config.mineskin_api_key = api_key.map(str::to_owned);
        config.aes_secret_key = aes_secret.map(str::to_owned);
        config
    }

    #[test]
    fn warns_about_missing_or_blank_secrets() {
        for (api_key, aes_secret) in [(None, None), (Some(" "), Some(""))] {
            let warnings = config_with_secrets(api_key, aes_secret).startup_warnings();
            assert_eq!(
                warnings,
                [
                    "MINESKIN_API_KEY is not set, so MineSkin requests will fail",
                    "AES_SECRET_KEY is not set, so URL encryption will fail",
                ],
                "unexpected warnings for {api_key:?} and {aes_secret:?}"
            );
        }
    }

    #[test]
    fn warns_about_api_keys_the_client_cannot_send() {
        for api_key in ["Bearer", " bearer \n", "bad\nkey", "bad\u{7f}key"] {
            let warnings = config_with_secrets(Some(api_key), Some("secret")).startup_warnings();
            assert_eq!(
                warnings,
                ["MINESKIN_API_KEY is not a usable bearer token, so MineSkin requests will fail"],
                "unexpected warnings for {api_key:?}"
            );
        }
        for api_key in [" key\n", "Bearer key", "tab\tkey"] {
            assert!(
                config_with_secrets(Some(api_key), Some("secret"))
                    .startup_warnings()
                    .is_empty(),
                "{api_key:?} should be usable"
            );
        }
    }

    #[test]
    fn warns_about_padded_aes_secret() {
        let warnings = config_with_secrets(Some("key"), Some(" hunter2\n")).startup_warnings();
        assert_eq!(
            warnings,
            ["AES_SECRET_KEY has leading or trailing whitespace, which is part of the derived key"]
        );
    }

    #[test]
    fn has_no_warnings_for_configured_secrets() {
        assert!(
            config_with_secrets(Some("key"), Some("secret"))
                .startup_warnings()
                .is_empty()
        );
    }

    #[test]
    fn treats_blank_discord_webhook_as_disabled() {
        for value in [None, Some(String::new()), Some("  ".to_owned())] {
            assert!(
                matches!(parse_discord_webhook(value.clone()), Ok(None)),
                "{value:?} should disable the reporter"
            );
        }
    }

    #[test]
    fn accepts_only_https_discord_webhooks() {
        let webhook = parse_discord_webhook(Some(
            " https://discord.com/api/webhooks/1/token\n".to_owned(),
        ));
        assert!(
            matches!(&webhook, Ok(Some(url)) if url.as_str() == "https://discord.com/api/webhooks/1/token"),
            "a padded HTTPS webhook should be accepted: {webhook:?}"
        );

        let insecure =
            parse_discord_webhook(Some("http://discord.com/api/webhooks/1/token".to_owned()));
        assert!(
            matches!(insecure, Err(ConfigError::InsecureDiscordWebhook)),
            "an HTTP webhook should be rejected: {insecure:?}"
        );

        let invalid = parse_discord_webhook(Some("not a url".to_owned()));
        assert!(
            matches!(invalid, Err(ConfigError::InvalidDiscordWebhook(_))),
            "an unparsable webhook should be rejected: {invalid:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn reports_non_unicode_variables_by_name_without_the_value() {
        use std::{env::VarError, ffi::OsString, os::unix::ffi::OsStringExt};

        let value = OsString::from_vec(b"hunter2\xff".to_vec());
        let error = read_environment_value("AES_SECRET_KEY", Err(VarError::NotUnicode(value)))
            .expect_err("a non-Unicode value should be rejected");
        assert_eq!(error.to_string(), "AES_SECRET_KEY must be valid Unicode");
        assert!(
            !format!("{error:?}").contains("hunter2"),
            "the error must not expose the value: {error:?}"
        );
    }
}
