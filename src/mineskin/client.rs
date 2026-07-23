use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::body::Bytes;
use reqwest::{
    Client, RequestBuilder, StatusCode,
    header::{AUTHORIZATION, HeaderValue},
    multipart::{Form, Part},
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use thiserror::Error;
use tokio::{
    sync::Mutex,
    time::{sleep, timeout},
};
use tracing::error;
use url::Url;

use crate::{
    config::AppConfig,
    crypto::{MINESKIN_URL_PREFIX, UrlCipher},
};

use super::models::{
    Cape, CapeResponse, EnqueueResponse, GenericResponse, JobDetails, JobStatus,
    JobSuccessResponse, MeResponse, SanitizedResponse,
};

const MINESKIN_USER_AGENT: &str = "Axolotl-MineSkin-Proxy/1.0";

#[derive(Clone)]
pub struct MineSkinClient {
    http: Client,
    base_url: Url,
    api_key: Option<String>,
    cipher: UrlCipher,
    cache: Arc<Mutex<Option<CachedCapes>>>,
    default_poll_interval: Duration,
    max_poll_duration: Duration,
    cape_cache_ttl: Duration,
}

impl MineSkinClient {
    pub fn new(config: &AppConfig, cipher: UrlCipher) -> Result<Self, MineSkinClientError> {
        let http = Client::builder()
            .user_agent(MINESKIN_USER_AGENT)
            .timeout(config.request_timeout)
            .build()
            .map_err(MineSkinClientError::Request)?;

        Ok(Self {
            http,
            base_url: config.mineskin_base_url.clone(),
            api_key: config.mineskin_api_key.clone(),
            cipher,
            cache: Arc::new(Mutex::new(None)),
            default_poll_interval: config.default_poll_interval,
            max_poll_duration: config.max_poll_duration,
            cape_cache_ttl: config.cape_cache_ttl,
        })
    }

    #[must_use]
    pub const fn default_poll_interval(&self) -> Duration {
        self.default_poll_interval
    }

    pub async fn fetch_job(&self, job_id: &str) -> Result<JobSuccessResponse, MineSkinClientError> {
        let url = self.endpoint(&format!("queue/{job_id}"))?;
        let request = self.authorize(self.http.get(url))?;
        let (status, value) = self.execute(request).await?;
        let generic = generic_response(&value);

        ensure_upstream_success(status, &generic)?;
        let response: JobSuccessResponse = parse_response("MineSkin job response", &value)?;
        response
            .validate()
            .map_err(|message| MineSkinClientError::unexpected("MineSkin job response", message))?;

        Ok(response)
    }

    pub async fn poll_job(
        &self,
        job_id: &str,
        poll_interval: Duration,
    ) -> Result<SanitizedResponse, MineSkinClientError> {
        let poll = async {
            loop {
                let response = self.fetch_job(job_id).await?;

                match response.job.status {
                    JobStatus::Completed => {
                        if !response.has_skin() {
                            return Err(MineSkinClientError::upstream(
                                StatusCode::BAD_GATEWAY,
                                "MineSkin job completed but no skin data provided",
                            ));
                        }
                        return self.sanitize_job(response);
                    }
                    JobStatus::Failed => {
                        return Err(MineSkinClientError::upstream(
                            StatusCode::BAD_GATEWAY,
                            "MineSkin job failed to complete",
                        ));
                    }
                    JobStatus::Unknown
                    | JobStatus::Waiting
                    | JobStatus::Active
                    | JobStatus::Processing => sleep(poll_interval).await,
                }
            }
        };

        timeout(self.max_poll_duration, poll).await.map_err(|_| {
            MineSkinClientError::upstream(
                StatusCode::GATEWAY_TIMEOUT,
                "Timed out waiting for MineSkin job to finish",
            )
        })?
    }

    pub fn sanitize_job(
        &self,
        response: JobSuccessResponse,
    ) -> Result<SanitizedResponse, MineSkinClientError> {
        let encrypted_url = response
            .skin_uuid()
            .map(|uuid| self.cipher.encrypt_uuid(uuid))
            .transpose()
            .map_err(MineSkinClientError::Crypto)?;

        response
            .into_sanitized(encrypted_url)
            .map_err(|message| MineSkinClientError::unexpected("MineSkin job response", message))
    }

    pub async fn enqueue(&self, upload: UploadPayload) -> Result<JobDetails, MineSkinClientError> {
        let mut file = Part::bytes(upload.file.to_vec())
            .file_name(upload.file_name.unwrap_or_else(|| "skin.png".to_owned()));
        if let Some(content_type) = upload.content_type {
            file = file.mime_str(&content_type).map_err(|_| {
                MineSkinClientError::InvalidUpload("Invalid skin file content type".to_owned())
            })?;
        }

        let mut form = Form::new()
            .part("file", file)
            .text("variant", upload.variant)
            .text("cape", upload.cape_uuid);
        if let Some(name) = upload.name {
            form = form.text("name", name);
        }

        let url = self.endpoint("queue")?;
        let request = self.authorize(self.http.post(url))?.multipart(form);
        let (status, value) = self.execute(request).await?;
        let response: EnqueueResponse = parse_response("MineSkin job enqueue response", &value)?;

        ensure_upstream_success(status, &response.generic)?;
        response.job.ok_or_else(|| {
            MineSkinClientError::upstream(StatusCode::BAD_GATEWAY, response.generic.error_message())
        })
    }

    pub async fn supported_capes(&self) -> Result<Vec<Cape>, MineSkinClientError> {
        let mut cache = self.cache.lock().await;
        if let Some(cached) = cache.as_ref()
            && cached.fetched_at.elapsed() < self.cape_cache_ttl
        {
            return Ok(cached.data.clone());
        }

        let capes = self.fetch_supported_capes().await?;
        *cache = Some(CachedCapes {
            data: capes.clone(),
            fetched_at: Instant::now(),
        });

        Ok(capes)
    }

    pub async fn has_cape_grant(&self) -> Result<bool, MineSkinClientError> {
        let url = self.endpoint("me")?;
        let request = self.authorize(self.http.get(url))?;
        let (status, value) = self.execute(request).await?;
        let response: MeResponse = parse_response("MineSkin account response", &value)?;

        ensure_upstream_success(status, &response.generic)?;
        Ok(response
            .grants
            .as_ref()
            .and_then(|grants| grants.get("capes"))
            .is_some_and(is_api_value_truthy))
    }

    async fn fetch_supported_capes(&self) -> Result<Vec<Cape>, MineSkinClientError> {
        let url = self.endpoint("capes")?;
        let request = self.authorize(self.http.get(url))?;
        let (status, value) = self.execute(request).await?;
        let response: CapeResponse = parse_response("MineSkin cape response", &value)?;

        ensure_upstream_success(status, &response.generic)?;

        response
            .capes
            .unwrap_or_default()
            .into_iter()
            .filter(|cape| cape.supported == Some(true))
            .map(|cape| {
                let uuid = self.encrypt_mineskin_string(cape.uuid)?;
                let alias = self.encrypt_mineskin_string(cape.alias)?;
                let normalized_url = normalize_texture_url(&cape.url)?;
                let url = self.encrypt_mineskin_string(normalized_url)?;

                Ok(Cape { uuid, alias, url })
            })
            .collect()
    }

    fn encrypt_mineskin_string(&self, value: String) -> Result<String, MineSkinClientError> {
        if value.starts_with(MINESKIN_URL_PREFIX) {
            self.cipher
                .encrypt_url(&value)
                .map_err(MineSkinClientError::Crypto)
        } else {
            Ok(value)
        }
    }

    fn endpoint(&self, path: &str) -> Result<Url, MineSkinClientError> {
        self.base_url
            .join(path)
            .map_err(|error| MineSkinClientError::Configuration(error.to_string()))
    }

    fn authorize(&self, request: RequestBuilder) -> Result<RequestBuilder, MineSkinClientError> {
        let raw_key = self
            .api_key
            .as_deref()
            .ok_or_else(|| {
                MineSkinClientError::Configuration("MineSkin API key is not configured".to_owned())
            })?
            .trim();

        if raw_key.is_empty() {
            return Err(MineSkinClientError::Configuration(
                "MineSkin API key is empty".to_owned(),
            ));
        }

        let authorization = if raw_key.starts_with("Bearer ") {
            raw_key.to_owned()
        } else {
            format!("Bearer {raw_key}")
        };
        let header = HeaderValue::from_str(&authorization).map_err(|_| {
            MineSkinClientError::Configuration(
                "MineSkin API key contains invalid characters".to_owned(),
            )
        })?;

        Ok(request.header(AUTHORIZATION, header))
    }

    async fn execute(
        &self,
        request: RequestBuilder,
    ) -> Result<(StatusCode, Value), MineSkinClientError> {
        let response = request.send().await.map_err(MineSkinClientError::Request)?;
        let status = response.status();
        let value = response
            .json()
            .await
            .map_err(MineSkinClientError::Request)?;

        Ok((status, value))
    }
}

#[derive(Debug)]
pub struct UploadPayload {
    pub file: Bytes,
    pub file_name: Option<String>,
    pub content_type: Option<String>,
    pub variant: String,
    pub name: Option<String>,
    pub cape_uuid: String,
}

#[derive(Clone)]
struct CachedCapes {
    data: Vec<Cape>,
    fetched_at: Instant,
}

fn parse_response<T: DeserializeOwned>(
    context: &'static str,
    value: &Value,
) -> Result<T, MineSkinClientError> {
    serde_json::from_value(value.clone()).map_err(|source| {
        error!(context, response = %value, %source, "Failed to parse MineSkin response");
        MineSkinClientError::UnexpectedResponse {
            context,
            message: source.to_string(),
        }
    })
}

fn generic_response(value: &Value) -> GenericResponse {
    serde_json::from_value(value.clone()).unwrap_or_default()
}

fn ensure_upstream_success(
    status: StatusCode,
    response: &GenericResponse,
) -> Result<(), MineSkinClientError> {
    if status.is_success() && response.success != Some(false) {
        return Ok(());
    }

    let status = if status.is_success() {
        StatusCode::BAD_GATEWAY
    } else {
        status
    };
    Err(MineSkinClientError::upstream(
        status,
        response.error_message(),
    ))
}

fn normalize_texture_url(value: &str) -> Result<String, MineSkinClientError> {
    let mut url = Url::parse(value).map_err(|_| {
        MineSkinClientError::unexpected("MineSkin cape response", "cape URL is invalid")
    })?;

    if url.scheme() == "http" {
        url.set_scheme("https").map_err(|()| {
            MineSkinClientError::unexpected(
                "MineSkin cape response",
                "cape URL scheme could not be normalized",
            )
        })?;
    }

    Ok(url.to_string())
}

fn is_api_value_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value
            .as_f64()
            .is_some_and(|number| number != 0.0 && !number.is_nan()),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

#[derive(Debug, Error)]
pub enum MineSkinClientError {
    #[error("{0}")]
    Configuration(String),
    #[error("MineSkin request failed: {0}")]
    Request(#[source] reqwest::Error),
    #[error("Unexpected {context}: {message}")]
    UnexpectedResponse {
        context: &'static str,
        message: String,
    },
    #[error("{message}")]
    Upstream { status: StatusCode, message: String },
    #[error("{0}")]
    Crypto(#[source] crate::crypto::CryptoError),
    #[error("{0}")]
    InvalidUpload(String),
}

impl MineSkinClientError {
    fn upstream(status: StatusCode, message: impl Into<String>) -> Self {
        Self::Upstream {
            status,
            message: message.into(),
        }
    }

    fn unexpected(context: &'static str, message: impl Into<String>) -> Self {
        Self::UnexpectedResponse {
            context,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn upstream_status(&self) -> Option<StatusCode> {
        match self {
            Self::Upstream { status, .. } => Some(*status),
            Self::Configuration(_)
            | Self::Request(_)
            | Self::UnexpectedResponse { .. }
            | Self::Crypto(_)
            | Self::InvalidUpload(_) => None,
        }
    }

    #[must_use]
    pub const fn is_configuration_error(&self) -> bool {
        matches!(
            self,
            Self::Configuration(_) | Self::Crypto(crate::crypto::CryptoError::MissingConfiguration)
        )
    }
}
