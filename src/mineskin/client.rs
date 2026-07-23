use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::body::Bytes;
use futures_util::StreamExt;
use reqwest::{
    Client, RequestBuilder, StatusCode,
    header::{AUTHORIZATION, HeaderValue},
    multipart::{Form, Part},
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use thiserror::Error;
use tokio::{
    sync::{Mutex, RwLock},
    time::{sleep, timeout},
};
use tracing::{error, warn};
use url::Url;
use uuid::Uuid;

use crate::{
    config::AppConfig,
    crypto::{MINESKIN_URL_PREFIX, UrlCipher},
};

use super::models::{
    Cape, JobDetails, JobStatus, JobSuccessResponse, MineSkinResponse, SanitizedResponse,
};

const MINESKIN_USER_AGENT: &str = "Axolotl-MineSkin-Proxy/1.0";
const MAXIMUM_UPSTREAM_RESPONSE_SIZE: usize = 1024 * 1024;
const INITIAL_UPSTREAM_RESPONSE_CAPACITY: usize = 16 * 1024;
const CAPE_REFRESH_RETRY_DELAY: Duration = Duration::from_secs(5);

pub struct MineSkinClient {
    http: Client,
    base_url: Url,
    authorization: AuthorizationHeader,
    cipher: UrlCipher,
    cache: CapeCache,
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
            authorization: AuthorizationHeader::new(config.mineskin_api_key.as_deref()),
            cipher,
            cache: CapeCache::default(),
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
        let url = self.job_endpoint(job_id)?;
        let request = self.authorize(self.http.get(url))?;
        let mut response = self.execute(request, "MineSkin job response").await?;
        let job = response.job.take().ok_or_else(|| {
            MineSkinClientError::unexpected("MineSkin job response", "job is missing")
        })?;
        let response = JobSuccessResponse {
            success: true,
            job,
            skin: response.skin.take(),
            warnings: response.warnings.take(),
            messages: response.messages.take(),
        };
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
        let file_length = u64::try_from(upload.file.len())
            .map_err(|_| MineSkinClientError::InvalidUpload("Skin file is too large".to_owned()))?;
        let mut file = Part::stream_with_length(upload.file, file_length)
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
        let mut response = self
            .execute(request, "MineSkin job enqueue response")
            .await?;

        if let Some(job) = response.job.take() {
            Ok(job)
        } else {
            Err(MineSkinClientError::upstream(
                StatusCode::BAD_GATEWAY,
                response.into_error_message(),
            ))
        }
    }

    pub async fn supported_capes(&self) -> Result<Arc<[Cape]>, MineSkinClientError> {
        let cached = self.cached_capes().await;
        if let Some(cached) = cached.as_ref().filter(|cached| self.is_cache_fresh(cached)) {
            return Ok(Arc::clone(&cached.data));
        }

        let refresh = match self.cache.refresh.try_lock() {
            Ok(refresh) => refresh,
            Err(_) => match &cached {
                Some(cached) => return Ok(Arc::clone(&cached.data)),
                None => self.cache.refresh.lock().await,
            },
        };

        let cached = self.cached_capes().await;
        if let Some(cached) = cached.as_ref().filter(|cached| self.is_cache_fresh(cached)) {
            return Ok(Arc::clone(&cached.data));
        }

        if let Some(failure) = self.recent_cache_failure().await {
            return cached
                .map(|cached| Arc::clone(&cached.data))
                .ok_or_else(|| failure.to_error());
        }

        match self.fetch_supported_capes().await {
            Ok(capes) => {
                let capes = Arc::<[Cape]>::from(capes);
                let mut state = self.cache.state.write().await;
                state.value = Some(Arc::new(CachedCapes {
                    data: Arc::clone(&capes),
                    fetched_at: Instant::now(),
                }));
                state.last_failure = None;
                drop(refresh);

                Ok(capes)
            }
            Err(error) => {
                self.cache.state.write().await.last_failure = Some(CachedCapeFailure::new(&error));
                drop(refresh);

                if let Some(cached) = cached {
                    warn!(%error, "Failed to refresh MineSkin capes; serving stale data");
                    Ok(Arc::clone(&cached.data))
                } else {
                    Err(error)
                }
            }
        }
    }

    async fn cached_capes(&self) -> Option<Arc<CachedCapes>> {
        self.cache.state.read().await.value.clone()
    }

    async fn recent_cache_failure(&self) -> Option<CachedCapeFailure> {
        self.cache
            .state
            .read()
            .await
            .last_failure
            .as_ref()
            .filter(|failure| failure.failed_at.elapsed() < CAPE_REFRESH_RETRY_DELAY)
            .cloned()
    }

    fn is_cache_fresh(&self, cached: &CachedCapes) -> bool {
        cached.fetched_at.elapsed() < self.cape_cache_ttl
    }

    pub async fn has_cape_grant(&self) -> Result<bool, MineSkinClientError> {
        let url = self.endpoint("me")?;
        let request = self.authorize(self.http.get(url))?;
        let response = self.execute(request, "MineSkin account response").await?;

        Ok(response
            .grants
            .as_ref()
            .and_then(|grants| grants.capes.as_ref())
            .is_some_and(is_api_value_truthy))
    }

    async fn fetch_supported_capes(&self) -> Result<Vec<Cape>, MineSkinClientError> {
        let url = self.endpoint("capes")?;
        let request = self.authorize(self.http.get(url))?;
        let response = self.execute(request, "MineSkin cape response").await?;

        response
            .capes
            .unwrap_or_default()
            .into_iter()
            .filter(|cape| cape.supported == Some(true))
            .map(|cape| {
                let uuid = Uuid::parse_str(&cape.uuid)
                    .map(|uuid| uuid.hyphenated().to_string())
                    .map_err(|_| {
                        MineSkinClientError::unexpected(
                            "MineSkin cape response",
                            "cape UUID is invalid",
                        )
                    })?;
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

    fn job_endpoint(&self, job_id: &str) -> Result<Url, MineSkinClientError> {
        let mut url = self.endpoint("queue/")?;
        url.path_segments_mut()
            .map_err(|()| {
                MineSkinClientError::Configuration(
                    "MineSkin base URL cannot contain path segments".to_owned(),
                )
            })?
            .pop_if_empty()
            .push(job_id);

        Ok(url)
    }

    fn authorize(&self, request: RequestBuilder) -> Result<RequestBuilder, MineSkinClientError> {
        match &self.authorization {
            AuthorizationHeader::Configured(header) => {
                Ok(request.header(AUTHORIZATION, header.clone()))
            }
            AuthorizationHeader::Missing => Err(MineSkinClientError::Configuration(
                "MineSkin API key is not configured".to_owned(),
            )),
            AuthorizationHeader::Empty => Err(MineSkinClientError::Configuration(
                "MineSkin API key is empty".to_owned(),
            )),
            AuthorizationHeader::Invalid => Err(MineSkinClientError::Configuration(
                "MineSkin API key contains invalid characters".to_owned(),
            )),
        }
    }

    async fn execute(
        &self,
        request: RequestBuilder,
        context: &'static str,
    ) -> Result<MineSkinResponse, MineSkinClientError> {
        let response = request.send().await.map_err(MineSkinClientError::Request)?;
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > MAXIMUM_UPSTREAM_RESPONSE_SIZE as u64)
        {
            return Err(MineSkinClientError::unexpected(
                context,
                "response exceeded 1 MiB",
            ));
        }

        let capacity = response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(MAXIMUM_UPSTREAM_RESPONSE_SIZE)
            .min(INITIAL_UPSTREAM_RESPONSE_CAPACITY);
        let mut body = Vec::with_capacity(capacity);
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(MineSkinClientError::Request)?;
            if body.len().saturating_add(chunk.len()) > MAXIMUM_UPSTREAM_RESPONSE_SIZE {
                return Err(MineSkinClientError::unexpected(
                    context,
                    "response exceeded 1 MiB",
                ));
            }
            body.extend_from_slice(&chunk);
        }

        let buffered = BufferedResponse { status, body };
        let response = parse_response(context, &buffered)?;

        ensure_upstream_success(status, response)
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

struct CachedCapes {
    data: Arc<[Cape]>,
    fetched_at: Instant,
}

#[derive(Default)]
struct CapeCache {
    state: RwLock<CapeCacheState>,
    refresh: Mutex<()>,
}

#[derive(Default)]
struct CapeCacheState {
    value: Option<Arc<CachedCapes>>,
    last_failure: Option<CachedCapeFailure>,
}

#[derive(Clone)]
struct CachedCapeFailure {
    failed_at: Instant,
    configuration_error: bool,
    upstream_status: Option<StatusCode>,
    message: String,
}

impl CachedCapeFailure {
    fn new(error: &MineSkinClientError) -> Self {
        Self {
            failed_at: Instant::now(),
            configuration_error: error.is_configuration_error(),
            upstream_status: error.upstream_status(),
            message: error.to_string(),
        }
    }

    fn to_error(&self) -> MineSkinClientError {
        if self.configuration_error {
            return MineSkinClientError::Configuration(self.message.clone());
        }
        if let Some(status) = self.upstream_status {
            return MineSkinClientError::upstream(status, self.message.clone());
        }

        MineSkinClientError::unexpected("MineSkin cape response", self.message.clone())
    }
}

enum AuthorizationHeader {
    Configured(HeaderValue),
    Missing,
    Empty,
    Invalid,
}

impl AuthorizationHeader {
    fn new(api_key: Option<&str>) -> Self {
        let Some(raw_key) = api_key else {
            return Self::Missing;
        };
        let raw_key = raw_key.trim();
        if raw_key.is_empty() || raw_key.eq_ignore_ascii_case("Bearer") {
            return Self::Empty;
        }

        let authorization = if raw_key.starts_with("Bearer ") {
            raw_key.to_owned()
        } else {
            format!("Bearer {raw_key}")
        };

        HeaderValue::from_str(&authorization).map_or(Self::Invalid, |mut header| {
            header.set_sensitive(true);
            Self::Configured(header)
        })
    }
}

struct BufferedResponse {
    status: StatusCode,
    body: Vec<u8>,
}

fn parse_response<T: DeserializeOwned>(
    context: &'static str,
    response: &BufferedResponse,
) -> Result<T, MineSkinClientError> {
    serde_json::from_slice(&response.body).map_err(|source| {
        error!(
            context,
            status = %response.status,
            response_size = response.body.len(),
            %source,
            "Failed to parse MineSkin response"
        );
        MineSkinClientError::UnexpectedResponse {
            context,
            message: source.to_string(),
        }
    })
}

fn ensure_upstream_success(
    status: StatusCode,
    response: MineSkinResponse,
) -> Result<MineSkinResponse, MineSkinClientError> {
    if status.is_success() && response.success != Some(false) {
        return Ok(response);
    }

    let status = if status.is_success() {
        StatusCode::BAD_GATEWAY
    } else {
        status
    };
    Err(MineSkinClientError::upstream(
        status,
        response.into_error_message(),
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
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(MineSkinClientError::unexpected(
            "MineSkin cape response",
            "cape URL must use HTTPS",
        ));
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

#[cfg(test)]
mod tests {
    use std::{error::Error, time::Duration};

    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;

    const CAPE_UUID: &str = "123e4567-e89b-12d3-a456-426614174001";

    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    #[tokio::test]
    async fn serves_stale_capes_when_refresh_fails() -> TestResult {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/capes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "capes": [{
                    "uuid": CAPE_UUID,
                    "alias": "founders",
                    "url": "https://textures.example/cape.png",
                    "supported": true
                }]
            })))
            .with_priority(1)
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v2/capes"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "success": false,
                "errors": [{ "message": "temporary failure" }]
            })))
            .with_priority(2)
            .expect(1)
            .mount(&server)
            .await;

        let mut config = AppConfig::for_tests(Url::parse(&format!("{}/v2/", server.uri()))?);
        config.cape_cache_ttl = Duration::ZERO;
        let client =
            MineSkinClient::new(&config, UrlCipher::new(config.aes_secret_key.as_deref()))?;

        let initial = client.supported_capes().await?;
        let stale = client.supported_capes().await?;

        assert!(Arc::ptr_eq(&initial, &stale));
        server.verify().await;
        Ok(())
    }

    #[test]
    fn encodes_job_ids_as_single_path_segments() -> TestResult {
        let config = AppConfig::for_tests(Url::parse("https://example.com/v2/")?);
        let client =
            MineSkinClient::new(&config, UrlCipher::new(config.aes_secret_key.as_deref()))?;

        let url = client.job_endpoint("job/with?syntax")?;

        assert_eq!(url.path(), "/v2/queue/job%2Fwith%3Fsyntax");
        Ok(())
    }
}
