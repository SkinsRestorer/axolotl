#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

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
    http_client,
    metrics::Metrics,
};

use super::models::{
    Cape, JobDetails, JobStatus, JobSuccessResponse, MineSkinErrorItem, MineSkinResponse,
    SanitizedResponse,
};

const MINESKIN_USER_AGENT: &str = "Axolotl-MineSkin-Proxy/1.0";
const MAXIMUM_UPSTREAM_RESPONSE_SIZE: usize = 1024 * 1024;
const FAILURE_RETRY_DELAY: Duration = Duration::from_secs(5);
const MAXIMUM_POLL_RETRY_DELAY: Duration = Duration::from_secs(10);

pub struct MineSkinClient {
    http: Client,
    base_url: Url,
    authorization: Option<HeaderValue>,
    cipher: UrlCipher,
    metrics: Arc<Metrics>,
    cache: CapeCache,
    grant_cache: Mutex<GrantCacheState>,
    default_poll_interval: Duration,
    max_poll_duration: Duration,
    cape_cache_ttl: Duration,
}

impl MineSkinClient {
    pub fn new(
        config: &AppConfig,
        cipher: UrlCipher,
        metrics: Arc<Metrics>,
    ) -> Result<Self, MineSkinClientError> {
        let http = http_client::builder(config.request_timeout)
            .user_agent(MINESKIN_USER_AGENT)
            .build()
            .map_err(MineSkinClientError::Request)?;

        Ok(Self {
            http,
            base_url: config.mineskin_base_url.clone(),
            authorization: authorization_header(config.mineskin_api_key.as_deref()),
            cipher,
            metrics,
            cache: CapeCache::default(),
            grant_cache: Mutex::default(),
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
        self.fetch_job_with_errors(job_id)
            .await
            .map(|(response, _)| response)
    }

    /// Fetches a job and keeps the upstream `errors` list, which `MineSkin`
    /// uses to explain why a job failed.
    async fn fetch_job_with_errors(
        &self,
        job_id: &str,
    ) -> Result<(JobSuccessResponse, Option<Vec<MineSkinErrorItem>>), MineSkinClientError> {
        let url = self.job_endpoint(job_id)?;
        let request = self.authorize(self.http.get(url))?;
        let mut response = self.execute(request, "MineSkin job response").await?;
        let errors = response.errors.take();
        let job = response.job.take().ok_or_else(|| {
            MineSkinClientError::unexpected("MineSkin job response", "job is missing")
        })?;
        let response = JobSuccessResponse {
            job,
            skin: response.skin.take(),
            warnings: response.warnings.take(),
            messages: response.messages.take(),
        };
        response
            .validate()
            .map_err(|message| MineSkinClientError::unexpected("MineSkin job response", message))?;

        Ok((response, errors))
    }

    pub async fn poll_job(
        &self,
        job_id: &str,
        poll_interval: Duration,
    ) -> Result<SanitizedResponse, MineSkinClientError> {
        let poll = async {
            let mut warned_unknown_status = false;
            let mut retry_delay = poll_interval;
            loop {
                // The job is already queued, so a transient failure must not
                // abort the upload. Retrying the upload would queue a duplicate.
                let (response, errors) = match self.fetch_job_with_errors(job_id).await {
                    Ok(result) => result,
                    Err(error) if error.is_transient() => {
                        warn!(%error, job_id, "Retrying MineSkin job status after a transient error");
                        // Back off so a rate-limited or failing MineSkin is not polled
                        // at the client's chosen interval.
                        sleep(retry_delay).await;
                        retry_delay = retry_delay
                            .saturating_mul(2)
                            .min(MAXIMUM_POLL_RETRY_DELAY)
                            .max(poll_interval);
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                retry_delay = poll_interval;

                match response.job.status {
                    JobStatus::Completed => {
                        if response.skin_uuid().is_none() {
                            return Err(MineSkinClientError::upstream(
                                StatusCode::BAD_GATEWAY,
                                "MineSkin job completed but no skin data provided",
                            ));
                        }
                        return self.sanitize_job(response);
                    }
                    JobStatus::Failed => {
                        let message = errors
                            .into_iter()
                            .flatten()
                            .find_map(|item| item.message)
                            .unwrap_or_else(|| "MineSkin job failed to complete".to_owned());
                        return Err(MineSkinClientError::upstream(
                            StatusCode::BAD_GATEWAY,
                            message,
                        ));
                    }
                    JobStatus::Unknown => {
                        if !warned_unknown_status {
                            warn!(
                                job_id,
                                "MineSkin returned an unknown job status; still polling"
                            );
                            warned_unknown_status = true;
                        }
                        sleep(poll_interval).await;
                    }
                    JobStatus::Waiting | JobStatus::Active | JobStatus::Processing => {
                        sleep(poll_interval).await;
                    }
                }
            }
        };

        timeout(self.max_poll_duration, poll)
            .await
            .map_err(|error| {
                tracing::debug!(%error, "MineSkin polling deadline elapsed");
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
        let file_length = u64::try_from(upload.file.len()).map_err(|error| {
            tracing::debug!(%error, "Skin file length exceeds the multipart limit");
            MineSkinClientError::InvalidUpload("Skin file is too large".to_owned())
        })?;
        let mut file = Part::stream_with_length(upload.file, file_length)
            .file_name(upload.file_name.unwrap_or_else(|| "skin.png".to_owned()));
        if let Some(content_type) = upload.content_type {
            file = file.mime_str(&content_type).map_err(|error| {
                tracing::debug!(%error, "Invalid skin file content type");
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
                drop(state);

                Ok(capes)
            }
            Err(error) => {
                self.cache.state.write().await.last_failure = Some(CachedFailure::new(&error));
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

    async fn recent_cache_failure(&self) -> Option<CachedFailure> {
        self.cache
            .state
            .read()
            .await
            .last_failure
            .as_ref()
            .filter(|failure| failure.is_recent())
            .cloned()
    }

    fn is_cache_fresh(&self, cached: &CachedCapes) -> bool {
        cached.fetched_at.elapsed() < self.cape_cache_ttl
    }

    /// Returns whether the account may use capes. The answer is cached for the
    /// cape cache TTL, because grants change rarely and every call costs a
    /// `MineSkin` request. The lock is held during the request, so callers that
    /// wait for it share its result, including a failure. Later callers retry.
    pub async fn has_cape_grant(&self) -> Result<bool, MineSkinClientError> {
        let called_at = Instant::now();
        let mut cache = self.grant_cache.lock().await;
        if let Some((has_grant, fetched_at)) = cache.value
            && fetched_at.elapsed() < self.cape_cache_ttl
        {
            return Ok(has_grant);
        }
        // After a failure, wait before asking MineSkin again, as the cape cache
        // does, so a failing /me is not called once per client request. Serve
        // the last known grant meanwhile.
        let stale = cache.value.map(|(has_grant, _)| has_grant);
        if let Some(failure) = cache
            .last_failure
            .as_ref()
            .filter(|failure| failure.failed_at > called_at || failure.is_recent())
        {
            return stale.ok_or_else(|| failure.to_error());
        }

        let result = match self.fetch_cape_grant().await {
            Ok(has_grant) => {
                cache.value = Some((has_grant, Instant::now()));
                cache.last_failure = None;
                Ok(has_grant)
            }
            Err(error) => {
                cache.last_failure = Some(CachedFailure::new(&error));
                if let Some(has_grant) = stale {
                    warn!(%error, "Failed to refresh the MineSkin cape grant; serving stale data");
                    Ok(has_grant)
                } else {
                    Err(error)
                }
            }
        };
        drop(cache);
        result
    }

    async fn fetch_cape_grant(&self) -> Result<bool, MineSkinClientError> {
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
                    .map_err(|error| {
                        tracing::debug!(%error, "Invalid MineSkin cape UUID");
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
        let header = self.authorization.clone().ok_or_else(|| {
            MineSkinClientError::Configuration("MineSkin API key is missing or invalid".to_owned())
        })?;
        Ok(request.header(AUTHORIZATION, header))
    }

    async fn execute(
        &self,
        request: RequestBuilder,
        context: &'static str,
    ) -> Result<MineSkinResponse, MineSkinClientError> {
        let started_at = Instant::now();
        let result = async {
            let response = request.send().await.map_err(MineSkinClientError::Request)?;
            let status = response.status();
            let mut body = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(MineSkinClientError::Request)?;
                if body
                    .len()
                    .checked_add(chunk.len())
                    .is_none_or(|length| length > MAXIMUM_UPSTREAM_RESPONSE_SIZE)
                {
                    return Err(MineSkinClientError::unexpected(
                        context,
                        "response exceeded 1 MiB",
                    ));
                }
                body.extend_from_slice(&chunk);
            }

            self.metrics.record_mineskin_response_bytes(body.len());
            let buffered = BufferedResponse { status, body };
            if !status.is_success() {
                return Err(parse_error_response(context, &buffered));
            }
            let response = parse_response(context, &buffered)?;
            if response.success == Some(false) {
                return Err(MineSkinClientError::upstream(
                    StatusCode::BAD_GATEWAY,
                    response.into_error_message(),
                ));
            }

            Ok(response)
        }
        .await;
        let rate_limited = result
            .as_ref()
            .err()
            .and_then(MineSkinClientError::upstream_status)
            == Some(StatusCode::TOO_MANY_REQUESTS);
        self.metrics
            .finish_mineskin_request(started_at.elapsed(), result.is_err(), rate_limited);
        result
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
    last_failure: Option<CachedFailure>,
}

#[derive(Default)]
struct GrantCacheState {
    value: Option<(bool, Instant)>,
    last_failure: Option<CachedFailure>,
}

/// A failed `MineSkin` request, kept so other callers can get the same error
/// without another request.
#[derive(Clone)]
struct CachedFailure {
    failed_at: Instant,
    configuration_error: bool,
    upstream_status: StatusCode,
    message: String,
}

impl CachedFailure {
    fn new(error: &MineSkinClientError) -> Self {
        // reqwest includes the upstream URL in its error text, so keep only the
        // generic message that clients see for transport errors.
        let message = match error {
            MineSkinClientError::Request(_) => "MineSkin request failed".to_owned(),
            MineSkinClientError::Configuration(_)
            | MineSkinClientError::UnexpectedResponse { .. }
            | MineSkinClientError::Upstream { .. }
            | MineSkinClientError::Crypto(_)
            | MineSkinClientError::InvalidUpload(_) => error.to_string(),
        };
        Self {
            failed_at: Instant::now(),
            configuration_error: error.is_configuration_error(),
            upstream_status: error.upstream_status().unwrap_or(StatusCode::BAD_GATEWAY),
            message,
        }
    }

    fn is_recent(&self) -> bool {
        self.failed_at.elapsed() < FAILURE_RETRY_DELAY
    }

    fn to_error(&self) -> MineSkinClientError {
        if self.configuration_error {
            return MineSkinClientError::Configuration(self.message.clone());
        }

        MineSkinClientError::upstream(self.upstream_status, self.message.clone())
    }
}

/// Builds the `MineSkin` authorization header. Returns `None` when the key is
/// missing, blank, or not a valid header value; the startup warnings say which.
pub(crate) fn authorization_header(api_key: Option<&str>) -> Option<HeaderValue> {
    let raw_key = api_key?.trim();
    // Accept the key with or without a "Bearer " prefix, in any letter case.
    let token = raw_key
        .get(..7)
        .filter(|prefix| prefix.eq_ignore_ascii_case("bearer "))
        .and_then(|_| raw_key.get(7..))
        .map_or(raw_key, str::trim_start);
    if token.is_empty() || token.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let mut header = HeaderValue::from_str(&format!("Bearer {token}")).ok()?;
    header.set_sensitive(true);
    Some(header)
}

struct BufferedResponse {
    status: StatusCode,
    body: Vec<u8>,
}

fn parse_response(
    context: &'static str,
    response: &BufferedResponse,
) -> Result<MineSkinResponse, MineSkinClientError> {
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

/// Keeps the upstream status even when a proxy or CDN in front of `MineSkin`
/// returns an error page that is not JSON.
fn parse_error_response(context: &'static str, response: &BufferedResponse) -> MineSkinClientError {
    match serde_json::from_slice::<MineSkinResponse>(&response.body) {
        Ok(body) => MineSkinClientError::upstream(response.status, body.into_error_message()),
        Err(source) => {
            warn!(
                context,
                status = %response.status,
                response_size = response.body.len(),
                %source,
                "MineSkin returned a non-JSON error response"
            );
            MineSkinClientError::upstream(
                response.status,
                format!("MineSkin request failed with status {}", response.status),
            )
        }
    }
}

fn normalize_texture_url(value: &str) -> Result<String, MineSkinClientError> {
    let mut url = Url::parse(value).map_err(|error| {
        tracing::debug!(%error, "Invalid MineSkin cape URL");
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

    /// Returns whether a job status request may succeed when retried:
    /// request failures, timeouts, rate limits, and upstream server errors.
    fn is_transient(&self) -> bool {
        match self {
            Self::Request(_) => true,
            Self::Upstream { status, .. } => {
                *status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
            }
            Self::Configuration(_)
            | Self::UnexpectedResponse { .. }
            | Self::Crypto(_)
            | Self::InvalidUpload(_) => false,
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
#[expect(
    clippy::panic_in_result_fn,
    reason = "tests assert inside Result-returning test functions"
)]
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
    async fn rejects_completed_jobs_without_a_valid_skin_reference() -> TestResult {
        for result in [None, Some(Value::Null), Some(json!("invalid-uuid"))] {
            let server = MockServer::start().await;
            let mut job = json!({ "id": "job-result", "status": "completed" });
            if let Some(result) = result {
                job.as_object_mut()
                    .ok_or("job is not an object")?
                    .insert("result".to_owned(), result);
            }
            Mock::given(method("GET"))
                .and(path("/v2/queue/job-result"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "success": true,
                    "job": job,
                    "skin": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            let config = AppConfig::for_tests(Url::parse(&format!("{}/v2/", server.uri()))?);
            let client = MineSkinClient::new(
                &config,
                UrlCipher::new(config.aes_secret_key.as_deref()),
                Arc::new(Metrics::default()),
            )?;

            let result = client.poll_job("job-result", Duration::ZERO).await;
            assert!(matches!(
                result,
                Err(MineSkinClientError::Upstream {
                    status: StatusCode::BAD_GATEWAY,
                    ..
                } | MineSkinClientError::Crypto(crate::crypto::CryptoError::InvalidUuid))
            ));
            server.verify().await;
        }
        Ok(())
    }

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
        let client = MineSkinClient::new(
            &config,
            UrlCipher::new(config.aes_secret_key.as_deref()),
            Arc::new(Metrics::default()),
        )?;

        let initial = client.supported_capes().await?;
        let stale = client.supported_capes().await?;

        assert!(Arc::ptr_eq(&initial, &stale));
        server.verify().await;
        Ok(())
    }

    #[test]
    fn encodes_job_ids_as_single_path_segments() -> TestResult {
        let config = AppConfig::for_tests(Url::parse("https://example.com/v2/")?);
        let client = MineSkinClient::new(
            &config,
            UrlCipher::new(config.aes_secret_key.as_deref()),
            Arc::new(Metrics::default()),
        )?;

        let url = client.job_endpoint("job/with?syntax")?;

        assert_eq!(url.path(), "/v2/queue/job%2Fwith%3Fsyntax");
        Ok(())
    }

    #[test]
    fn builds_the_authorization_header_only_from_a_usable_key() {
        for key in [None, Some(""), Some("  "), Some("Bearer"), Some("bad\nkey")] {
            assert!(
                authorization_header(key).is_none(),
                "{key:?} should not produce a header"
            );
        }
        for key in [
            "secret",
            " secret ",
            "Bearer secret",
            "bearer secret",
            "BEARER  secret",
        ] {
            assert_eq!(
                authorization_header(Some(key))
                    .and_then(|header| header.to_str().ok().map(str::to_owned))
                    .as_deref(),
                Some("Bearer secret"),
                "{key:?} should produce a bearer header"
            );
        }
    }

    const SKIN_UUID: &str = "123e4567-e89b-12d3-a456-426614174002";

    fn poll_test_client(
        server: &MockServer,
        max_poll_duration: Duration,
    ) -> Result<MineSkinClient, Box<dyn Error + Send + Sync>> {
        let mut config = AppConfig::for_tests(Url::parse(&format!("{}/v2/", server.uri()))?);
        config.max_poll_duration = max_poll_duration;
        Ok(MineSkinClient::new(
            &config,
            UrlCipher::new(config.aes_secret_key.as_deref()),
            Arc::new(Metrics::default()),
        )?)
    }

    async fn mount_job_response(server: &MockServer, priority: u8, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path("/v2/queue/job-poll"))
            .respond_with(response)
            .with_priority(priority)
            .up_to_n_times(1)
            .expect(1)
            .mount(server)
            .await;
    }

    fn completed_job() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "job": { "id": "job-poll", "status": "completed", "result": SKIN_UUID },
            "skin": { "uuid": SKIN_UUID }
        }))
    }

    #[tokio::test]
    async fn keeps_polling_after_transient_job_status_errors() -> TestResult {
        let server = MockServer::start().await;
        mount_job_response(
            &server,
            1,
            ResponseTemplate::new(429).set_body_json(json!({
                "success": false,
                "errors": [{ "message": "rate limited" }]
            })),
        )
        .await;
        mount_job_response(
            &server,
            2,
            ResponseTemplate::new(503).set_body_string("<html>unavailable</html>"),
        )
        .await;
        mount_job_response(
            &server,
            3,
            ResponseTemplate::new(200).set_delay(Duration::from_secs(5)),
        )
        .await;
        mount_job_response(&server, 4, completed_job()).await;
        let mut config = AppConfig::for_tests(Url::parse(&format!("{}/v2/", server.uri()))?);
        config.request_timeout = Duration::from_millis(100);
        let client = MineSkinClient::new(
            &config,
            UrlCipher::new(config.aes_secret_key.as_deref()),
            Arc::new(Metrics::default()),
        )?;

        let response = client.poll_job("job-poll", Duration::ZERO).await?;

        assert!(response.skin.is_some());
        server.verify().await;
        Ok(())
    }

    #[tokio::test]
    async fn stops_polling_on_client_errors() -> TestResult {
        let server = MockServer::start().await;
        mount_job_response(
            &server,
            1,
            ResponseTemplate::new(404).set_body_json(json!({
                "success": false,
                "errors": [{ "code": "job_not_found", "message": "Job not found" }]
            })),
        )
        .await;
        let client = poll_test_client(&server, Duration::from_secs(1))?;

        let result = client.poll_job("job-poll", Duration::ZERO).await;

        assert!(matches!(
            result,
            Err(MineSkinClientError::Upstream { status: StatusCode::NOT_FOUND, ref message })
                if message == "Job not found"
        ));
        server.verify().await;
        Ok(())
    }

    #[tokio::test]
    async fn times_out_when_job_status_errors_persist() -> TestResult {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/queue/job-poll"))
            .respond_with(ResponseTemplate::new(502))
            .mount(&server)
            .await;
        let client = poll_test_client(&server, Duration::from_millis(200))?;

        let result = client.poll_job("job-poll", Duration::from_millis(10)).await;

        assert!(matches!(
            result,
            Err(MineSkinClientError::Upstream {
                status: StatusCode::GATEWAY_TIMEOUT,
                ..
            })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn reports_the_upstream_reason_for_failed_jobs() -> TestResult {
        let server = MockServer::start().await;
        mount_job_response(
            &server,
            1,
            ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "messages": [{ "code": "job_failed", "message": "Job failed" }],
                "job": { "id": "job-poll", "status": "failed" },
                "errors": [{ "code": "invalid_image", "message": "Invalid skin image" }]
            })),
        )
        .await;
        let client = poll_test_client(&server, Duration::from_secs(1))?;

        let result = client.poll_job("job-poll", Duration::ZERO).await;

        assert!(matches!(
            result,
            Err(MineSkinClientError::Upstream { status: StatusCode::BAD_GATEWAY, ref message })
                if message == "Invalid skin image"
        ));
        server.verify().await;
        Ok(())
    }

    #[tokio::test]
    async fn keeps_the_generic_message_for_failed_jobs_without_errors() -> TestResult {
        let server = MockServer::start().await;
        mount_job_response(
            &server,
            1,
            ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "job": { "id": "job-poll", "status": "failed" }
            })),
        )
        .await;
        let client = poll_test_client(&server, Duration::from_secs(1))?;

        let result = client.poll_job("job-poll", Duration::ZERO).await;

        assert!(matches!(
            result,
            Err(MineSkinClientError::Upstream { status: StatusCode::BAD_GATEWAY, ref message })
                if message == "MineSkin job failed to complete"
        ));
        server.verify().await;
        Ok(())
    }

    #[tokio::test]
    async fn keeps_polling_through_unknown_job_statuses() -> TestResult {
        let server = MockServer::start().await;
        for priority in 1..=2 {
            mount_job_response(
                &server,
                priority,
                ResponseTemplate::new(200).set_body_json(json!({
                    "success": true,
                    "job": { "id": "job-poll", "status": "rendering" }
                })),
            )
            .await;
        }
        mount_job_response(&server, 3, completed_job()).await;
        let client = poll_test_client(&server, Duration::from_secs(1))?;

        let response = client.poll_job("job-poll", Duration::ZERO).await?;

        assert!(response.skin.is_some());
        server.verify().await;
        Ok(())
    }

    fn cache_test_client(server_uri: &str) -> Result<MineSkinClient, Box<dyn Error + Send + Sync>> {
        let config = AppConfig::for_tests(Url::parse(&format!("{server_uri}/v2/"))?);
        Ok(MineSkinClient::new(
            &config,
            UrlCipher::new(config.aes_secret_key.as_deref()),
            Arc::new(Metrics::default()),
        )?)
    }

    #[tokio::test]
    async fn repeats_a_cached_cape_failure_with_the_original_message() -> TestResult {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/capes"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .expect(1)
            .mount(&server)
            .await;
        let client = cache_test_client(&server.uri())?;

        let first = client
            .supported_capes()
            .await
            .err()
            .ok_or("expected an error")?;
        let cached = client
            .supported_capes()
            .await
            .err()
            .ok_or("expected an error")?;

        assert_eq!(cached.to_string(), first.to_string());
        server.verify().await;
        Ok(())
    }

    #[tokio::test]
    async fn keeps_the_upstream_url_out_of_cached_transport_failures() -> TestResult {
        // Nothing listens on the port after the listener is dropped.
        let address = std::net::TcpListener::bind("127.0.0.1:0")?
            .local_addr()?
            .to_string();
        let client = cache_test_client(&format!("http://{address}"))?;

        let first = client
            .supported_capes()
            .await
            .err()
            .ok_or("expected an error")?;
        let cached = client
            .supported_capes()
            .await
            .err()
            .ok_or("expected an error")?;

        assert!(matches!(first, MineSkinClientError::Request(_)));
        assert_eq!(cached.to_string(), "MineSkin request failed");
        assert!(!cached.to_string().contains(&address));
        Ok(())
    }

    #[tokio::test]
    async fn shares_one_grant_request_between_concurrent_callers() -> TestResult {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/me"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "success": true, "grants": { "capes": true } }))
                    .set_delay(Duration::from_millis(200)),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = cache_test_client(&server.uri())?;

        let results = futures_util::future::join_all((0..5).map(|_| client.has_cape_grant())).await;

        for result in results {
            assert!(result?);
        }
        server.verify().await;
        Ok(())
    }

    #[tokio::test]
    async fn serves_the_last_grant_while_a_refresh_fails() -> TestResult {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/me"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "success": true, "grants": { "capes": true } })),
            )
            .up_to_n_times(1)
            .with_priority(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v2/me"))
            .respond_with(ResponseTemplate::new(429).set_body_json(json!({
                "success": false,
                "errors": [{ "message": "rate limited" }]
            })))
            .with_priority(2)
            .expect(1)
            .mount(&server)
            .await;
        let mut config = AppConfig::for_tests(Url::parse(&format!("{}/v2/", server.uri()))?);
        config.cape_cache_ttl = Duration::ZERO;
        let client = MineSkinClient::new(
            &config,
            UrlCipher::new(config.aes_secret_key.as_deref()),
            Arc::new(Metrics::default()),
        )?;

        // The first call caches the grant. The expired cache then fails to
        // refresh, and the next calls get the last grant without another
        // request until the retry delay passes.
        for _ in 0..3 {
            assert!(
                client.has_cape_grant().await?,
                "the last grant should be served"
            );
        }
        server.verify().await;
        Ok(())
    }

    #[tokio::test]
    async fn shares_a_grant_failure_until_the_retry_delay_passes() -> TestResult {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/me"))
            .respond_with(
                ResponseTemplate::new(503)
                    .set_body_json(json!({
                        "success": false,
                        "errors": [{ "message": "maintenance" }]
                    }))
                    .set_delay(Duration::from_millis(200)),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = cache_test_client(&server.uri())?;

        let mut results =
            futures_util::future::join_all((0..5).map(|_| client.has_cape_grant())).await;
        // Within the retry delay, later callers get the cached failure too.
        results.push(client.has_cape_grant().await);

        for result in results {
            assert!(matches!(
                result,
                Err(MineSkinClientError::Upstream {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    ref message
                }) if message == "maintenance"
            ));
        }
        server.verify().await;
        Ok(())
    }
}
