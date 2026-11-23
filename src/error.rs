use std::time::Duration;

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header::RETRY_AFTER},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tracing::{debug, error, warn};
use utoipa::ToSchema;

/// Stable, machine-readable error code. Clients should branch on this value
/// instead of on the `error` text, which may change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// `waitMs` is not an integer between 250 and 10000.
    InvalidWaitMs,
    /// The upload form is malformed, or a field is missing or invalid.
    InvalidUpload,
    /// `MineSkin` rejected the skin, for example because the image is not a
    /// valid skin.
    SkinRejected,
    /// The requested cape is not in `GET /mineskin/capes`.
    UnsupportedCape,
    /// The job ID has a wrong length or contains other characters.
    InvalidJobId,
    /// `encryptedUrl` is missing, repeated, or not a URL that this proxy encrypted.
    InvalidEncryptedUrl,
    /// The skin file or the upload body exceeds the size limit.
    PayloadTooLarge,
    /// The upload body was not received in time.
    UploadBodyTimeout,
    /// Too many uploads are in progress.
    UploadBusy,
    /// The upload exceeded its execution deadline.
    UploadTimeout,
    /// `MineSkin` has no job with this ID.
    JobNotFound,
    /// `MineSkin` did not finish the job in time.
    JobTimeout,
    /// The proxy's `MineSkin` account is rate limited.
    MineskinRateLimited,
    /// `MineSkin` returned an error or an unreadable response, or the job failed.
    MineskinError,
    /// The proxy has no usable `MineSkin` API key or AES secret key.
    NotConfigured,
    /// No route matches the path.
    NotFound,
    /// The route does not support the request method.
    MethodNotAllowed,
    /// Fallback for a 400 without a more specific code.
    BadRequest,
    /// Fallback for a 408 without a more specific code.
    RequestTimeout,
    /// Fallback for a 429 without a more specific code.
    TooManyRequests,
    /// Fallback for a 503 without a more specific code.
    ServiceUnavailable,
    /// Fallback for a 504 without a more specific code.
    GatewayTimeout,
    /// Fallback for any other 4xx status.
    ClientError,
    /// Fallback for any other status.
    InternalError,
}

impl ErrorCode {
    /// The fallback code for errors that do not set a specific one.
    #[must_use]
    pub fn for_status(status: StatusCode) -> Self {
        match status {
            StatusCode::BAD_REQUEST => Self::BadRequest,
            StatusCode::NOT_FOUND => Self::NotFound,
            StatusCode::METHOD_NOT_ALLOWED => Self::MethodNotAllowed,
            StatusCode::REQUEST_TIMEOUT => Self::RequestTimeout,
            StatusCode::PAYLOAD_TOO_LARGE => Self::PayloadTooLarge,
            StatusCode::TOO_MANY_REQUESTS => Self::TooManyRequests,
            StatusCode::SERVICE_UNAVAILABLE => Self::ServiceUnavailable,
            StatusCode::GATEWAY_TIMEOUT => Self::GatewayTimeout,
            status if status.is_client_error() => Self::ClientError,
            _ => Self::InternalError,
        }
    }
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: ErrorCode,
    message: String,
    retry_after: Option<Duration>,
    job_id: Option<String>,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl ApiError {
    /// Creates an error with the fallback code for `status`. Use
    /// [`ApiError::with_code`] to set a specific code.
    #[must_use]
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            code: ErrorCode::for_status(status),
            message: message.into(),
            retry_after: None,
            job_id: None,
            source: None,
        }
    }

    #[must_use]
    pub const fn with_code(mut self, code: ErrorCode) -> Self {
        self.code = code;
        self
    }

    /// Sets the `Retry-After` header, rounded up to whole seconds and at least 1.
    #[must_use]
    pub const fn with_retry_after(mut self, delay: Duration) -> Self {
        self.retry_after = Some(delay);
        self
    }

    /// Names the `MineSkin` job that the failed request had already queued, so
    /// the client can check it later instead of uploading again.
    #[must_use]
    pub fn with_job_id(mut self, job_id: impl Into<String>) -> Self {
        self.job_id = Some(job_id.into());
        self
    }

    pub(crate) fn with_source(
        mut self,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    #[must_use]
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status.as_u16();
        let source = self
            .source
            .as_deref()
            .map(|source| source as &dyn std::error::Error);
        if self.code == ErrorCode::UploadBusy {
            warn!(status, message = %self.message, "Request rejected");
        } else if self.status.is_server_error() {
            // Upstream failures are also logged where they happen, with their own
            // context. This line records the response that the client receives.
            error!(status, message = %self.message, error = source, "Request failed");
        } else if let Some(source) = source {
            debug!(status, message = %self.message, error = source, "Request rejected");
        }

        let mut response = (
            self.status,
            Json(ErrorResponse {
                error: self.message,
                code: self.code,
                job_id: self.job_id,
            }),
        )
            .into_response();
        if let Some(delay) = self.retry_after {
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from(retry_after_seconds(delay)));
        }
        response
    }
}

fn retry_after_seconds(delay: Duration) -> u64 {
    let seconds = delay.as_secs();
    let seconds = if delay.subsec_nanos() > 0 {
        seconds.saturating_add(1)
    } else {
        seconds
    };
    seconds.max(1)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    /// Human-readable description of the error.
    pub error: String,
    /// Machine-readable error code.
    pub code: ErrorCode,
    /// The `MineSkin` job that an upload had already queued before it failed,
    /// for example on `job_timeout`. Pass it to `GET /mineskin/jobs/{jobId}`
    /// instead of uploading again. Absent when no job was queued.
    #[serde(rename = "jobId", skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub job_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        serde_json::from_slice(&bytes).expect("body should be JSON")
    }

    #[tokio::test]
    async fn server_error_keeps_status_and_body() {
        let response = ApiError::new(StatusCode::GATEWAY_TIMEOUT, "Skin upload request timed out")
            .with_source(std::io::Error::other("deadline elapsed"))
            .into_response();

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            body_json(response).await,
            serde_json::json!({
                "error": "Skin upload request timed out",
                "code": "gateway_timeout"
            })
        );
    }

    #[tokio::test]
    async fn client_error_keeps_status_and_body() {
        let response = ApiError::bad_request("Failed to parse multipart form data")
            .with_source(std::io::Error::other("unexpected end of stream"))
            .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(response).await,
            serde_json::json!({
                "error": "Failed to parse multipart form data",
                "code": "bad_request"
            })
        );
    }

    #[test]
    fn retry_after_rounds_up_to_whole_seconds_with_a_minimum_of_one() {
        let header = |delay| {
            ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate limited")
                .with_retry_after(delay)
                .into_response()
                .headers()
                .get(RETRY_AFTER)
                .cloned()
        };

        assert_eq!(header(Duration::ZERO), Some(HeaderValue::from_static("1")));
        assert_eq!(
            header(Duration::from_millis(1500)),
            Some(HeaderValue::from_static("2"))
        );
        assert_eq!(
            header(Duration::from_secs(30)),
            Some(HeaderValue::from_static("30"))
        );
    }

    #[test]
    fn omits_retry_after_unless_set() {
        let response = ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();

        assert!(response.headers().get(RETRY_AFTER).is_none());
    }
}
