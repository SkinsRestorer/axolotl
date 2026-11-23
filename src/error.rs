use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tracing::{debug, error};
use utoipa::ToSchema;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl ApiError {
    #[must_use]
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            source: None,
        }
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
        if self.status.is_server_error() {
            // Upstream failures are also logged where they happen, with their own
            // context. This line records the response that the client receives.
            error!(status, message = %self.message, error = source, "Request failed");
        } else if let Some(source) = source {
            debug!(status, message = %self.message, error = source, "Request rejected");
        }

        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
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
            serde_json::json!({ "error": "Skin upload request timed out" })
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
            serde_json::json!({ "error": "Failed to parse multipart form data" })
        );
    }
}
