use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode};
use serde::Serialize;
use utoipa::ToSchema;

use crate::app::AppState;

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    /// Current health status.
    status: &'static str,
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    summary = "Check that the service is running.",
    responses(
        (status = 200, description = "The process is running. This is a liveness check; use /ready to check configuration.", body = HealthResponse)
    )
)]
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "UP" })
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReadinessResponse {
    /// `READY` when the service can serve every endpoint, otherwise `NOT_READY`.
    #[schema(example = "NOT_READY")]
    status: &'static str,
    /// Names of the environment variables that are missing or unusable.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(example = json!(["MINESKIN_API_KEY"]))]
    missing: Vec<&'static str>,
}

#[utoipa::path(
    get,
    path = "/ready",
    tag = "health",
    summary = "Check that the service has the configuration it needs to serve requests.",
    responses(
        (status = 200, description = "The service is ready", body = ReadinessResponse,
            example = json!({ "status": "READY" })),
        (status = 503, description = "Required configuration is missing or unusable",
            body = ReadinessResponse,
            example = json!({ "status": "NOT_READY", "missing": ["MINESKIN_API_KEY"] }))
    )
)]
pub async fn ready(State(state): State<Arc<AppState>>) -> (StatusCode, Json<ReadinessResponse>) {
    let missing = state.missing_configuration.clone();
    if missing.is_empty() {
        (
            StatusCode::OK,
            Json(ReadinessResponse {
                status: "READY",
                missing,
            }),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadinessResponse {
                status: "NOT_READY",
                missing,
            }),
        )
    }
}
