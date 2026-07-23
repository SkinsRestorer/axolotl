use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    /// Current health status.
    status: &'static str,
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    description = "Health check endpoint",
    responses(
        (status = 200, description = "Successful response", body = HealthResponse)
    )
)]
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "UP" })
}
