use std::{sync::Arc, time::Duration};

use axum::{
    Json,
    extract::{
        Multipart, Path, Query, State, multipart::MultipartRejection, rejection::QueryRejection,
    },
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    app::AppState,
    crypto::CryptoError,
    error::{ApiError, ErrorResponse},
    mineskin::{
        CapeSupportResponse, CapesResponse, MineSkinClientError, SanitizedResponse, UploadPayload,
    },
};

const MINIMUM_POLL_INTERVAL_MS: u64 = 250;
const MAXIMUM_POLL_INTERVAL_MS: u64 = 10_000;
const MAXIMUM_FILE_SIZE: usize = 5 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadQuery {
    wait_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobPath {
    job_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptUrlQuery {
    encrypted_url: String,
}

#[derive(Debug, ToSchema)]
#[schema(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct UploadRequest {
    #[schema(value_type = String, format = Binary)]
    file: String,
    variant: UploadVariant,
    #[schema(min_length = 1, max_length = 64)]
    name: Option<String>,
    #[schema(value_type = String, format = Uuid)]
    cape_uuid: String,
}

#[derive(Debug, ToSchema)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
enum UploadVariant {
    Classic,
    Slim,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DecryptedUrlResponse {
    url: String,
}

#[utoipa::path(
    post,
    path = "/mineskin/skins",
    tag = "mineskin",
    description = "Upload a skin to MineSkin with a required cape and wait for completion.",
    params(
        (
            "waitMs" = Option<u64>,
            Query,
            minimum = 250,
            maximum = 10000,
            description = "Polling interval in milliseconds.",
            example = 1000
        )
    ),
    request_body(content = UploadRequest, content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "MineSkin job completed successfully.", body = SanitizedResponse),
        (status = 400, description = "Invalid request payload.", body = ErrorResponse),
        (status = 408, description = "The upload request exceeded its execution deadline.", body = ErrorResponse),
        (status = 429, description = "MineSkin rate limit exceeded.", body = ErrorResponse),
        (status = 500, description = "MineSkin proxy configuration error.", body = ErrorResponse),
        (status = 502, description = "MineSkin returned an error.", body = ErrorResponse),
        (status = 503, description = "The upload concurrency limit has been reached.", body = ErrorResponse),
        (status = 504, description = "Timed out waiting for MineSkin to finish processing.", body = ErrorResponse)
    )
)]
pub async fn upload_skin(
    State(state): State<Arc<AppState>>,
    query: Result<Query<UploadQuery>, QueryRejection>,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Json<SanitizedResponse>, ApiError> {
    let Query(query) = query.map_err(|error| ApiError::bad_request(error.body_text()))?;
    let poll_interval = validate_poll_interval(query.wait_ms.map_or(
        state.mineskin.default_poll_interval(),
        Duration::from_millis,
    ))?;
    let upload = timeout(
        state.upload_body_timeout,
        parse_upload(
            multipart.map_err(|_| ApiError::bad_request("Failed to parse multipart form data"))?,
        ),
    )
    .await
    .map_err(|_| ApiError::new(StatusCode::REQUEST_TIMEOUT, "Skin upload body timed out"))??;

    let supported_capes = state
        .mineskin
        .supported_capes()
        .await
        .map_err(|error| map_upload_error(&error))?;
    if !supported_capes
        .iter()
        .any(|cape| cape.uuid == upload.cape_uuid)
    {
        return Err(ApiError::bad_request("Requested cape is not supported"));
    }

    let job = state
        .mineskin
        .enqueue(upload)
        .await
        .map_err(|error| map_upload_error(&error))?;
    let response = state
        .mineskin
        .poll_job(&job.id, poll_interval)
        .await
        .map_err(|error| map_upload_error(&error))?;

    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/mineskin/jobs/{jobId}",
    tag = "mineskin",
    description = "Retrieve the status of a MineSkin job.",
    params(
        ("jobId" = String, Path, description = "Identifier of the MineSkin job.")
    ),
    responses(
        (status = 200, description = "Job retrieved successfully.", body = SanitizedResponse),
        (status = 404, description = "Job could not be found.", body = ErrorResponse),
        (status = 429, description = "MineSkin rate limit exceeded.", body = ErrorResponse),
        (status = 500, description = "MineSkin proxy configuration error.", body = ErrorResponse),
        (status = 502, description = "MineSkin returned an error.", body = ErrorResponse)
    )
)]
pub async fn job_status(
    State(state): State<Arc<AppState>>,
    Path(path): Path<JobPath>,
) -> Result<Json<SanitizedResponse>, ApiError> {
    let job = state
        .mineskin
        .fetch_job(&path.job_id)
        .await
        .map_err(|error| map_job_error(&error))?;
    let response = state
        .mineskin
        .sanitize_job(job)
        .map_err(|error| map_job_error(&error))?;

    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/mineskin/capes",
    tag = "mineskin",
    description = "List MineSkin capes supported by the proxy.",
    responses(
        (status = 200, description = "List of supported capes.", body = CapesResponse),
        (status = 429, description = "MineSkin rate limit exceeded.", body = ErrorResponse),
        (status = 500, description = "MineSkin proxy configuration error.", body = ErrorResponse),
        (status = 502, description = "MineSkin returned an error.", body = ErrorResponse)
    )
)]
pub async fn supported_capes(
    State(state): State<Arc<AppState>>,
) -> Result<Json<CapesResponse>, ApiError> {
    let capes = state
        .mineskin
        .supported_capes()
        .await
        .map_err(|error| map_proxy_error(&error))?;

    Ok(Json(CapesResponse { capes }))
}

#[utoipa::path(
    get,
    path = "/mineskin/cape-support",
    tag = "mineskin",
    description = "Check whether the configured MineSkin account has cape grants and list supported capes.",
    responses(
        (status = 200, description = "Cape support information.", body = CapeSupportResponse),
        (status = 429, description = "MineSkin rate limit exceeded.", body = ErrorResponse),
        (status = 500, description = "MineSkin proxy configuration error.", body = ErrorResponse),
        (status = 502, description = "MineSkin returned an error.", body = ErrorResponse)
    )
)]
pub async fn cape_support(
    State(state): State<Arc<AppState>>,
) -> Result<Json<CapeSupportResponse>, ApiError> {
    let (grant, capes) = tokio::join!(
        state.mineskin.has_cape_grant(),
        state.mineskin.supported_capes()
    );
    let has_cape_grant = grant.map_err(|error| map_proxy_error(&error))?;
    let capes = capes.map_err(|error| map_proxy_error(&error))?;

    Ok(Json(CapeSupportResponse {
        has_cape_grant,
        capes: if has_cape_grant { capes } else { Arc::from([]) },
    }))
}

#[utoipa::path(
    get,
    path = "/mineskin/decrypt-url",
    tag = "mineskin",
    description = "Decrypt an encrypted MineSkin URL back to the original URL.",
    params(
        ("encryptedUrl" = String, Query, description = "The encrypted URL to decrypt.")
    ),
    responses(
        (status = 200, description = "Decrypted URL.", body = DecryptedUrlResponse),
        (status = 400, description = "Invalid encrypted URL.", body = ErrorResponse),
        (status = 500, description = "Configuration error.", body = ErrorResponse)
    )
)]
pub async fn decrypt_url(
    State(state): State<Arc<AppState>>,
    query: Result<Query<DecryptUrlQuery>, QueryRejection>,
) -> Result<Json<DecryptedUrlResponse>, ApiError> {
    let Query(query) = query.map_err(|error| ApiError::bad_request(error.body_text()))?;
    let url = state
        .cipher
        .decrypt_url(&query.encrypted_url)
        .map_err(|error| match error {
            CryptoError::MissingConfiguration => ApiError::internal(error.to_string()),
            CryptoError::InvalidFormat
            | CryptoError::InvalidPayload
            | CryptoError::UnsupportedUrl
            | CryptoError::InvalidUuid
            | CryptoError::Encryption
            | CryptoError::Randomness => ApiError::bad_request(error.to_string()),
        })?;

    Ok(Json(DecryptedUrlResponse { url }))
}

async fn parse_upload(mut multipart: Multipart) -> Result<UploadPayload, ApiError> {
    let mut file = None;
    let mut variant = None;
    let mut name = None;
    let mut name_was_present = false;
    let mut cape_uuid = None;
    let mut cape_alias = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| ApiError::bad_request("Failed to parse multipart form data"))?
    {
        let Some(field_name) = field.name().map(str::to_owned) else {
            continue;
        };

        match field_name.as_str() {
            "file" if file.is_none() && field.file_name().is_some() => {
                let file_name = field.file_name().map(str::to_owned);
                let content_type = field.content_type().map(str::to_owned);
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|_| ApiError::bad_request("Failed to parse multipart form data"))?;
                if bytes.len() > MAXIMUM_FILE_SIZE {
                    return Err(ApiError::bad_request("Skin file must not exceed 5 MiB"));
                }
                file = Some((bytes, file_name, content_type));
            }
            "variant" if variant.is_none() => {
                variant = Some(read_text_field(field).await?);
            }
            "name" if !name_was_present => {
                name_was_present = true;
                name = Some(read_text_field(field).await?);
            }
            "capeUuid" if cape_uuid.is_none() => {
                cape_uuid = Some(read_text_field(field).await?);
            }
            "cape" if cape_alias.is_none() => {
                cape_alias = Some(read_text_field(field).await?);
            }
            _ => {}
        }
    }

    let (file, file_name, content_type) =
        file.ok_or_else(|| ApiError::bad_request("A skin file must be provided"))?;
    let variant = variant
        .filter(|value| matches!(value.as_str(), "classic" | "slim"))
        .ok_or_else(|| ApiError::bad_request("variant must be one of classic or slim"))?;
    let name = name
        .map(|value| value.trim().to_owned())
        .transpose_non_empty("name must contain at least 1 character")?;
    if name
        .as_ref()
        .is_some_and(|value| value.encode_utf16().count() > 64)
    {
        return Err(ApiError::bad_request(
            "name must contain at most 64 characters",
        ));
    }

    let cape_uuid = cape_uuid
        .or(cape_alias)
        .ok_or_else(|| ApiError::bad_request("capeUuid is required"))?;
    let cape_uuid = Uuid::parse_str(&cape_uuid)
        .map_err(|_| ApiError::bad_request("capeUuid must be a valid UUID"))?
        .hyphenated()
        .to_string();

    Ok(UploadPayload {
        file,
        file_name,
        content_type,
        variant,
        name,
        cape_uuid,
    })
}

async fn read_text_field(field: axum::extract::multipart::Field<'_>) -> Result<String, ApiError> {
    field
        .text()
        .await
        .map_err(|_| ApiError::bad_request("Failed to parse multipart form data"))
}

fn validate_poll_interval(interval: Duration) -> Result<Duration, ApiError> {
    let milliseconds = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
    if !(MINIMUM_POLL_INTERVAL_MS..=MAXIMUM_POLL_INTERVAL_MS).contains(&milliseconds) {
        return Err(ApiError::bad_request(
            "waitMs must be between 250 and 10000",
        ));
    }

    Ok(interval)
}

fn map_upload_error(error: &MineSkinClientError) -> ApiError {
    error!(%error, "MineSkin upload failed");

    if error.is_configuration_error() {
        return ApiError::internal(error.to_string());
    }

    match error {
        MineSkinClientError::Configuration(_) => ApiError::internal(error.to_string()),
        MineSkinClientError::InvalidUpload(_) => ApiError::bad_request(error.to_string()),
        MineSkinClientError::Upstream { status, .. } => match *status {
            StatusCode::BAD_REQUEST => ApiError::bad_request(error.to_string()),
            StatusCode::TOO_MANY_REQUESTS => {
                ApiError::new(StatusCode::TOO_MANY_REQUESTS, error.to_string())
            }
            StatusCode::GATEWAY_TIMEOUT => {
                ApiError::new(StatusCode::GATEWAY_TIMEOUT, error.to_string())
            }
            _ => ApiError::bad_gateway(error.to_string()),
        },
        MineSkinClientError::Request(_)
        | MineSkinClientError::UnexpectedResponse { .. }
        | MineSkinClientError::Crypto(_) => ApiError::bad_gateway(error.to_string()),
    }
}

fn map_job_error(error: &MineSkinClientError) -> ApiError {
    error!(%error, "Failed to fetch MineSkin job");

    if error.is_configuration_error() {
        return ApiError::internal(error.to_string());
    }
    if error.upstream_status() == Some(StatusCode::NOT_FOUND) {
        return ApiError::new(StatusCode::NOT_FOUND, error.to_string());
    }
    if error.upstream_status() == Some(StatusCode::TOO_MANY_REQUESTS) {
        return ApiError::new(StatusCode::TOO_MANY_REQUESTS, error.to_string());
    }

    ApiError::bad_gateway(error.to_string())
}

fn map_proxy_error(error: &MineSkinClientError) -> ApiError {
    error!(%error, "MineSkin proxy request failed");

    if error.is_configuration_error() {
        ApiError::internal(error.to_string())
    } else if error.upstream_status() == Some(StatusCode::TOO_MANY_REQUESTS) {
        ApiError::new(StatusCode::TOO_MANY_REQUESTS, error.to_string())
    } else {
        ApiError::bad_gateway(error.to_string())
    }
}

trait OptionalStringExt {
    fn transpose_non_empty(self, empty_message: &'static str) -> Result<Option<String>, ApiError>;
}

impl OptionalStringExt for Option<String> {
    fn transpose_non_empty(self, empty_message: &'static str) -> Result<Option<String>, ApiError> {
        match self {
            Some(value) if value.is_empty() => Err(ApiError::bad_request(empty_message)),
            value => Ok(value),
        }
    }
}
