#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::{sync::Arc, time::Duration};

use axum::{
    Json,
    extract::{
        Multipart, Path, Query, State,
        multipart::{MultipartError, MultipartRejection},
        rejection::{PathRejection, QueryRejection},
    },
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use tracing::warn;
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
const INVALID_WAIT_MS_MESSAGE: &str = "waitMs must be an integer between 250 and 10000";
const MAXIMUM_FILE_SIZE: usize = 5 * 1024 * 1024;
const MAXIMUM_JOB_ID_LENGTH: usize = 64;
const MAXIMUM_NAME_LENGTH: usize = 48;
const INVALID_NAME_MESSAGE: &str =
    "name must be at most 48 letters, digits, spaces, dots, hyphens, or underscores";
const INVALID_JOB_ID_MESSAGE: &str =
    "jobId must contain 1 to 64 letters, digits, hyphens, or underscores";

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
#[expect(dead_code, reason = "used only to describe the OpenAPI schema")]
pub struct UploadRequest {
    #[schema(value_type = String, format = Binary)]
    file: String,
    variant: UploadVariant,
    #[schema(min_length = 1, max_length = 48, pattern = "^[A-Za-z0-9_. -]+$")]
    name: Option<String>,
    #[schema(value_type = String, format = Uuid)]
    cape_uuid: String,
}

#[derive(Debug, ToSchema)]
#[serde(rename_all = "lowercase")]
#[expect(dead_code, reason = "used only to describe the OpenAPI schema")]
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
    summary = "Upload a skin to MineSkin with a required cape and wait for completion.",
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
        (status = 408, description = "The upload body was not received in time.", body = ErrorResponse),
        (status = 413, description = "The skin file or the upload body exceeds the size limit.", body = ErrorResponse),
        (status = 429, description = "MineSkin rate limit exceeded.", body = ErrorResponse),
        (status = 500, description = "MineSkin proxy configuration error.", body = ErrorResponse),
        (status = 502, description = "MineSkin returned an error.", body = ErrorResponse),
        (status = 503, description = "The upload concurrency limit has been reached.", body = ErrorResponse),
        (status = 504, description = "Timed out waiting for MineSkin, or the upload exceeded its execution deadline.", body = ErrorResponse)
    )
)]
pub async fn upload_skin(
    State(state): State<Arc<AppState>>,
    query: Result<Query<UploadQuery>, QueryRejection>,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Json<SanitizedResponse>, ApiError> {
    // waitMs is the only query parameter, so any rejection means it is invalid.
    let Query(query) =
        query.map_err(|error| ApiError::bad_request(INVALID_WAIT_MS_MESSAGE).with_source(error))?;
    let poll_interval = match query.wait_ms {
        Some(wait_ms) => validate_poll_interval(wait_ms)?,
        None => state.mineskin.default_poll_interval(),
    };
    let upload = timeout(
        state.upload_body_timeout,
        parse_upload(multipart.map_err(|error| {
            ApiError::bad_request("Failed to parse multipart form data").with_source(error)
        })?),
    )
    .await
    .map_err(|error| {
        ApiError::new(StatusCode::REQUEST_TIMEOUT, "Skin upload body timed out").with_source(error)
    })??;

    let supported_capes = state
        .mineskin
        .supported_capes()
        .await
        .map_err(map_upload_error)?;
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
        .map_err(map_upload_error)?;
    let response = state
        .mineskin
        .poll_job(&job.id, poll_interval)
        .await
        .map_err(map_upload_error)?;

    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/mineskin/jobs/{jobId}",
    tag = "mineskin",
    summary = "Retrieve the status of a MineSkin job.",
    params(
        (
            "jobId" = String,
            Path,
            pattern = "^[A-Za-z0-9_-]{1,64}$",
            description = "Identifier of the MineSkin job."
        )
    ),
    responses(
        (status = 200, description = "Job retrieved successfully.", body = SanitizedResponse),
        (status = 400, description = "Invalid job identifier.", body = ErrorResponse),
        (status = 404, description = "Job could not be found.", body = ErrorResponse),
        (status = 429, description = "MineSkin rate limit exceeded.", body = ErrorResponse),
        (status = 500, description = "MineSkin proxy configuration error.", body = ErrorResponse),
        (status = 502, description = "MineSkin returned an error.", body = ErrorResponse)
    )
)]
pub async fn job_status(
    State(state): State<Arc<AppState>>,
    path: Result<Path<JobPath>, PathRejection>,
) -> Result<Json<SanitizedResponse>, ApiError> {
    let Path(path) =
        path.map_err(|error| ApiError::bad_request(INVALID_JOB_ID_MESSAGE).with_source(error))?;
    if !is_valid_job_id(&path.job_id) {
        return Err(ApiError::bad_request(INVALID_JOB_ID_MESSAGE));
    }

    let job = state
        .mineskin
        .fetch_job(&path.job_id)
        .await
        .map_err(map_job_error)?;
    let response = state.mineskin.sanitize_job(job).map_err(map_job_error)?;

    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/mineskin/capes",
    tag = "mineskin",
    summary = "List MineSkin capes supported by the proxy.",
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
        .map_err(map_proxy_error)?;

    Ok(Json(CapesResponse { capes }))
}

#[utoipa::path(
    get,
    path = "/mineskin/cape-support",
    tag = "mineskin",
    summary = "Check whether the configured MineSkin account has cape grants and list supported capes.",
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
    // Without a grant the capes are not returned, so do not fetch them: a cape
    // list failure would otherwise fail the whole response for nothing.
    let has_cape_grant = state
        .mineskin
        .has_cape_grant()
        .await
        .map_err(map_proxy_error)?;
    let capes = if has_cape_grant {
        state
            .mineskin
            .supported_capes()
            .await
            .map_err(map_proxy_error)?
    } else {
        Arc::from([])
    };

    Ok(Json(CapeSupportResponse {
        has_cape_grant,
        capes,
    }))
}

#[utoipa::path(
    get,
    path = "/mineskin/decrypt-url",
    tag = "mineskin",
    summary = "Decrypt an encrypted MineSkin URL back to the original URL.",
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
    let Query(query) = query
        .map_err(|error| ApiError::bad_request("encryptedUrl is required").with_source(error))?;
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
    let mut cape_uuid = None;
    let mut cape_alias = None;

    while let Some(field) = multipart.next_field().await.map_err(map_multipart_error)? {
        let Some(field_name) = field.name().map(str::to_owned) else {
            continue;
        };

        match field_name.as_str() {
            "file" if file.is_none() && field.file_name().is_some() => {
                let file_name = field.file_name().map(str::to_owned);
                let content_type = field.content_type().map(str::to_owned);
                let bytes = field.bytes().await.map_err(map_multipart_error)?;
                if bytes.len() > MAXIMUM_FILE_SIZE {
                    return Err(ApiError::new(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Skin file must not exceed 5 MiB",
                    ));
                }
                file = Some((bytes, file_name, content_type));
            }
            "variant" if variant.is_none() => {
                variant = Some(read_text_field(field).await?);
            }
            "name" if name.is_none() => {
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
    let name = name.map(|value| value.trim().to_owned());
    if name.as_ref().is_some_and(String::is_empty) {
        return Err(ApiError::bad_request(
            "name must contain at least 1 character",
        ));
    }
    // MineSkin rejects other names with a generic "Validation error", so check
    // its rule here and say what is wrong.
    if name.as_ref().is_some_and(|value| {
        value.len() > MAXIMUM_NAME_LENGTH
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b' ')
            })
    }) {
        return Err(ApiError::bad_request(INVALID_NAME_MESSAGE));
    }

    let cape_uuid = cape_uuid
        .or(cape_alias)
        .ok_or_else(|| ApiError::bad_request("capeUuid is required"))?;
    let cape_uuid = Uuid::parse_str(&cape_uuid)
        .map_err(|error| ApiError::bad_request("capeUuid must be a valid UUID").with_source(error))?
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
    field.text().await.map_err(map_multipart_error)
}

fn map_multipart_error(error: MultipartError) -> ApiError {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Skin upload body exceeds the size limit",
        )
        .with_source(error);
    }

    ApiError::bad_request("Failed to parse multipart form data").with_source(error)
}

/// `MineSkin` job IDs are opaque tokens. Accept only URL-safe characters so an ID
/// such as `..` cannot change the upstream path after percent-decoding.
fn is_valid_job_id(job_id: &str) -> bool {
    (1..=MAXIMUM_JOB_ID_LENGTH).contains(&job_id.len())
        && job_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn validate_poll_interval(milliseconds: u64) -> Result<Duration, ApiError> {
    if !(MINIMUM_POLL_INTERVAL_MS..=MAXIMUM_POLL_INTERVAL_MS).contains(&milliseconds) {
        return Err(ApiError::bad_request(INVALID_WAIT_MS_MESSAGE));
    }

    Ok(Duration::from_millis(milliseconds))
}

fn map_upload_error(error: MineSkinClientError) -> ApiError {
    let status = if error.is_configuration_error() {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        match &error {
            MineSkinClientError::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
            MineSkinClientError::InvalidUpload(_) => StatusCode::BAD_REQUEST,
            MineSkinClientError::Upstream { status, .. } => match *status {
                StatusCode::BAD_REQUEST
                | StatusCode::TOO_MANY_REQUESTS
                | StatusCode::GATEWAY_TIMEOUT => *status,
                _ => StatusCode::BAD_GATEWAY,
            },
            MineSkinClientError::Request(_)
            | MineSkinClientError::UnexpectedResponse { .. }
            | MineSkinClientError::Crypto(_) => StatusCode::BAD_GATEWAY,
        }
    };

    mineskin_error(error, status)
}

fn map_job_error(error: MineSkinClientError) -> ApiError {
    let status = if error.is_configuration_error() {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        match error.upstream_status() {
            Some(status @ (StatusCode::NOT_FOUND | StatusCode::TOO_MANY_REQUESTS)) => status,
            _ => StatusCode::BAD_GATEWAY,
        }
    };

    mineskin_error(error, status)
}

fn map_proxy_error(error: MineSkinClientError) -> ApiError {
    let status = if error.is_configuration_error() {
        StatusCode::INTERNAL_SERVER_ERROR
    } else if error.upstream_status() == Some(StatusCode::TOO_MANY_REQUESTS) {
        StatusCode::TOO_MANY_REQUESTS
    } else {
        StatusCode::BAD_GATEWAY
    };

    mineskin_error(error, status)
}

/// Builds the client response. `ApiError` logs it once, with the `MineSkin` error
/// as its source. Transport errors get a generic message because reqwest
/// includes the upstream URL in its error text.
fn mineskin_error(error: MineSkinClientError, status: StatusCode) -> ApiError {
    // A 429 comes from the proxy's shared MineSkin account, not the client, so
    // operators need to see it even though it is a 4xx.
    if status == StatusCode::TOO_MANY_REQUESTS {
        warn!(%error, "MineSkin rate limit reached");
    }
    let message = match &error {
        MineSkinClientError::Request(_) => "MineSkin request failed".to_owned(),
        MineSkinClientError::Configuration(_)
        | MineSkinClientError::UnexpectedResponse { .. }
        | MineSkinClientError::Upstream { .. }
        | MineSkinClientError::Crypto(_)
        | MineSkinClientError::InvalidUpload(_) => error.to_string(),
    };

    ApiError::new(status, message).with_source(error)
}
