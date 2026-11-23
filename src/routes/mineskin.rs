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
    crypto::{CryptoError, UrlCipher},
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
/// A valid skin ID, encrypted only to check that URL encryption is configured.
const ENCRYPTION_PROBE_SKIN_ID: &str = "00000000000000000000000000000000";

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

/// Multipart form fields of a skin upload. Unknown fields are ignored, and only
/// the first copy of a repeated field is used.
#[derive(Debug, ToSchema)]
#[schema(rename_all = "camelCase")]
#[expect(dead_code, reason = "used only to describe the OpenAPI schema")]
pub struct UploadRequest {
    /// Skin image, usually a 64x64 PNG. At most 5 MiB.
    #[schema(value_type = String, format = Binary)]
    file: String,
    variant: UploadVariant,
    /// Optional skin name. Leading and trailing spaces are removed.
    #[schema(
        min_length = 1,
        max_length = 48,
        pattern = "^[A-Za-z0-9_. -]+$",
        nullable = false,
        example = "My Skin"
    )]
    name: Option<String>,
    /// UUID of a cape listed by `GET /mineskin/capes`. The form field `cape` is
    /// accepted as an alias.
    #[schema(value_type = String, format = Uuid, example = "123e4567-e89b-12d3-a456-426614174001")]
    cape_uuid: String,
}

/// Skin model: `classic` for 4-pixel arms (Steve), `slim` for 3-pixel arms (Alex).
#[derive(Debug, ToSchema)]
#[serde(rename_all = "lowercase")]
#[expect(dead_code, reason = "used only to describe the OpenAPI schema")]
enum UploadVariant {
    Classic,
    Slim,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DecryptedUrlResponse {
    /// Skin URL on minesk.in, with the skin ID as 32 hex digits.
    #[schema(example = "https://minesk.in/123e4567e89b12d3a456426614174000")]
    url: String,
}

#[utoipa::path(
    post,
    path = "/mineskin/skins",
    tag = "mineskin",
    summary = "Upload a skin to MineSkin with a required cape and wait for completion.",
    description = "Checks that the cape is in `GET /mineskin/capes`, queues the skin on MineSkin, \
and polls the job until it finishes. The response holds the encrypted skin URL, which \
`GET /mineskin/decrypt-url` turns back into a MineSkin URL. If the job is not done after 5 \
minutes, the request fails with a 504.",
    params(
        (
            "waitMs" = Option<u64>,
            Query,
            minimum = 250,
            maximum = 10000,
            description = "How long to wait between job status checks, in milliseconds. \
Defaults to 1000.",
            example = 1000
        )
    ),
    request_body(content = UploadRequest, content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "The skin was generated. `skin.url` is the encrypted skin URL.", body = SanitizedResponse),
        (status = 400, description = "A form field or `waitMs` is invalid, the cape is not supported, or MineSkin rejected the skin.", body = ErrorResponse),
        (status = 408, description = "The upload body was not received in time.", body = ErrorResponse),
        (status = 413, description = "The skin file or the upload body exceeds the size limit.", body = ErrorResponse),
        (status = 429, description = "The proxy's MineSkin account is rate limited.", body = ErrorResponse),
        (status = 500, description = "The proxy has no usable MineSkin API key or AES secret key.", body = ErrorResponse),
        (status = 502, description = "MineSkin returned an error or an unreadable response, or the job failed.", body = ErrorResponse),
        (status = 503, description = "Too many uploads are in progress. Retry later.", body = ErrorResponse),
        (status = 504, description = "MineSkin did not finish the job in time, or the upload exceeded its execution deadline.", body = ErrorResponse)
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
            ApiError::bad_request("Content-Type must be multipart/form-data with a boundary")
                .with_source(error)
        })?),
    )
    .await
    .map_err(|error| {
        ApiError::new(StatusCode::REQUEST_TIMEOUT, "Skin upload body timed out").with_source(error)
    })??;
    ensure_url_encryption(&state.cipher)?;

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
        .map_err(map_enqueue_error)?;
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
    description = "Asks MineSkin for the job once and does not wait for it to finish.",
    params(
        (
            "jobId" = String,
            Path,
            pattern = "^[A-Za-z0-9_-]{1,64}$",
            description = "MineSkin job ID: 1 to 64 letters, digits, hyphens, or underscores."
        )
    ),
    responses(
        (status = 200, description = "The job exists. `skin` is null until the job completes, then `skin.url` is the encrypted skin URL.", body = SanitizedResponse),
        (status = 400, description = "The job ID is invalid.", body = ErrorResponse),
        (status = 404, description = "MineSkin has no job with this ID.", body = ErrorResponse),
        (status = 429, description = "The proxy's MineSkin account is rate limited.", body = ErrorResponse),
        (status = 500, description = "The proxy has no usable MineSkin API key or AES secret key.", body = ErrorResponse),
        (status = 502, description = "MineSkin returned an error or an unreadable response, or the job failed.", body = ErrorResponse)
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
    description = "Lists the capes that MineSkin marks as supported. Use a cape's `uuid` as \
`capeUuid` when uploading. The list is cached, and a stale list is served while MineSkin fails.",
    responses(
        (status = 200, description = "The supported capes.", body = CapesResponse),
        (status = 429, description = "The proxy's MineSkin account is rate limited.", body = ErrorResponse),
        (status = 500, description = "The proxy has no usable MineSkin API key or AES secret key.", body = ErrorResponse),
        (status = 502, description = "MineSkin returned an error or an unreadable response.", body = ErrorResponse)
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
    description = "`capes` is empty when `hasCapeGrant` is false. Otherwise it matches \
`GET /mineskin/capes`.",
    responses(
        (status = 200, description = "Whether the account may use capes, and the supported capes.", body = CapeSupportResponse),
        (status = 429, description = "The proxy's MineSkin account is rate limited.", body = ErrorResponse),
        (status = 500, description = "The proxy has no usable MineSkin API key or AES secret key.", body = ErrorResponse),
        (status = 502, description = "MineSkin returned an error or an unreadable response.", body = ErrorResponse)
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
        (
            "encryptedUrl" = String,
            Query,
            description = "Encrypted skin URL from an upload or job response. It starts with \
`skinsrestorer-axolotl://`. Percent-encode it in the query string."
        )
    ),
    responses(
        (status = 200, description = "The decrypted MineSkin URL.", body = DecryptedUrlResponse),
        (status = 400, description = "`encryptedUrl` is missing, repeated, or not a URL that this proxy encrypted.", body = ErrorResponse),
        (status = 500, description = "The proxy has no AES secret key.", body = ErrorResponse)
    )
)]
pub async fn decrypt_url(
    State(state): State<Arc<AppState>>,
    query: Result<Query<DecryptUrlQuery>, QueryRejection>,
) -> Result<Json<DecryptedUrlResponse>, ApiError> {
    let Query(query) = query.map_err(|error| {
        // encryptedUrl is the only parameter, so it is missing or repeated.
        ApiError::bad_request("encryptedUrl must be provided exactly once").with_source(error)
    })?;
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
            // The file name is optional: the MineSkin client falls back to "skin.png".
            "file" if file.is_none() => {
                let file_name = field.file_name().map(str::to_owned);
                let content_type = field.content_type().map(str::to_owned);
                let bytes = field.bytes().await.map_err(map_multipart_error)?;
                if bytes.is_empty() {
                    return Err(ApiError::bad_request("A skin file must be provided"));
                }
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
        return Err(ApiError::bad_request("name must not be blank"));
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

/// Fails when the skin URL could not be encrypted. Checked before queueing, because
/// a queued upload uses `MineSkin` quota even if the response then fails.
fn ensure_url_encryption(cipher: &UrlCipher) -> Result<(), ApiError> {
    match cipher.encrypt_uuid(ENCRYPTION_PROBE_SKIN_ID) {
        Err(error @ CryptoError::MissingConfiguration) => {
            Err(ApiError::internal(error.to_string()).with_source(error))
        }
        _ => Ok(()),
    }
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

/// Maps the queue request error. Only this request carries the client's skin,
/// so only its 400 means that the client sent something invalid.
fn map_enqueue_error(error: MineSkinClientError) -> ApiError {
    let is_client_error = matches!(error, MineSkinClientError::InvalidUpload(_))
        || error.upstream_status() == Some(StatusCode::BAD_REQUEST);
    if is_client_error {
        return mineskin_error(error, StatusCode::BAD_REQUEST);
    }

    map_upload_error(error)
}

/// Maps errors of the other upload steps. A 400 from the cape list or a job
/// status poll means the proxy sent a bad request, not the client, so it
/// becomes a 502.
fn map_upload_error(error: MineSkinClientError) -> ApiError {
    let status = if error.is_configuration_error() {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        match &error {
            MineSkinClientError::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
            MineSkinClientError::Upstream { status, .. } => match *status {
                StatusCode::TOO_MANY_REQUESTS | StatusCode::GATEWAY_TIMEOUT => *status,
                _ => StatusCode::BAD_GATEWAY,
            },
            MineSkinClientError::Request(_)
            | MineSkinClientError::UnexpectedResponse { .. }
            | MineSkinClientError::Crypto(_)
            | MineSkinClientError::InvalidUpload(_) => StatusCode::BAD_GATEWAY,
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

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "tests assert inside Result-returning test functions"
)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use serde_json::{Value, json};
    use tower::ServiceExt;
    use url::Url;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};

    use crate::{app::build_app, config::AppConfig, metrics::Metrics};

    #[tokio::test]
    async fn rejects_uploads_before_calling_mineskin_when_encryption_is_not_configured()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let mut config = AppConfig::for_tests(Url::parse(&format!("{}/v2/", server.uri()))?);
        config.aes_secret_key = None;
        let app = build_app(&config, Arc::new(Metrics::default()))?;
        let boundary = "axolotl-no-aes-key";
        let body = format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"skin.png\"\r\n\
             Content-Type: image/png\r\n\r\n\
             png-bytes\r\n\
             --{boundary}\r\n\
             Content-Disposition: form-data; name=\"variant\"\r\n\r\n\
             classic\r\n\
             --{boundary}\r\n\
             Content-Disposition: form-data; name=\"capeUuid\"\r\n\r\n\
             123e4567-e89b-12d3-a456-426614174001\r\n\
             --{boundary}--\r\n"
        );

        let response = app
            .oneshot(
                Request::post("/mineskin/skins")
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(body, json!({ "error": "URL encryption is not configured" }));
        server.verify().await;
        Ok(())
    }
}
