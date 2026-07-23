use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    http::{
        HeaderValue, Method, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    },
    response::IntoResponse,
    routing::{get, post},
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use utoipa::{
    OpenApi,
    openapi::{OpenApi as OpenApiDocument, Server},
};
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    config::AppConfig,
    crypto::UrlCipher,
    error::ErrorResponse,
    mineskin::MineSkinClient,
    routes::{
        __path_cape_support, __path_decrypt_url, __path_health, __path_job_status,
        __path_supported_capes, __path_upload_skin, DecryptedUrlResponse, HealthResponse,
        UploadRequest, cape_support, decrypt_url, health, job_status, supported_capes, upload_skin,
    },
};

const MAXIMUM_REQUEST_BODY_SIZE: usize = 6 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct AppState {
    pub mineskin: MineSkinClient,
    pub cipher: UrlCipher,
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Axolotl",
        version = "1.0.0",
        description = "A lightweight MineSkin proxy API"
    ),
    paths(
        health,
        upload_skin,
        job_status,
        supported_capes,
        cape_support,
        decrypt_url
    ),
    components(schemas(HealthResponse, UploadRequest, DecryptedUrlResponse, ErrorResponse)),
    tags(
        (name = "health", description = "Health check endpoint"),
        (
            name = "mineskin",
            description = "MineSkin proxy endpoints that inject the configured API key."
        )
    )
)]
struct ApiDoc;

/// Builds the Axolotl HTTP router from application configuration.
///
/// # Errors
///
/// Returns an error when the outbound `MineSkin` HTTP client cannot be created.
pub fn build_app(config: &AppConfig) -> Result<Router, crate::mineskin::MineSkinClientError> {
    let cipher = UrlCipher::new(config.aes_secret_key.as_deref());
    let state = AppState {
        mineskin: MineSkinClient::new(config, cipher.clone())?,
        cipher,
    };
    let openapi = api_document(config.port);

    let api = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/mineskin/skins", post(upload_skin))
        .route("/mineskin/jobs/{jobId}", get(job_status))
        .route("/mineskin/capes", get(supported_capes))
        .route("/mineskin/cape-support", get(cape_support))
        .route("/mineskin/decrypt-url", get(decrypt_url))
        .merge(SwaggerUi::new("/swagger").url("/openapi", openapi))
        .fallback(not_found)
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAXIMUM_REQUEST_BODY_SIZE))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http());

    Ok(api)
}

#[must_use]
pub fn api_document(port: u16) -> OpenApiDocument {
    let mut document = ApiDoc::openapi();
    let mut production = Server::new("https://axolotl.skinsrestorer.net");
    production.description = Some("Main Server".to_owned());
    let mut local = Server::new(format!("http://localhost:{port}"));
    local.description = Some("Local Server".to_owned());
    document.servers = Some(vec![production, local]);
    document
}

async fn root() -> impl IntoResponse {
    (
        StatusCode::FOUND,
        [(LOCATION, HeaderValue::from_static("/swagger"))],
    )
}

async fn not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
        Json(ErrorResponse {
            error: "Not Found".to_owned(),
        }),
    )
}
