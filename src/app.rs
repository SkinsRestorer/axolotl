use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State},
    http::{
        HeaderValue, Method, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use tokio::{sync::Semaphore, time::timeout};
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
    error::{ApiError, ErrorResponse},
    metrics::Metrics,
    mineskin::MineSkinClient,
    routes::{
        __path_cape_support, __path_decrypt_url, __path_health, __path_job_status,
        __path_supported_capes, __path_upload_skin, DecryptedUrlResponse, HealthResponse,
        UploadRequest, cape_support, decrypt_url, health, job_status, supported_capes, upload_skin,
    },
};

const MAXIMUM_REQUEST_BODY_SIZE: usize = 6 * 1024 * 1024;

pub(crate) struct AppState {
    pub mineskin: MineSkinClient,
    pub cipher: UrlCipher,
    pub upload_body_timeout: Duration,
    upload_slots: Arc<Semaphore>,
    upload_request_timeout: Duration,
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
pub fn build_app(
    config: &AppConfig,
    metrics: Arc<Metrics>,
) -> Result<Router, crate::mineskin::MineSkinClientError> {
    let cipher = UrlCipher::new(config.aes_secret_key.as_deref());
    let state = Arc::new(AppState {
        mineskin: MineSkinClient::new(config, cipher.clone(), Arc::clone(&metrics))?,
        cipher,
        upload_body_timeout: config.request_timeout,
        upload_slots: Arc::new(Semaphore::new(config.max_concurrent_uploads)),
        upload_request_timeout: config
            .max_poll_duration
            .saturating_add(config.request_timeout.saturating_mul(3)),
    });
    let openapi = api_document(config.port);

    let api = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route(
            "/mineskin/skins",
            post(upload_skin).route_layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                guard_upload,
            )),
        )
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
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(metrics, record_metrics));

    Ok(api)
}

async fn record_metrics(
    State(metrics): State<Arc<Metrics>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    let client_ip = client_ip(&request);
    let started_at = Instant::now();
    let response = next.run(request).await;
    metrics.record_request(
        &path,
        response.status().as_u16(),
        client_ip,
        started_at.elapsed(),
    );
    response
}

fn client_ip(request: &Request) -> Option<IpAddr> {
    forwarded_ip(request, "cf-connecting-ip")
        .or_else(|| {
            request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(address)| address.ip())
        })
        .map(normalize_ip)
}

fn forwarded_ip(request: &Request, header: &'static str) -> Option<IpAddr> {
    request
        .headers()
        .get(header)?
        .to_str()
        .ok()?
        .split(',')
        .next()?
        .trim()
        .parse()
        .ok()
}

fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address @ IpAddr::V4(_) => address,
    }
}

async fn guard_upload(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(_permit) = Arc::clone(&state.upload_slots).try_acquire_owned() else {
        return ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many skin uploads are already in progress",
        )
        .into_response();
    };

    match timeout(state.upload_request_timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => ApiError::new(StatusCode::REQUEST_TIMEOUT, "Skin upload request timed out")
            .into_response(),
    }
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, header::HeaderValue},
    };

    use super::client_ip;

    #[test]
    fn prefers_cloudflare_client_ip_and_normalizes_mapped_ipv4() {
        let mut request = Request::new(Body::empty());
        request.headers_mut().insert(
            "cf-connecting-ip",
            HeaderValue::from_static("::ffff:192.0.2.10"),
        );
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((Ipv4Addr::LOCALHOST, 1234))));

        assert_eq!(
            client_ip(&request),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        );
    }
}
