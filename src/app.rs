use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Router,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State},
    http::{
        HeaderName, HeaderValue, Method, StatusCode,
        header::{LOCATION, RETRY_AFTER},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use tokio::{sync::Semaphore, time::timeout};
use tower_http::{
    cors::{Any, CorsLayer},
    request_id::{MakeRequestId, MakeRequestUuid},
};
use tracing::{Instrument, debug, info, info_span};
use utoipa::{
    OpenApi,
    openapi::{OpenApi as OpenApiDocument, Server},
};
use utoipa_swagger_ui::{Config, SwaggerUi};

use crate::{
    config::AppConfig,
    crypto::UrlCipher,
    error::{ApiError, ErrorCode, ErrorResponse},
    metrics::Metrics,
    mineskin::MineSkinClient,
    routes::{
        __path_cape_support, __path_decrypt_url, __path_health, __path_job_status, __path_ready,
        __path_supported_capes, __path_upload_skin, DecryptedUrlResponse, HealthResponse,
        ReadinessResponse, UploadRequest, cape_support, decrypt_url, health, job_status, ready,
        supported_capes, upload_skin,
    },
};

const MAXIMUM_REQUEST_BODY_SIZE: usize = 6 * 1024 * 1024;

/// Cloudflare's ID for a request, which Axolotl reuses as its own request ID.
const CF_RAY: HeaderName = HeaderName::from_static("cf-ray");
/// The longest `cf-ray` value that Axolotl accepts as a request ID. Real ray
/// IDs have about 20 characters, such as `8f1e2d3c4b5a6978-FRA`.
const MAXIMUM_REQUEST_ID_LENGTH: usize = 64;
const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// How long a client should wait before it retries an upload that was rejected
/// because every upload slot was busy. Uploads usually take a few seconds.
const UPLOAD_BUSY_RETRY_AFTER: Duration = Duration::from_secs(5);

/// Paths that container probes call often. Their access log lines use the
/// debug level, so they do not flood the log.
const PROBE_PATHS: [&str; 2] = ["/health", "/ready"];

pub(crate) struct AppState {
    pub mineskin: MineSkinClient,
    pub cipher: UrlCipher,
    pub upload_body_timeout: Duration,
    /// Required environment variables that are missing or unusable.
    pub missing_configuration: Vec<&'static str>,
    upload_slots: Arc<Semaphore>,
    upload_request_timeout: Duration,
}

#[derive(OpenApi)]
#[openapi(
    info(title = "Axolotl", description = "A lightweight MineSkin proxy API"),
    paths(
        health,
        ready,
        upload_skin,
        job_status,
        supported_capes,
        cape_support,
        decrypt_url
    ),
    components(schemas(HealthResponse, ReadinessResponse, UploadRequest, DecryptedUrlResponse, ErrorResponse)),
    tags(
        (
            name = "mineskin",
            description = "MineSkin proxy endpoints that inject the configured API key."
        ),
        (name = "health", description = "Liveness and readiness checks")
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
        missing_configuration: missing_configuration(config),
        upload_slots: Arc::new(Semaphore::new(config.max_concurrent_uploads)),
        upload_request_timeout: config
            .max_poll_duration
            .saturating_add(config.request_timeout.saturating_mul(3)),
    });
    let openapi = api_document(config.port);

    let api = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/ready", get(ready))
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
        .merge(Router::from(swagger_ui(openapi)).layer(middleware::map_response(swagger_not_found)))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAXIMUM_REQUEST_BODY_SIZE))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers(Any)
                // Browsers hide other response headers from scripts unless
                // they are exposed.
                .expose_headers([X_REQUEST_ID, RETRY_AFTER]),
        )
        .layer(middleware::from_fn_with_state(metrics, record_metrics))
        .layer(middleware::from_fn(log_request));

    Ok(api)
}

/// Lists the required environment variables that the service cannot use.
///
/// It applies the same checks as the code that uses each value, so readiness
/// agrees with whether requests can succeed.
fn missing_configuration(config: &AppConfig) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if crate::mineskin::authorization_header(config.mineskin_api_key.as_deref()).is_none() {
        missing.push("MINESKIN_API_KEY");
    }
    // `UrlCipher::new` ignores a blank secret, exactly like this check.
    if !config.has_aes_secret_key() {
        missing.push("AES_SECRET_KEY");
    }
    missing
}

/// Runs the request in a span that carries its ID, logs one line when the
/// response is ready and returns the ID in the `x-request-id` header.
///
/// The line has the path without the query string, because `decrypt-url`
/// receives encrypted skin URLs in the query.
async fn log_request(request: Request, next: Next) -> Response {
    let request_id = request_id(&request);
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let span = info_span!(
        "request",
        request_id = %request_id.to_str().unwrap_or_default(),
    );

    let started_at = Instant::now();
    let mut response = next.run(request).instrument(span.clone()).await;
    // Round to microseconds so the log shows 0.038, not 0.037873000000000004.
    let latency_ms = (started_at.elapsed().as_secs_f64() * 1_000_000.0).round() / 1000.0;
    let status = response.status().as_u16();
    span.in_scope(|| {
        if PROBE_PATHS.contains(&path.as_str()) {
            debug!(%method, %path, status, latency_ms, "Request completed");
        } else {
            info!(%method, %path, status, latency_ms, "Request completed");
        }
    });

    response.headers_mut().insert(X_REQUEST_ID, request_id);
    response
}

/// Returns the request's `cf-ray` value, or a random UUID when it has none.
///
/// Cloudflare sets `cf-ray` on every request it forwards. Requests that reach
/// the container directly, such as probes, can send any value, so a value that
/// does not look like a ray ID also gets a random UUID. This keeps long or
/// unusual values out of the logs and the response headers.
fn request_id(request: &Request) -> HeaderValue {
    request
        .headers()
        .get(CF_RAY)
        .filter(|value| is_valid_request_id(value.as_bytes()))
        .cloned()
        .or_else(|| {
            MakeRequestUuid
                .make_request_id(request)
                .map(|id| id.header_value().clone())
        })
        // `MakeRequestUuid` always returns an ID.
        .unwrap_or_else(|| HeaderValue::from_static("unknown"))
}

fn is_valid_request_id(value: &[u8]) -> bool {
    (1..=MAXIMUM_REQUEST_ID_LENGTH).contains(&value.len())
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

async fn record_metrics(
    State(metrics): State<Arc<Metrics>>,
    request: Request,
    next: Next,
) -> Response {
    let path = metrics_path(request.method(), request.uri().path()).to_owned();
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

/// Returns the path to record for a request.
///
/// Requests with a method that an endpoint does not serve, such as CORS
/// preflights and 405 responses, must not count as uploads or decryptions.
/// They are recorded under a path that no endpoint uses.
fn metrics_path<'a>(method: &Method, path: &'a str) -> &'a str {
    let served = match path {
        "/mineskin/skins" => method == Method::POST,
        "/mineskin/decrypt-url" => method == Method::GET || method == Method::HEAD,
        _ => true,
    };
    if served { path } else { "" }
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
        .with_code(ErrorCode::UploadBusy)
        .with_retry_after(UPLOAD_BUSY_RETRY_AFTER)
        .into_response();
    };

    match timeout(state.upload_request_timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => ApiError::new(StatusCode::GATEWAY_TIMEOUT, "Skin upload request timed out")
            .with_code(ErrorCode::UploadTimeout)
            .into_response(),
    }
}

/// Serves the API document at `/openapi` and Swagger UI at `/swagger/`.
///
/// The base layout drops the "Explore" bar, which only invites loading other
/// specs. The Schemas section starts collapsed so the operations come first,
/// and each response shows how long it took, since uploads can take seconds.
fn swagger_ui(openapi: OpenApiDocument) -> SwaggerUi {
    SwaggerUi::new("/swagger").url("/openapi", openapi).config(
        Config::default()
            .use_base_layout()
            .default_models_expand_depth(0)
            .display_request_duration(true),
    )
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
        [(LOCATION, HeaderValue::from_static("/swagger/"))],
    )
}

async fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "Not Found")
}

/// Replaces the empty 404 that Swagger UI returns for unknown files with the
/// JSON error that every other route returns.
async fn swagger_not_found(response: Response) -> Response {
    if response.status() == StatusCode::NOT_FOUND {
        not_found().await.into_response()
    } else {
        response
    }
}

async fn method_not_allowed() -> ApiError {
    ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode, header, header::HeaderValue},
    };
    use tower::ServiceExt;
    use url::Url;

    use super::{build_app, client_ip};
    use crate::{config::AppConfig, metrics::Metrics};

    #[tokio::test]
    async fn does_not_count_preflights_or_wrong_methods_as_endpoint_requests() {
        let metrics = Arc::new(Metrics::default());
        let config = AppConfig::for_tests(Url::parse("http://127.0.0.1:9/v2/").expect("valid URL"));
        let app = build_app(&config, Arc::clone(&metrics)).expect("app should build");

        let preflight = Request::options("/mineskin/skins")
            .header(header::ORIGIN, "https://example.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .body(Body::empty())
            .expect("valid request");
        let wrong_method = Request::get("/mineskin/skins")
            .body(Body::empty())
            .expect("valid request");
        let decrypt_preflight = Request::options("/mineskin/decrypt-url")
            .header(header::ORIGIN, "https://example.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .body(Body::empty())
            .expect("valid request");
        for (request, status) in [
            (preflight, StatusCode::OK),
            (wrong_method, StatusCode::METHOD_NOT_ALLOWED),
            (decrypt_preflight, StatusCode::OK),
        ] {
            let response = app.clone().oneshot(request).await.expect("infallible");
            assert_eq!(response.status(), status);
        }

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.requests, 3);
        assert_eq!(snapshot.upload.requests, 0);
        assert_eq!(snapshot.decrypt.requests, 0);
        assert_eq!(snapshot.other_requests, 3);
    }

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

    fn test_config() -> AppConfig {
        AppConfig::for_tests(Url::parse("http://127.0.0.1:9/v2/").expect("valid URL"))
    }

    async fn json_body(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        serde_json::from_slice(&bytes).expect("body should be JSON")
    }

    #[tokio::test]
    async fn reports_unusable_configuration_by_name_without_values() {
        let mut config = test_config();
        // The client rejects a bare "Bearer" and the cipher ignores a blank secret.
        config.mineskin_api_key = Some("Bearer ".to_owned());
        config.aes_secret_key = Some("   ".to_owned());
        let app = build_app(&config, Arc::new(Metrics::default())).expect("app should build");

        let response = app
            .clone()
            .oneshot(
                Request::get("/ready")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            json_body(response).await,
            serde_json::json!({
                "status": "NOT_READY",
                "missing": ["MINESKIN_API_KEY", "AES_SECRET_KEY"]
            })
        );

        let health = app
            .oneshot(
                Request::get("/health")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("infallible");
        assert_eq!(
            health.status(),
            StatusCode::OK,
            "liveness must not depend on configuration"
        );
    }

    #[tokio::test]
    async fn names_only_the_missing_variable() {
        let mut config = test_config();
        config.aes_secret_key = None;
        let app = build_app(&config, Arc::new(Metrics::default())).expect("app should build");

        let response = app
            .oneshot(
                Request::get("/ready")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            json_body(response).await,
            serde_json::json!({ "status": "NOT_READY", "missing": ["AES_SECRET_KEY"] })
        );
    }

    #[tokio::test]
    async fn asks_clients_to_retry_when_every_upload_slot_is_busy() {
        let mut config = test_config();
        config.max_concurrent_uploads = 0;
        let app = build_app(&config, Arc::new(Metrics::default())).expect("app should build");

        let response = app
            .oneshot(
                Request::post("/mineskin/skins")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("5"))
        );
        assert_eq!(
            json_body(response).await,
            serde_json::json!({
                "error": "Too many skin uploads are already in progress",
                "code": "upload_busy"
            })
        );
    }
}
