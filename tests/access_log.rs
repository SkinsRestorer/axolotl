//! Checks the access log. This test installs the global tracing subscriber,
//! so it runs in its own test binary: a callsite that another test thread
//! registers while the subscriber is being installed can stay disabled.

#![expect(
    clippy::panic_in_result_fn,
    reason = "tests assert inside Result-returning test functions"
)]

use std::{
    error::Error,
    io,
    sync::{Arc, Mutex},
};

use axolotl::{AppConfig, Metrics, build_app};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use url::Url;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl io::Write for CapturedLog {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|error| io::Error::other(error.to_string()))?
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn logs_each_request_with_its_id_and_without_the_query_string() -> TestResult {
    let log = CapturedLog::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("axolotl=info"))
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    // MineSkin is unreachable, so the capes handler logs an error inside the
    // request.
    let app = build_app(
        &AppConfig::for_tests(Url::parse("http://127.0.0.1:9/v2/")?),
        Arc::new(Metrics::default()),
    )?;

    let probe = get_with_ray(&app, "/ready", "probe-ray").await?;
    assert_eq!(probe, StatusCode::OK);
    let decrypt = get_with_ray(
        &app,
        "/mineskin/decrypt-url?encryptedUrl=secret-encrypted-value",
        "decrypt-ray",
    )
    .await?;
    assert_eq!(decrypt, StatusCode::BAD_REQUEST);
    let capes = get_with_ray(&app, "/mineskin/capes", "capes-ray").await?;
    assert_eq!(capes, StatusCode::BAD_GATEWAY);

    let output = String::from_utf8(
        log.0
            .lock()
            .map_err(|error| io::Error::other(error.to_string()))?
            .clone(),
    )?;
    let lines_for = |request_id: &str| {
        let field = format!("request_id={request_id}");
        output
            .lines()
            .filter(|line| line.contains(&field))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };

    assert_eq!(
        lines_for("probe-ray"),
        Vec::<String>::new(),
        "probes must not log at info"
    );
    let decrypt_lines = lines_for("decrypt-ray");
    assert_eq!(decrypt_lines.len(), 1, "{decrypt_lines:?}");
    assert!(
        decrypt_lines
            .iter()
            .all(|line| line.contains("Request completed")
                && line.contains("method=GET")
                && line.contains("path=/mineskin/decrypt-url ")
                && line.contains("status=400")
                && line.contains("latency_ms=")),
        "{decrypt_lines:?}"
    );
    assert!(
        !output.contains("secret-encrypted-value"),
        "the log must not contain the query string: {output}"
    );
    let capes_lines = lines_for("capes-ray");
    assert!(
        capes_lines.len() >= 2
            && capes_lines.last().is_some_and(
                |line| line.contains("Request completed") && line.contains("status=502")
            ),
        "log lines inside a request must carry its ID: {capes_lines:?}"
    );
    Ok(())
}

/// Sends a GET request that Cloudflare forwarded with the given ray ID and
/// returns the response status.
async fn get_with_ray(app: &Router, uri: &str, ray: &str) -> TestResult<StatusCode> {
    let request = Request::get(uri)
        .header("cf-ray", ray)
        .body(Body::empty())?;
    Ok(app.clone().oneshot(request).await?.status())
}
