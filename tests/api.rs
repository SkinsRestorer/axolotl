use std::{collections::BTreeSet, error::Error, io, time::Duration};

use axolotl::{AppConfig, api_document, build_app};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, Response, StatusCode, header},
};
use serde_json::{Value, json};
use tokio::time::{sleep, timeout};
use tower::ServiceExt;
use url::{Url, form_urlencoded};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header as header_matcher, method, path},
};

const LEGACY_ENCRYPTED_URL: &str = "skinsrestorer-axolotl://AAECAwQFBgcICQoLDA0OD8imM586fmS6OpsiL50KsnvRWjSo4S7vTKK3sl3b3l7RG1vToG52Tih6IdrpltHyHA==";
const SKIN_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
const CAPE_UUID: &str = "123e4567-e89b-12d3-a456-426614174001";

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn serves_health_and_json_not_found_responses() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;

    let health = send(&app, Request::get("/health").body(Body::empty())?).await?;
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(json_body(health).await?, json!({ "status": "UP" }));

    let missing = send(&app, Request::get("/does-not-exist").body(Body::empty())?).await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(missing).await?, json!({ "error": "Not Found" }));
    Ok(())
}

#[tokio::test]
async fn decrypts_urls_created_by_the_legacy_service() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("encryptedUrl", LEGACY_ENCRYPTED_URL)
        .finish();
    let response = send(
        &app,
        Request::get(format!("/mineskin/decrypt-url?{query}")).body(Body::empty())?,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await?,
        json!({ "url": format!("https://minesk.in/{SKIN_UUID}") })
    );
    Ok(())
}

#[tokio::test]
async fn caches_supported_capes_and_normalizes_texture_urls() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/capes"))
        .and(header_matcher("authorization", "Bearer test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "capes": [
                {
                    "uuid": CAPE_UUID,
                    "alias": "founders",
                    "url": "http://textures.example/cape.png",
                    "supported": true
                },
                {
                    "uuid": "123e4567-e89b-12d3-a456-426614174002",
                    "alias": "unsupported",
                    "url": "https://textures.example/other.png",
                    "supported": false
                }
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;

    for _ in 0..2 {
        let response = send(&app, Request::get("/mineskin/capes").body(Body::empty())?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await?,
            json!({
                "capes": [{
                    "uuid": CAPE_UUID,
                    "alias": "founders",
                    "url": "https://textures.example/cape.png"
                }]
            })
        );
    }

    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn maps_mineskin_job_not_found_to_the_public_contract() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/queue/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "success": false,
            "errors": [{ "message": "Job not found" }]
        })))
        .mount(&server)
        .await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;

    let response = send(
        &app,
        Request::get("/mineskin/jobs/missing").body(Body::empty())?,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "Job not found" })
    );
    Ok(())
}

#[tokio::test]
async fn accepts_new_upstream_job_statuses_without_parsing_unused_fields() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/queue/job-new"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "job": {
                "id": "job-new",
                "status": "scheduled"
            },
            "skin": null
        })))
        .expect(1)
        .mount(&server)
        .await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;

    let response = send(
        &app,
        Request::get("/mineskin/jobs/job-new").body(Body::empty())?,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await?,
        json!({
            "success": true,
            "skin": null,
            "warnings": [],
            "messages": []
        })
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn deduplicates_concurrent_failed_cape_refreshes() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/capes"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_delay(Duration::from_millis(50))
                .set_body_json(json!({
                    "success": false,
                    "errors": [{ "message": "temporary failure" }]
                })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;

    let first_request = Request::get("/mineskin/capes").body(Body::empty())?;
    let second_request = Request::get("/mineskin/capes").body(Body::empty())?;
    let (first, second) = tokio::join!(send(&app, first_request), send(&app, second_request));

    assert_eq!(first?.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(second?.status(), StatusCode::BAD_GATEWAY);
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn rejects_oversized_upstream_responses() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/capes"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(vec![b'x'; 1024 * 1024 + 1], "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;

    let response = send(&app, Request::get("/mineskin/capes").body(Body::empty())?).await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn rejects_non_https_cape_urls() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/capes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "capes": [{
                "uuid": CAPE_UUID,
                "alias": "founders",
                "url": "ftp://textures.example/cape.png",
                "supported": true
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;

    let response = send(&app, Request::get("/mineskin/capes").body(Body::empty())?).await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn forwards_uploads_and_returns_an_encrypted_skin_url() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/capes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "capes": [{
                "uuid": CAPE_UUID,
                "alias": "founders",
                "url": "https://textures.example/cape.png",
                "supported": true
            }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/queue"))
        .and(header_matcher("authorization", "Bearer test-api-key"))
        .and(body_string_contains("name=\"variant\"\r\n\r\nslim"))
        .and(body_string_contains(format!(
            "name=\"cape\"\r\n\r\n{CAPE_UUID}"
        )))
        .and(body_string_contains(
            "name=\"name\"\r\n\r\nintegration_skin",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "job": {
                "id": "job-1",
                "status": "waiting",
                "result": null
            }
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/queue/job-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(completed_job_response()))
        .expect(1)
        .mount(&server)
        .await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;
    let boundary = "axolotl-integration-boundary";
    let body = multipart_upload_with_cape(boundary, &CAPE_UUID.to_uppercase());

    let response = send(
        &app,
        Request::post("/mineskin/skins?waitMs=250")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))?,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let response = json_body(response).await?;
    assert_eq!(
        response
            .get("success")
            .ok_or_else(|| io::Error::other("response did not contain success"))?,
        &json!(true)
    );
    assert_eq!(
        response
            .get("warnings")
            .ok_or_else(|| io::Error::other("response did not contain warnings"))?,
        &json!([])
    );
    assert_eq!(
        response
            .get("messages")
            .ok_or_else(|| io::Error::other("response did not contain messages"))?,
        &json!([])
    );
    let encrypted_url = response
        .get("skin")
        .and_then(|skin| skin.get("url"))
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("response did not contain an encrypted skin URL"))?;
    assert!(encrypted_url.starts_with("skinsrestorer-axolotl://v2/"));

    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("encryptedUrl", encrypted_url)
        .finish();
    let decrypted = send(
        &app,
        Request::get(format!("/mineskin/decrypt-url?{query}")).body(Body::empty())?,
    )
    .await?;
    assert_eq!(decrypted.status(), StatusCode::OK);
    assert_eq!(
        json_body(decrypted).await?,
        json!({ "url": format!("https://minesk.in/{SKIN_UUID}") })
    );

    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn rejects_uploads_above_the_concurrency_limit_before_processing() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/capes"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(500))
                .set_body_json(json!({
                    "success": true,
                    "capes": [{
                        "uuid": CAPE_UUID,
                        "alias": "founders",
                        "url": "https://textures.example/cape.png",
                        "supported": true
                    }]
                })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;

    let first_app = app.clone();
    let first_boundary = "axolotl-concurrency-first";
    let first_request = Request::post("/mineskin/skins?waitMs=250")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={first_boundary}"),
        )
        .body(Body::from(multipart_upload(first_boundary)))?;
    let first = tokio::spawn(async move { send(&first_app, first_request).await });
    wait_for_upstream_path(&server, "/v2/capes").await?;

    let second_boundary = "axolotl-concurrency-second";
    let second = send(
        &app,
        Request::post("/mineskin/skins?waitMs=250")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={second_boundary}"),
            )
            .body(Body::from(multipart_upload(second_boundary)))?,
    )
    .await?;

    assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
    first.abort();
    let _ = first.await;
    server.verify().await;
    Ok(())
}

#[test]
fn openapi_document_exposes_the_complete_public_surface() -> TestResult {
    let value = serde_json::to_value(api_document(4242))?;
    let paths = value
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| io::Error::other("OpenAPI document did not contain a paths object"))?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected = [
        "/health",
        "/mineskin/cape-support",
        "/mineskin/capes",
        "/mineskin/decrypt-url",
        "/mineskin/jobs/{jobId}",
        "/mineskin/skins",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();

    let openapi_version = value
        .get("openapi")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("OpenAPI document did not contain a version"))?;
    let local_server_url = value
        .get("servers")
        .and_then(Value::as_array)
        .and_then(|servers| servers.get(1))
        .and_then(|server| server.get("url"))
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("OpenAPI document did not contain the local server URL"))?;

    assert_eq!(openapi_version, "3.1.0");
    assert_eq!(paths, expected);
    assert_eq!(local_server_url, "http://localhost:4242");
    Ok(())
}

fn test_app(base_url: &str) -> TestResult<Router> {
    let config = AppConfig::for_tests(Url::parse(base_url)?);
    Ok(build_app(&config)?)
}

async fn send(app: &Router, request: Request<Body>) -> TestResult<Response<Body>> {
    Ok(app.clone().oneshot(request).await?)
}

async fn json_body(response: Response<Body>) -> TestResult<Value> {
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn completed_job_response() -> Value {
    json!({
        "success": true,
        "job": {
            "id": "job-1",
            "status": "completed",
            "result": SKIN_UUID
        },
        "skin": {
            "uuid": SKIN_UUID,
            "name": "integration_skin",
            "visibility": "unlisted",
            "variant": "slim",
            "texture": {
                "data": {
                    "value": "texture-value",
                    "signature": "texture-signature"
                },
                "hash": {
                    "skin": "skin-hash",
                    "cape": "cape-hash"
                },
                "url": {
                    "skin": "https://textures.example/skin.png",
                    "cape": "https://textures.example/cape.png"
                }
            },
            "generator": {
                "version": "2.0",
                "timestamp": 1,
                "duration": 2,
                "account": "account",
                "server": "server"
            },
            "views": 0,
            "duplicate": false
        },
        "rateLimit": null,
        "usage": null,
        "warnings": [],
        "messages": []
    })
}

fn multipart_upload(boundary: &str) -> String {
    multipart_upload_with_cape(boundary, CAPE_UUID)
}

fn multipart_upload_with_cape(boundary: &str, cape_uuid: &str) -> String {
    format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"file\"; filename=\"skin.png\"\r\n\
         Content-Type: image/png\r\n\r\n\
         png-bytes\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; name=\"variant\"\r\n\r\n\
         slim\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; name=\"name\"\r\n\r\n\
         integration_skin\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; name=\"capeUuid\"\r\n\r\n\
         {cape_uuid}\r\n\
         --{boundary}--\r\n"
    )
}

async fn wait_for_upstream_path(server: &MockServer, expected_path: &str) -> TestResult {
    timeout(Duration::from_secs(2), async {
        loop {
            if server.received_requests().await.is_some_and(|requests| {
                requests
                    .iter()
                    .any(|request| request.url.path() == expected_path)
            }) {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;

    Ok(())
}
