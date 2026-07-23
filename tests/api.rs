use std::collections::BTreeSet;

use axolotl::{AppConfig, api_document, build_app};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, Response, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt;
use url::{Url, form_urlencoded};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header as header_matcher, method, path},
};

const LEGACY_ENCRYPTED_URL: &str = "skinsrestorer-axolotl://AAECAwQFBgcICQoLDA0OD8imM586fmS6OpsiL50KsnvRWjSo4S7vTKK3sl3b3l7RG1vToG52Tih6IdrpltHyHA==";
const SKIN_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
const CAPE_UUID: &str = "123e4567-e89b-12d3-a456-426614174001";

#[tokio::test]
async fn serves_health_and_json_not_found_responses() {
    let app = test_app("http://127.0.0.1:9/v2/");

    let health = send(&app, Request::get("/health").body(Body::empty()).unwrap()).await;
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(json_body(health).await, json!({ "status": "UP" }));

    let missing = send(
        &app,
        Request::get("/does-not-exist").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(missing).await, json!({ "error": "Not Found" }));
}

#[tokio::test]
async fn decrypts_urls_created_by_the_legacy_service() {
    let app = test_app("http://127.0.0.1:9/v2/");
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("encryptedUrl", LEGACY_ENCRYPTED_URL)
        .finish();
    let response = send(
        &app,
        Request::get(format!("/mineskin/decrypt-url?{query}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await,
        json!({ "url": format!("https://minesk.in/{SKIN_UUID}") })
    );
}

#[tokio::test]
async fn caches_supported_capes_and_normalizes_texture_urls() {
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
    let app = test_app(&format!("{}/v2/", server.uri()));

    for _ in 0..2 {
        let response = send(
            &app,
            Request::get("/mineskin/capes").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await,
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
}

#[tokio::test]
async fn maps_mineskin_job_not_found_to_the_public_contract() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/queue/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "success": false,
            "errors": [{ "message": "Job not found" }]
        })))
        .mount(&server)
        .await;
    let app = test_app(&format!("{}/v2/", server.uri()));

    let response = send(
        &app,
        Request::get("/mineskin/jobs/missing")
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(response).await,
        json!({ "error": "Job not found" })
    );
}

#[tokio::test]
async fn forwards_uploads_and_returns_an_encrypted_skin_url() {
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
    let app = test_app(&format!("{}/v2/", server.uri()));
    let boundary = "axolotl-integration-boundary";
    let body = multipart_upload(boundary);

    let response = send(
        &app,
        Request::post("/mineskin/skins?waitMs=250")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let response = json_body(response).await;
    assert_eq!(response["success"], json!(true));
    assert_eq!(response["warnings"], json!([]));
    assert_eq!(response["messages"], json!([]));
    let encrypted_url = response["skin"]["url"].as_str().unwrap();

    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("encryptedUrl", encrypted_url)
        .finish();
    let decrypted = send(
        &app,
        Request::get(format!("/mineskin/decrypt-url?{query}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(decrypted.status(), StatusCode::OK);
    assert_eq!(
        json_body(decrypted).await,
        json!({ "url": format!("https://minesk.in/{SKIN_UUID}") })
    );

    server.verify().await;
}

#[test]
fn openapi_document_exposes_the_complete_public_surface() {
    let value = serde_json::to_value(api_document(4242)).unwrap();
    let paths = value["paths"]
        .as_object()
        .unwrap()
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

    assert_eq!(value["openapi"], "3.1.0");
    assert_eq!(paths, expected);
    assert_eq!(value["servers"][1]["url"], "http://localhost:4242");
}

fn test_app(base_url: &str) -> Router {
    let config = AppConfig::for_tests(Url::parse(base_url).unwrap());
    build_app(&config).unwrap()
}

async fn send(app: &Router, request: Request<Body>) -> Response<Body> {
    app.clone().oneshot(request).await.unwrap()
}

async fn json_body(response: Response<Body>) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
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
         {CAPE_UUID}\r\n\
         --{boundary}--\r\n"
    )
}
