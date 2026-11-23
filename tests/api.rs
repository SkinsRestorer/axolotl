#![expect(
    clippy::panic_in_result_fn,
    reason = "tests assert inside Result-returning test functions"
)]

use std::{collections::BTreeSet, error::Error, io, time::Duration};

use axolotl::{AppConfig, Metrics, api_document, build_app};
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    http::{Request, Response, StatusCode, header},
};
use futures_util::{future, stream};
use serde_json::{Value, json};
use tokio::{
    sync::oneshot,
    time::{sleep, timeout},
};
use tower::ServiceExt;
use url::{Url, form_urlencoded};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header as header_matcher, method, path},
};

const LEGACY_ENCRYPTED_URL: &str = "skinsrestorer-axolotl://AAECAwQFBgcICQoLDA0OD8imM586fmS6OpsiL50KsnvRWjSo4S7vTKK3sl3b3l7RG1vToG52Tih6IdrpltHyHA==";
const SKIN_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
/// `SKIN_UUID` in `MineSkin`'s format, which decrypted URLs use.
const SKIN_ID: &str = "123e4567e89b12d3a456426614174000";
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
        json!({ "url": format!("https://minesk.in/{SKIN_ID}") })
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
async fn preserves_upstream_status_for_non_json_error_pages() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/queue/limited"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_raw("<html><body>Too Many Requests</body></html>", "text/html"),
        )
        .mount(&server)
        .await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;

    let response = send(
        &app,
        Request::get("/mineskin/jobs/limited").body(Body::empty())?,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "MineSkin request failed with status 429 Too Many Requests" })
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
            // Long enough that the first refresh is still in flight when the
            // second request arrives, but shorter than the 2s client timeout.
            ResponseTemplate::new(500)
                .set_delay(Duration::from_secs(1))
                .set_body_json(json!({
                    "success": false,
                    "errors": [{ "message": "temporary failure" }]
                })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;

    let first_app = app.clone();
    let first_request = Request::get("/mineskin/capes").body(Body::empty())?;
    let first = tokio::spawn(async move { send(&first_app, first_request).await });
    // The failure backoff starts only when the first refresh fails, so a
    // second upstream call here would mean concurrent refreshes are not shared.
    wait_for_upstream_path(&server, "/v2/capes").await?;
    let second = send(&app, Request::get("/mineskin/capes").body(Body::empty())?).await?;
    let first = first.await??;

    for response in [first, second] {
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            json_body(response).await?,
            json!({ "error": "temporary failure" })
        );
    }
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
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "Unexpected MineSkin cape response: response exceeded 1 MiB" })
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn rejects_oversized_chunked_upstream_responses_while_streaming() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/capes"))
        .respond_with(
            // A Transfer-Encoding header makes the mock server send a chunked
            // body without Content-Length, so only the streaming limit applies.
            ResponseTemplate::new(200)
                .insert_header("transfer-encoding", "chunked")
                .set_body_raw(vec![b'x'; 1024 * 1024 + 1], "application/json"),
        )
        .expect(2)
        .mount(&server)
        .await;
    let upstream = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?
        .get(format!("{}/v2/capes", server.uri()))
        .send()
        .await?;
    assert_eq!(upstream.headers().get(header::CONTENT_LENGTH), None);
    assert_eq!(upstream.content_length(), None);
    drop(upstream);
    let app = test_app(&format!("{}/v2/", server.uri()))?;

    let response = send(&app, Request::get("/mineskin/capes").body(Body::empty())?).await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "Unexpected MineSkin cape response: response exceeded 1 MiB" })
    );
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
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "Unexpected MineSkin cape response: cape URL must use HTTPS" })
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn reports_cape_support_only_for_accounts_with_a_cape_grant() -> TestResult {
    let supported_capes = json!({
        "capes": [{
            "uuid": CAPE_UUID,
            "alias": "founders",
            "url": "https://textures.example/cape.png"
        }]
    });
    for (grants, has_cape_grant) in [
        (Some(json!({ "capes": false })), false),
        (Some(json!({ "capes": "" })), false),
        (Some(json!({ "capes": 0 })), false),
        (Some(json!({ "capes": null })), false),
        (Some(json!({})), false),
        (None, false),
        (Some(json!({ "capes": true })), true),
        (Some(json!({ "capes": "all" })), true),
        (Some(json!({ "capes": 1 })), true),
        (Some(json!({ "capes": [] })), true),
    ] {
        let server = MockServer::start().await;
        let mut account = json!({ "success": true });
        if let (Some(grants), Some(object)) = (grants.clone(), account.as_object_mut()) {
            object.insert("grants".to_owned(), grants);
        }
        Mock::given(method("GET"))
            .and(path("/v2/me"))
            .and(header_matcher("authorization", "Bearer test-api-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(account))
            .expect(1)
            .mount(&server)
            .await;
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
            // Capes are only fetched when the account can use them.
            .expect(u64::from(has_cape_grant))
            .mount(&server)
            .await;
        let app = test_app(&format!("{}/v2/", server.uri()))?;

        let response = send(
            &app,
            Request::get("/mineskin/cape-support").body(Body::empty())?,
        )
        .await?;

        assert_eq!(response.status(), StatusCode::OK, "grants {grants:?}");
        let expected_capes = if has_cape_grant {
            supported_capes.get("capes").cloned().unwrap_or_default()
        } else {
            json!([])
        };
        assert_eq!(
            json_body(response).await?,
            json!({ "hasCapeGrant": has_cape_grant, "capes": expected_capes }),
            "grants {grants:?}"
        );
        server.verify().await;
    }
    Ok(())
}

#[tokio::test]
async fn reports_cape_support_upstream_failures_as_json() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/me"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "success": false,
            "errors": [{ "message": "invalid api key" }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/capes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "capes": []
        })))
        .mount(&server)
        .await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;

    let response = send(
        &app,
        Request::get("/mineskin/cape-support").body(Body::empty())?,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "invalid api key" })
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_decrypt_url_requests_with_json_errors() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;
    let encoded = |value: &str| {
        form_urlencoded::Serializer::new(String::new())
            .append_pair("encryptedUrl", value)
            .finish()
    };
    for (query, expected_error) in [
        (String::new(), "encryptedUrl is required"),
        (
            encoded("https://minesk.in/123e4567-e89b-12d3-a456-426614174000"),
            "Invalid encrypted URL format",
        ),
        (
            encoded("skinsrestorer-axolotl://not*base64!"),
            "Invalid encrypted URL payload",
        ),
        (
            encoded("skinsrestorer-axolotl://v2/not*base64!"),
            "Invalid encrypted URL payload",
        ),
    ] {
        let response = send(
            &app,
            Request::get(format!("/mineskin/decrypt-url?{query}")).body(Body::empty())?,
        )
        .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "query {query}");
        assert_eq!(
            json_body(response).await?,
            json!({ "error": expected_error }),
            "query {query}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_upload_cape_uuid_with_the_public_error() -> TestResult {
    let server = MockServer::start().await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;
    let boundary = "axolotl-invalid-cape-boundary";
    let response = send(
        &app,
        Request::post("/mineskin/skins?waitMs=250")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(multipart_upload_with_cape(boundary, "invalid")))?,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "capeUuid must be a valid UUID" })
    );
    Ok(())
}

#[tokio::test]
async fn preserves_upload_rate_limits_and_cors_headers() -> TestResult {
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
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/queue"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "success": false,
            "errors": [{ "message": "rate limit exceeded (hour), 61 > 60" }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;
    let boundary = "axolotl-rate-limit-boundary";

    let response = send(
        &app,
        Request::post("/mineskin/skins?waitMs=250")
            .header(header::ORIGIN, "https://skinsrestorer.net")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(multipart_upload(boundary)))?,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&header::HeaderValue::from_static("*"))
    );
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "rate limit exceeded (hour), 61 > 60" })
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn forwards_uploads_and_returns_an_encrypted_skin_url() -> TestResult {
    let completed = completed_job_response();
    for skin in [
        completed.get("skin").cloned(),
        Some(Value::Null),
        Some(json!(false)),
        None,
    ] {
        let mut response = completed.clone();
        let object = response
            .as_object_mut()
            .ok_or_else(|| io::Error::other("job response is not an object"))?;
        if let Some(skin) = skin {
            object.insert("skin".to_owned(), skin);
        } else {
            object.remove("skin");
        }
        verify_encrypted_upload(response).await?;
    }
    Ok(())
}

async fn verify_encrypted_upload(completed: Value) -> TestResult {
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
        .respond_with(ResponseTemplate::new(200).set_body_json(completed))
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

    assert_eq!(response.status(), StatusCode::OK, "upload with cape failed");
    let response = json_body(response).await?;
    let encrypted_url = response
        .get("skin")
        .and_then(|skin| skin.get("url"))
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("response did not contain an encrypted skin URL"))?;
    assert!(
        encrypted_url.starts_with("skinsrestorer-axolotl://v2/"),
        "unexpected encrypted skin URL: {encrypted_url}"
    );
    assert!(
        !response.to_string().contains(SKIN_UUID),
        "upload response exposed skin UUID {SKIN_UUID}: {response}"
    );
    assert_eq!(
        response,
        json!({
            "success": true,
            "skin": { "url": encrypted_url },
            "warnings": [],
            "messages": []
        }),
        "unexpected upload response for cape {CAPE_UUID}"
    );

    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("encryptedUrl", encrypted_url)
        .finish();
    let decrypted = send(
        &app,
        Request::get(format!("/mineskin/decrypt-url?{query}")).body(Body::empty())?,
    )
    .await?;
    assert_eq!(decrypted.status(), StatusCode::OK, "decryption failed");
    assert_eq!(
        json_body(decrypted).await?,
        json!({ "url": format!("https://minesk.in/{SKIN_ID}") }),
        "decrypted URL did not match the uploaded skin"
    );

    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn keeps_job_results_encrypted_and_ignores_pending_results() -> TestResult {
    for status in ["completed", "waiting"] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/queue/job-result"))
            .and(header_matcher("authorization", "Bearer test-api-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "job": { "id": "job-result", "status": status, "result": SKIN_UUID },
                "skin": false
            })))
            .expect(1)
            .mount(&server)
            .await;
        let app = test_app(&format!("{}/v2/", server.uri()))?;
        let response = send(
            &app,
            Request::get("/mineskin/jobs/job-result").body(Body::empty())?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let response = json_body(response).await?;
        assert!(!response.to_string().contains(SKIN_UUID));
        let expected_skin = if status == "completed" {
            let url = response
                .get("skin")
                .and_then(|skin| skin.get("url"))
                .and_then(Value::as_str)
                .ok_or_else(|| io::Error::other("response has no encrypted skin URL"))?;
            assert!(url.starts_with("skinsrestorer-axolotl://v2/"));
            json!({ "url": url })
        } else {
            Value::Null
        };
        assert_eq!(
            response,
            json!({
                "success": true,
                "skin": expected_skin,
                "warnings": [],
                "messages": []
            })
        );
        server.verify().await;
    }
    Ok(())
}

#[tokio::test]
async fn rejects_uploads_above_the_concurrency_limit_before_processing() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;

    // The first upload holds the only slot while its body never arrives. The
    // handler reads the body only after the guard grants a slot, so the signal
    // proves the slot is taken without depending on an upstream delay.
    let (body_polled_tx, body_polled_rx) = oneshot::channel();
    let pending_body = stream::once(async move {
        body_polled_tx
            .send(())
            .map_err(|()| io::Error::other("the test stopped waiting for the upload body"))?;
        future::pending::<Result<Bytes, io::Error>>().await
    });
    let first_app = app.clone();
    let first_boundary = "axolotl-concurrency-first";
    let first_request = Request::post("/mineskin/skins?waitMs=250")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={first_boundary}"),
        )
        .body(Body::from_stream(pending_body))?;
    let first = tokio::spawn(async move { send(&first_app, first_request).await });
    timeout(Duration::from_secs(2), body_polled_rx).await??;

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
    assert_eq!(
        json_body(second).await?,
        json!({ "error": "Too many skin uploads are already in progress" })
    );

    first.abort();
    drop(first.await);
    let third_boundary = "axolotl-concurrency-third";
    let third = send(
        &app,
        Request::post("/mineskin/skins?waitMs=250")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={third_boundary}"),
            )
            .body(Body::from(multipart_upload_with_cape(
                third_boundary,
                "invalid",
            )))?,
    )
    .await?;
    assert_eq!(
        third.status(),
        StatusCode::BAD_REQUEST,
        "a cancelled upload must release its slot"
    );
    assert_eq!(
        json_body(third).await?,
        json!({ "error": "capeUuid must be a valid UUID" })
    );
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
    Ok(build_app(&config, std::sync::Arc::new(Metrics::default()))?)
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

#[tokio::test]
async fn returns_json_for_unsupported_methods_on_known_routes() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;

    for (method, uri) in [("POST", "/health"), ("GET", "/mineskin/skins")] {
        let response = send(
            &app,
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())?,
        )
        .await?;

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(response.headers().contains_key(header::ALLOW));
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static("application/json"))
        );
        assert_eq!(
            json_body(response).await?,
            json!({ "error": "Method Not Allowed" })
        );
    }
    Ok(())
}

#[tokio::test]
async fn rejects_job_ids_that_could_change_the_upstream_path() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(completed_job_response()))
        .expect(0)
        .mount(&server)
        .await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;
    let too_long = "a".repeat(65);

    for job_id in [
        "%2E%2E",
        "%2E",
        "job%2Fwith",
        "job%20id",
        "%FF",
        too_long.as_str(),
    ] {
        let response = send(
            &app,
            Request::get(format!("/mineskin/jobs/{job_id}")).body(Body::empty())?,
        )
        .await?;

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "job ID {job_id}"
        );
        assert_eq!(
            json_body(response).await?,
            json!({ "error": "jobId must contain 1 to 64 letters, digits, hyphens, or underscores" }),
            "job ID {job_id}"
        );
    }
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn rejects_upload_bodies_above_the_size_limit_with_413() -> TestResult {
    let server = MockServer::start().await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;
    let boundary = "axolotl-oversized-boundary";
    let file = "a".repeat(7 * 1024 * 1024);
    let body = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"file\"; filename=\"skin.png\"\r\n\
         Content-Type: image/png\r\n\r\n\
         {file}\r\n\
         --{boundary}--\r\n"
    );

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

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "Skin upload body exceeds the size limit" })
    );
    let document = serde_json::to_value(api_document(4242))?;
    assert!(
        document
            .pointer("/paths/~1mineskin~1skins/post/responses/413")
            .is_some(),
        "the OpenAPI document must describe the 413 response"
    );
    Ok(())
}

#[tokio::test]
async fn hides_transport_error_details_from_clients() -> TestResult {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    let app = test_app(&format!("http://{address}/v2/"))?;

    let response = send(&app, Request::get("/mineskin/capes").body(Body::empty())?).await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "MineSkin request failed" })
    );
    Ok(())
}

#[tokio::test]
async fn redirects_the_root_straight_to_the_swagger_ui() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;

    let response = send(&app, Request::get("/").body(Body::empty())?).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&header::HeaderValue::from_static("/swagger/"))
    );
    Ok(())
}

#[tokio::test]
async fn caches_the_cape_grant_between_cape_support_requests() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "grants": { "capes": false }
        })))
        .expect(1)
        .mount(&server)
        .await;
    let app = test_app(&format!("{}/v2/", server.uri()))?;

    for _ in 0..2 {
        let response = send(
            &app,
            Request::get("/mineskin/cape-support").body(Body::empty())?,
        )
        .await?;
        assert_eq!(
            json_body(response).await?,
            json!({ "hasCapeGrant": false, "capes": [] })
        );
    }
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn rejects_non_numeric_wait_ms_with_the_range_message() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;
    let boundary = "axolotl-wait-ms";

    let response = send(
        &app,
        Request::post("/mineskin/skins?waitMs=soon")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(multipart_upload(boundary)))?,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "waitMs must be an integer between 250 and 10000" })
    );
    Ok(())
}
