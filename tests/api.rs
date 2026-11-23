#![expect(
    clippy::panic_in_result_fn,
    reason = "tests assert inside Result-returning test functions"
)]

use std::{
    collections::BTreeSet,
    error::Error,
    future::{Future, poll_fn},
    io,
    pin::pin,
    sync::{Mutex, mpsc},
    task::Poll,
    time::Duration,
};

use axolotl::{AppConfig, Metrics, api_document, build_app};
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    http::{Request, Response, StatusCode, header, request},
};
use futures_util::{future, stream};
use serde_json::{Value, json};
use tokio::{sync::oneshot, time::timeout};
use tower::ServiceExt;
use url::{Url, form_urlencoded};
use wiremock::{
    Mock, MockServer, Respond, ResponseTemplate,
    matchers::{body_string_contains, header as header_matcher, method, path},
};

const LEGACY_ENCRYPTED_URL: &str = "skinsrestorer-axolotl://AAECAwQFBgcICQoLDA0OD8imM586fmS6OpsiL50KsnvRWjSo4S7vTKK3sl3b3l7RG1vToG52Tih6IdrpltHyHA==";
/// A legacy CBC URL whose random IV encodes to base64 starting with "v2/",
/// the prefix of the current format.
const LEGACY_ENCRYPTED_URL_WITH_V2_PREFIX: &str = "skinsrestorer-axolotl://v2/ADQ4PEBESExQVFhcYGc7ZapKMUREWbvOc5sAljDbSTHfQgEPNTM/PSXVx9bdZNJB2gFJJtjle7cjIGhHEKg==";
const SKIN_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
/// `SKIN_UUID` in `MineSkin`'s format, which decrypted URLs use.
const SKIN_ID: &str = "123e4567e89b12d3a456426614174000";
const CAPE_UUID: &str = "123e4567-e89b-12d3-a456-426614174001";
const UPLOAD_BOUNDARY: &str = "axolotl-upload-boundary";
const ENCRYPTED_URL_PREFIX: &str = "skinsrestorer-axolotl://v2/";

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn serves_health_and_json_not_found_responses() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;

    let health = get(&app, "/health").await?;
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(json_body(health).await?, json!({ "status": "UP" }));

    let missing = get(&app, "/does-not-exist").await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(missing).await?,
        json!({ "error": "Not Found", "code": "not_found" })
    );
    Ok(())
}

#[tokio::test]
async fn decrypts_urls_created_by_the_legacy_service() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;
    for encrypted_url in [LEGACY_ENCRYPTED_URL, LEGACY_ENCRYPTED_URL_WITH_V2_PREFIX] {
        let response = decrypt(&app, encrypted_url).await?;

        assert_eq!(response.status(), StatusCode::OK, "{encrypted_url}");
        assert_eq!(
            json_body(response).await?,
            json!({ "url": format!("https://minesk.in/{SKIN_ID}") }),
            "{encrypted_url}"
        );
    }
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
    let app = mock_app(&server)?;

    for _ in 0..2 {
        let response = get(&app, "/mineskin/capes").await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await?,
            json!({ "capes": public_capes() })
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
    let app = mock_app(&server)?;

    let response = get(&app, "/mineskin/jobs/missing").await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "Job not found", "code": "job_not_found" })
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
    let app = mock_app(&server)?;

    let response = get(&app, "/mineskin/jobs/limited").await?;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "MineSkin request failed with status 429 Too Many Requests", "code": "mineskin_rate_limited" })
    );
    Ok(())
}

#[tokio::test]
async fn reports_jobs_with_unknown_upstream_statuses_as_pending() -> TestResult {
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
    let app = mock_app(&server)?;

    let response = get(&app, "/mineskin/jobs/job-new").await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await?,
        json!({
            "success": true,
            "skin": null,
            "warnings": [],
            "messages": [],
            "job": { "id": "job-new", "status": "unknown" }
        })
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn deduplicates_concurrent_failed_cape_refreshes() -> TestResult {
    let server = MockServer::start().await;
    let (arrived_tx, arrived_rx) = oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    Mock::given(method("GET"))
        .and(path("/v2/capes"))
        .respond_with(HeldResponse {
            response: ResponseTemplate::new(500).set_body_json(json!({
                "success": false,
                "errors": [{ "message": "temporary failure" }]
            })),
            arrived: Mutex::new(Some(arrived_tx)),
            release: Mutex::new(release_rx),
        })
        .expect(1)
        .mount(&server)
        .await;
    let app = mock_app(&server)?;

    let first_app = app.clone();
    let first = tokio::spawn(async move { get(&first_app, "/mineskin/capes").await });
    timeout(Duration::from_secs(2), arrived_rx).await??;
    // The first refresh is now held upstream. The second request must wait for
    // it instead of starting its own refresh. The failure backoff starts only
    // when the first refresh fails, so a second upstream call would mean that
    // concurrent refreshes are not shared.
    let mut second = pin!(get(&app, "/mineskin/capes"));
    let second_is_waiting =
        poll_fn(|context| Poll::Ready(second.as_mut().poll(context).is_pending())).await;
    assert!(
        second_is_waiting,
        "the second request did not wait for the first refresh"
    );
    drop(release_tx);
    let first = first.await??;
    let second = second.await?;

    for response in [first, second] {
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            json_body(response).await?,
            json!({ "error": "temporary failure", "code": "mineskin_error" })
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
    let app = mock_app(&server)?;

    let response = get(&app, "/mineskin/capes").await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "Unexpected MineSkin cape response: response exceeded 1 MiB", "code": "mineskin_error" })
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
    // Build the app first: it installs the rustls provider that a plain
    // reqwest client needs, so the test also passes when run on its own.
    let app = mock_app(&server)?;
    let upstream = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?
        .get(format!("{}/v2/capes", server.uri()))
        .send()
        .await?;
    assert_eq!(upstream.headers().get(header::CONTENT_LENGTH), None);
    assert_eq!(upstream.content_length(), None);
    drop(upstream);

    let response = get(&app, "/mineskin/capes").await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "Unexpected MineSkin cape response: response exceeded 1 MiB", "code": "mineskin_error" })
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
    let app = mock_app(&server)?;

    let response = get(&app, "/mineskin/capes").await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "Unexpected MineSkin cape response: cape URL must use HTTPS", "code": "mineskin_error" })
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn reports_cape_support_only_for_accounts_with_a_cape_grant() -> TestResult {
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
        verify_cape_support(grants, has_cape_grant).await?;
    }
    Ok(())
}

async fn verify_cape_support(grants: Option<Value>, has_cape_grant: bool) -> TestResult {
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
    // Capes are only fetched when the account can use them.
    mount_supported_capes(&server, u64::from(has_cape_grant)).await;
    let app = mock_app(&server)?;

    let response = get(&app, "/mineskin/cape-support").await?;

    assert_eq!(response.status(), StatusCode::OK, "grants {grants:?}");
    let expected_capes = if has_cape_grant {
        public_capes()
    } else {
        json!([])
    };
    assert_eq!(
        json_body(response).await?,
        json!({ "hasCapeGrant": has_cape_grant, "capes": expected_capes }),
        "grants {grants:?}"
    );
    server.verify().await;
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
    // Without a known grant there is nothing to list.
    mount_supported_capes(&server, 0).await;
    let app = mock_app(&server)?;

    let response = get(&app, "/mineskin/cape-support").await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "invalid api key", "code": "mineskin_error" })
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn repeats_a_rate_limited_cape_grant_lookup_without_asking_mineskin_again() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/me"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "success": false,
            "errors": [{ "message": "rate limit exceeded" }]
        })))
        // The failure is cached for 5 seconds, so the second request reuses it.
        .expect(1)
        .mount(&server)
        .await;
    let app = mock_app(&server)?;

    for attempt in 0..2 {
        let response = get(&app, "/mineskin/cape-support").await?;

        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "attempt {attempt}"
        );
        assert_eq!(
            json_body(response).await?,
            json!({ "error": "rate limit exceeded", "code": "mineskin_rate_limited" }),
            "attempt {attempt}"
        );
    }
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn fails_cape_support_when_a_granted_account_cannot_list_capes() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "grants": { "capes": true }
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/capes"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "success": false,
            "errors": [{ "message": "rate limit exceeded" }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let app = mock_app(&server)?;

    let response = get(&app, "/mineskin/cape-support").await?;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "rate limit exceeded", "code": "mineskin_rate_limited" })
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_decrypt_url_requests_with_json_errors() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;
    for (query, expected_error) in [
        (String::new(), "encryptedUrl must be provided exactly once"),
        (
            "encryptedUrl=a&encryptedUrl=b".to_owned(),
            "encryptedUrl must be provided exactly once",
        ),
        (
            encrypted_url_query("https://minesk.in/123e4567-e89b-12d3-a456-426614174000"),
            "Invalid encrypted URL format",
        ),
        (
            encrypted_url_query("skinsrestorer-axolotl://not*base64!"),
            "Invalid encrypted URL payload",
        ),
        (
            encrypted_url_query("skinsrestorer-axolotl://v2/not*base64!"),
            "Invalid encrypted URL payload",
        ),
    ] {
        let response = get(&app, &format!("/mineskin/decrypt-url?{query}")).await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "query {query}");
        assert_eq!(
            json_body(response).await?,
            json!({ "error": expected_error, "code": "invalid_encrypted_url" }),
            "query {query}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_uploads_before_calling_mineskin() -> TestResult {
    let server = MockServer::start().await;
    let app = mock_app(&server)?;
    let upload = multipart_upload(UPLOAD_BOUNDARY);
    let file_part = format!(
        "--{UPLOAD_BOUNDARY}\r\n\
         Content-Disposition: form-data; name=\"file\"; filename=\"skin.png\"\r\n\
         Content-Type: image/png\r\n\r\n\
         png-bytes\r\n"
    );
    let invalid_name =
        "name must be at most 48 letters, digits, spaces, dots, hyphens, or underscores";
    let invalid_wait_ms = "waitMs must be an integer between 250 and 10000";

    for (case, uri, body, expected_error) in [
        (
            "missing file",
            "/mineskin/skins",
            upload.replace(&file_part, ""),
            "A skin file must be provided",
        ),
        (
            "empty file",
            "/mineskin/skins",
            upload.replace("png-bytes", ""),
            "A skin file must be provided",
        ),
        (
            "unknown variant",
            "/mineskin/skins",
            upload.replace("\r\n\r\nslim\r\n", "\r\n\r\nwide\r\n"),
            "variant must be one of classic or slim",
        ),
        (
            "long name",
            "/mineskin/skins",
            upload.replace("integration_skin", &"a".repeat(49)),
            invalid_name,
        ),
        (
            "punctuation in name",
            "/mineskin/skins",
            upload.replace("integration_skin", "skin!"),
            invalid_name,
        ),
        (
            "non-ASCII name",
            "/mineskin/skins",
            upload.replace("integration_skin", "\u{fc}ber"),
            invalid_name,
        ),
        (
            "missing cape",
            "/mineskin/skins",
            upload.replace("name=\"capeUuid\"", "name=\"unknownField\""),
            "capeUuid is required",
        ),
        (
            "invalid cape",
            "/mineskin/skins",
            multipart_upload_with_cape(UPLOAD_BOUNDARY, "invalid"),
            "capeUuid must be a valid UUID",
        ),
        (
            "non-numeric waitMs",
            "/mineskin/skins?waitMs=soon",
            upload.clone(),
            invalid_wait_ms,
        ),
        (
            "waitMs below the minimum",
            "/mineskin/skins?waitMs=249",
            upload.clone(),
            invalid_wait_ms,
        ),
        (
            "waitMs above the maximum",
            "/mineskin/skins?waitMs=10001",
            upload.clone(),
            invalid_wait_ms,
        ),
    ] {
        let response = post_multipart(&app, uri, body).await?;
        let expected_code = if uri.contains("waitMs=") {
            "invalid_wait_ms"
        } else {
            "invalid_upload"
        };

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{case}");
        assert_eq!(
            json_body(response).await?,
            json!({ "error": expected_error, "code": expected_code }),
            "{case}"
        );
    }
    assert_eq!(
        upstream_requests(&server, None).await,
        0,
        "an invalid upload must not reach MineSkin"
    );
    Ok(())
}

#[tokio::test]
async fn preserves_upload_rate_limits_and_cors_headers() -> TestResult {
    let server = MockServer::start().await;
    mount_supported_capes(&server, 1).await;
    Mock::given(method("POST"))
        .and(path("/v2/queue"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "success": false,
            "errors": [{ "message": "rate limit exceeded (hour), 61 > 60" }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let app = mock_app(&server)?;

    let response = send(
        &app,
        upload_request("/mineskin/skins?waitMs=250")
            .header(header::ORIGIN, "https://skinsrestorer.net")
            .body(Body::from(multipart_upload(UPLOAD_BOUNDARY)))?,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&header::HeaderValue::from_static("*"))
    );
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "rate limit exceeded (hour), 61 > 60", "code": "mineskin_rate_limited" })
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn returns_400_only_when_mineskin_rejects_the_queued_skin() -> TestResult {
    for (upstream_status, expected_status) in [
        (400, StatusCode::BAD_REQUEST),
        (503, StatusCode::BAD_GATEWAY),
    ] {
        let server = MockServer::start().await;
        mount_supported_capes(&server, 1).await;
        Mock::given(method("POST"))
            .and(path("/v2/queue"))
            .respond_with(ResponseTemplate::new(upstream_status).set_body_json(json!({
                "success": false,
                "errors": [{ "message": "Skin image is invalid" }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let app = mock_app(&server)?;

        let response = post_upload(&app, "/mineskin/skins").await?;

        assert_eq!(
            response.status(),
            expected_status,
            "upstream {upstream_status}"
        );
        let expected_code = if expected_status == StatusCode::BAD_REQUEST {
            "skin_rejected"
        } else {
            "mineskin_error"
        };
        assert_eq!(
            json_body(response).await?,
            json!({ "error": "Skin image is invalid", "code": expected_code }),
            "upstream {upstream_status}"
        );
        assert_eq!(
            upstream_requests(&server, Some("/v2/queue/job-1")).await,
            0,
            "a rejected skin has no job to poll"
        );
        server.verify().await;
    }
    Ok(())
}

#[tokio::test]
async fn forwards_uploads_and_returns_an_encrypted_skin_url() -> TestResult {
    let completed = completed_job_response();
    // MineSkin reports skin IDs without hyphens, so both forms must decrypt to
    // the same minesk.in link.
    for (skin, result) in [
        (completed.get("skin").cloned(), SKIN_UUID),
        (Some(json!({ "uuid": SKIN_ID })), SKIN_UUID),
        (Some(Value::Null), SKIN_UUID),
        (Some(json!(false)), SKIN_UUID),
        (None, SKIN_UUID),
        (None, SKIN_ID),
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
        if let Some(job_result) = response.pointer_mut("/job/result") {
            *job_result = json!(result);
        }
        verify_encrypted_upload(response).await?;
    }
    Ok(())
}

async fn verify_encrypted_upload(completed: Value) -> TestResult {
    let server = MockServer::start().await;
    mount_supported_capes(&server, 1).await;
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
    job_status_mock(200, completed)
        .expect(1)
        .mount(&server)
        .await;
    let app = mock_app(&server)?;
    let body = multipart_upload_with_cape(UPLOAD_BOUNDARY, &CAPE_UUID.to_uppercase());

    let response = post_multipart(&app, "/mineskin/skins?waitMs=250", body).await?;

    assert_eq!(response.status(), StatusCode::OK, "upload with cape failed");
    let response = json_body(response).await?;
    let encrypted_url = encrypted_skin_url(&response)?;
    for exposed in [SKIN_UUID, SKIN_ID] {
        assert!(
            !response.to_string().contains(exposed),
            "upload response exposed skin ID {exposed}: {response}"
        );
    }
    assert_eq!(
        response,
        json!({
            "success": true,
            "skin": { "url": encrypted_url },
            "warnings": [],
            "messages": [],
            "job": { "id": "job-1", "status": "completed" }
        }),
        "unexpected upload response for cape {CAPE_UUID}"
    );

    let decrypted = decrypt(&app, encrypted_url).await?;
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
async fn accepts_the_cape_form_field_as_an_alias_for_cape_uuid() -> TestResult {
    let server = MockServer::start().await;
    mount_supported_capes(&server, 1).await;
    Mock::given(method("POST"))
        .and(path("/v2/queue"))
        .and(body_string_contains(format!(
            "name=\"cape\"\r\n\r\n{CAPE_UUID}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "job": { "id": "job-1", "status": "waiting", "result": null }
        })))
        .expect(1)
        .mount(&server)
        .await;
    job_status_mock(200, completed_job_response())
        .expect(1)
        .mount(&server)
        .await;
    let app = mock_app(&server)?;
    let body = multipart_upload(UPLOAD_BOUNDARY).replace("name=\"capeUuid\"", "name=\"cape\"");

    let response = post_multipart(&app, "/mineskin/skins", body).await?;

    assert_eq!(response.status(), StatusCode::OK);
    encrypted_skin_url(&json_body(response).await?)?;
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
        let app = mock_app(&server)?;
        let response = get(&app, "/mineskin/jobs/job-result").await?;
        assert_eq!(response.status(), StatusCode::OK, "status {status}");
        let response = json_body(response).await?;
        assert!(!response.to_string().contains(SKIN_UUID), "status {status}");
        let expected_skin = if status == "completed" {
            json!({ "url": encrypted_skin_url(&response)? })
        } else {
            Value::Null
        };
        assert_eq!(
            response,
            json!({
                "success": true,
                "skin": expected_skin,
                "warnings": [],
                "messages": [],
                "job": { "id": "job-result", "status": status }
            }),
            "status {status}"
        );
        server.verify().await;
    }
    Ok(())
}

#[tokio::test]
async fn keeps_polling_an_upload_through_transient_job_status_errors() -> TestResult {
    let server = MockServer::start().await;
    mount_supported_capes(&server, 1).await;
    mount_enqueued_job(&server).await;
    let retryable_error = json!({
        "success": false,
        "errors": [{ "message": "try again later" }]
    });
    for (priority, status) in [(1, 503), (2, 429)] {
        job_status_mock(status, retryable_error.clone())
            .up_to_n_times(1)
            .with_priority(priority)
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/v2/queue/job-1"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{\"success\": tr"))
        .up_to_n_times(1)
        .with_priority(3)
        .expect(1)
        .mount(&server)
        .await;
    job_status_mock(200, completed_job_response())
        .expect(1)
        .mount(&server)
        .await;
    let app = mock_app(&server)?;

    // Without waitMs the test config polls every millisecond.
    let response = post_upload(&app, "/mineskin/skins").await?;

    assert_eq!(response.status(), StatusCode::OK);
    encrypted_skin_url(&json_body(response).await?)?;
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn backs_off_while_job_status_polls_keep_failing() -> TestResult {
    let server = MockServer::start().await;
    mount_supported_capes(&server, 1).await;
    mount_enqueued_job(&server).await;
    job_status_mock(
        503,
        json!({
            "success": false,
            "errors": [{ "message": "try again later" }]
        }),
    )
    .mount(&server)
    .await;
    let app = mock_app(&server)?;

    // The test config polls every millisecond and gives up after one second.
    // Doubling the delay from 1 ms allows at most 10 polls in that second;
    // a fixed 1 ms interval would poll hundreds of times.
    let response = timeout(Duration::from_secs(5), post_upload(&app, "/mineskin/skins")).await??;

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(
        json_body(response).await?,
        json!({
            "error": "Timed out waiting for MineSkin job to finish",
            "code": "job_timeout",
            "jobId": "job-1"
        })
    );
    let polls = upstream_requests(&server, Some("/v2/queue/job-1")).await;
    assert!(
        (3..=12).contains(&polls),
        "expected a backed-off number of polls, got {polls}"
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn returns_504_when_an_uploaded_job_never_finishes() -> TestResult {
    let server = MockServer::start().await;
    mount_supported_capes(&server, 1).await;
    mount_enqueued_job(&server).await;
    job_status_mock(
        200,
        json!({
            "success": true,
            "job": { "id": "job-1", "status": "processing", "result": null }
        }),
    )
    .mount(&server)
    .await;
    let app = mock_app(&server)?;

    // The test config gives up polling after one second.
    let response = timeout(
        Duration::from_secs(5),
        post_upload(&app, "/mineskin/skins?waitMs=250"),
    )
    .await??;

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(
        json_body(response).await?,
        json!({
            "error": "Timed out waiting for MineSkin job to finish",
            "code": "job_timeout",
            "jobId": "job-1"
        })
    );
    let polls = upstream_requests(&server, Some("/v2/queue/job-1")).await;
    assert!(polls >= 2, "the job was polled only {polls} times");
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn fails_an_upload_without_retrying_when_mineskin_rejects_the_job() -> TestResult {
    for (case, status, job_response, expected_error) in [
        (
            "failed job",
            200,
            json!({
                "success": true,
                "job": { "id": "job-1", "status": "failed", "result": null },
                "errors": [{ "message": "Skin image is invalid" }]
            }),
            "Skin image is invalid",
        ),
        (
            "unsuccessful response",
            200,
            json!({
                "success": false,
                "errors": [{ "code": "invalid_job", "message": "Job is invalid" }]
            }),
            "Job is invalid",
        ),
        (
            "400 response",
            400,
            json!({
                "success": false,
                "errors": [{ "code": "invalid_job_id", "message": "Invalid job ID" }]
            }),
            "Invalid job ID",
        ),
        (
            "completed job without a skin",
            200,
            json!({
                "success": true,
                "job": { "id": "job-1", "status": "completed", "result": null }
            }),
            "MineSkin job completed but no skin data provided",
        ),
    ] {
        let server = MockServer::start().await;
        mount_supported_capes(&server, 1).await;
        mount_enqueued_job(&server).await;
        job_status_mock(status, job_response)
            .expect(1)
            .mount(&server)
            .await;
        let app = mock_app(&server)?;

        // Without waitMs the test config polls every millisecond, so a retry
        // would reach the mock again at once.
        let response = post_upload(&app, "/mineskin/skins").await?;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{case}");
        assert_eq!(
            json_body(response).await?,
            json!({ "error": expected_error, "code": "mineskin_error", "jobId": "job-1" }),
            "{case}"
        );
        server.verify().await;
    }
    Ok(())
}

#[tokio::test]
async fn rejects_uploads_with_an_unsupported_cape_before_queueing() -> TestResult {
    let server = MockServer::start().await;
    mount_supported_capes(&server, 1).await;
    Mock::given(method("POST"))
        .and(path("/v2/queue"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let app = mock_app(&server)?;

    let response = post_multipart(
        &app,
        "/mineskin/skins?waitMs=250",
        multipart_upload_with_cape(UPLOAD_BOUNDARY, "123e4567-e89b-12d3-a456-426614174002"),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "Requested cape is not supported", "code": "unsupported_cape" })
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn rejects_uploads_above_the_concurrency_limit_until_a_slot_frees() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let app = mock_app(&server)?;

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
    let first_request =
        upload_request("/mineskin/skins?waitMs=250").body(Body::from_stream(pending_body))?;
    let first = tokio::spawn(async move { send(&first_app, first_request).await });
    timeout(Duration::from_secs(2), body_polled_rx).await??;

    let second = post_upload(&app, "/mineskin/skins?waitMs=250").await?;

    assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        second.headers().get(header::RETRY_AFTER),
        Some(&header::HeaderValue::from_static("5"))
    );
    assert_eq!(
        json_body(second).await?,
        json!({ "error": "Too many skin uploads are already in progress", "code": "upload_busy" })
    );

    first.abort();
    drop(first.await);
    let third = post_multipart(
        &app,
        "/mineskin/skins?waitMs=250",
        multipart_upload_with_cape(UPLOAD_BOUNDARY, "invalid"),
    )
    .await?;
    assert_eq!(
        third.status(),
        StatusCode::BAD_REQUEST,
        "a cancelled upload must release its slot"
    );
    assert_eq!(
        json_body(third).await?,
        json!({ "error": "capeUuid must be a valid UUID", "code": "invalid_upload" })
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
        "/ready",
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
    assert_eq!(
        value.pointer("/info/version").and_then(Value::as_str),
        Some(env!("CARGO_PKG_VERSION"))
    );
    Ok(())
}

#[test]
fn openapi_document_lists_mineskin_first_and_summarizes_every_operation() -> TestResult {
    let value = serde_json::to_value(api_document(4242))?;
    let tags = value
        .get("tags")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::other("OpenAPI document did not contain tags"))?
        .iter()
        .filter_map(|tag| tag.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(tags, ["mineskin", "health"]);

    for (pointer, tag) in [
        ("/paths/~1health/get", "health"),
        ("/paths/~1mineskin~1skins/post", "mineskin"),
        ("/paths/~1mineskin~1jobs~1{jobId}/get", "mineskin"),
        ("/paths/~1mineskin~1capes/get", "mineskin"),
        ("/paths/~1mineskin~1cape-support/get", "mineskin"),
        ("/paths/~1mineskin~1decrypt-url/get", "mineskin"),
    ] {
        let operation = value
            .pointer(pointer)
            .ok_or_else(|| io::Error::other(format!("OpenAPI document has no {pointer}")))?;
        assert_eq!(operation.get("tags"), Some(&json!([tag])), "{pointer}");
        let summary = operation
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(
            summary.ends_with('.') && summary.len() > 10,
            "{pointer} needs a one-sentence summary, got {summary:?}"
        );
    }
    Ok(())
}

fn test_app(base_url: &str) -> TestResult<Router> {
    let config = AppConfig::for_tests(Url::parse(base_url)?);
    Ok(build_app(&config, std::sync::Arc::new(Metrics::default()))?)
}

/// Builds an app whose `MineSkin` API is the mock server.
fn mock_app(server: &MockServer) -> TestResult<Router> {
    test_app(&format!("{}/v2/", server.uri()))
}

async fn send(app: &Router, request: Request<Body>) -> TestResult<Response<Body>> {
    Ok(app.clone().oneshot(request).await?)
}

async fn get(app: &Router, uri: &str) -> TestResult<Response<Body>> {
    send(app, Request::get(uri).body(Body::empty())?).await
}

async fn decrypt(app: &Router, encrypted_url: &str) -> TestResult<Response<Body>> {
    let query = encrypted_url_query(encrypted_url);
    get(app, &format!("/mineskin/decrypt-url?{query}")).await
}

fn encrypted_url_query(encrypted_url: &str) -> String {
    form_urlencoded::Serializer::new(String::new())
        .append_pair("encryptedUrl", encrypted_url)
        .finish()
}

async fn json_body(response: Response<Body>) -> TestResult<Value> {
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Returns `skin.url` of an upload or job response and checks that it is an
/// encrypted URL in the current format.
fn encrypted_skin_url(response: &Value) -> TestResult<&str> {
    let url = response
        .pointer("/skin/url")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other(format!("response has no skin URL: {response}")))?;
    assert!(
        url.starts_with(ENCRYPTED_URL_PREFIX),
        "unexpected encrypted skin URL: {url}"
    );
    Ok(url)
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

/// The cape that `mount_supported_capes` serves, as the proxy returns it.
fn public_capes() -> Value {
    json!([{
        "uuid": CAPE_UUID,
        "alias": "founders",
        "url": "https://textures.example/cape.png"
    }])
}

async fn mount_supported_capes(server: &MockServer, expected_calls: u64) {
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
        .expect(expected_calls)
        .mount(server)
        .await;
}

async fn mount_enqueued_job(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v2/queue"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "job": { "id": "job-1", "status": "waiting", "result": null }
        })))
        .expect(1)
        .mount(server)
        .await;
}

/// Answers status polls for the job that `mount_enqueued_job` queues.
fn job_status_mock(status: u16, body: Value) -> Mock {
    Mock::given(method("GET"))
        .and(path("/v2/queue/job-1"))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
}

/// Starts a skin upload request with the multipart content type for
/// `UPLOAD_BOUNDARY`.
fn upload_request(uri: &str) -> request::Builder {
    Request::post(uri).header(
        header::CONTENT_TYPE,
        format!("multipart/form-data; boundary={UPLOAD_BOUNDARY}"),
    )
}

async fn post_multipart(app: &Router, uri: &str, body: String) -> TestResult<Response<Body>> {
    send(app, upload_request(uri).body(Body::from(body))?).await
}

async fn post_upload(app: &Router, uri: &str) -> TestResult<Response<Body>> {
    post_multipart(app, uri, multipart_upload(UPLOAD_BOUNDARY)).await
}

/// Counts the requests that reached the mock server, optionally only those
/// for one path.
async fn upstream_requests(server: &MockServer, only_path: Option<&str>) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|request| only_path.is_none_or(|only_path| request.url.path() == only_path))
        .count()
}

/// Reports when its request arrives and holds the response until the test
/// drops the release sender.
struct HeldResponse {
    response: ResponseTemplate,
    arrived: Mutex<Option<oneshot::Sender<()>>>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl Respond for HeldResponse {
    fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
        if let Some(arrived) = self
            .arrived
            .lock()
            .ok()
            .and_then(|mut arrived| arrived.take())
        {
            arrived.send(()).unwrap_or_default();
        }
        // Blocks the mock server thread, which serves nothing else meanwhile.
        if let Ok(release) = self.release.lock() {
            release.recv().unwrap_or_default();
        }
        self.response.clone()
    }
}

#[tokio::test]
async fn returns_json_for_unsupported_methods_on_known_routes() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;

    for (method, uri, allow) in [
        ("POST", "/health", "GET,HEAD"),
        ("GET", "/mineskin/skins", "POST"),
        ("DELETE", "/mineskin/decrypt-url", "GET,HEAD"),
    ] {
        let response = send(
            &app,
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())?,
        )
        .await?;

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{uri}");
        assert_eq!(
            response.headers().get(header::ALLOW),
            Some(&header::HeaderValue::from_static(allow)),
            "{method} {uri}"
        );
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static("application/json"))
        );
        assert_eq!(
            json_body(response).await?,
            json!({ "error": "Method Not Allowed", "code": "method_not_allowed" })
        );
    }
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_job_ids_without_calling_mineskin() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(completed_job_response()))
        .expect(0)
        .mount(&server)
        .await;
    let app = mock_app(&server)?;
    let too_long = "a".repeat(65);

    for job_id in [
        "%2E%2E",
        "%2E",
        "job%2Fwith",
        "job%20id",
        "%FF",
        too_long.as_str(),
    ] {
        let response = get(&app, &format!("/mineskin/jobs/{job_id}")).await?;

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "job ID {job_id}"
        );
        assert_eq!(
            json_body(response).await?,
            json!({ "error": "jobId must contain 1 to 64 letters, digits, hyphens, or underscores", "code": "invalid_job_id" }),
            "job ID {job_id}"
        );
    }
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn rejects_upload_bodies_above_the_size_limit_with_a_documented_413() -> TestResult {
    let server = MockServer::start().await;
    let app = mock_app(&server)?;
    let file = "a".repeat(7 * 1024 * 1024);
    let body = multipart_upload(UPLOAD_BOUNDARY).replace("png-bytes", &file);

    let response = post_multipart(&app, "/mineskin/skins?waitMs=250", body).await?;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "Skin upload body exceeds the size limit", "code": "payload_too_large" })
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

    let response = get(&app, "/mineskin/capes").await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "MineSkin request failed", "code": "mineskin_error" })
    );
    Ok(())
}

#[tokio::test]
async fn redirects_the_root_straight_to_the_swagger_ui() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;

    let response = get(&app, "/").await?;

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
    let app = mock_app(&server)?;

    for _ in 0..2 {
        let response = get(&app, "/mineskin/cape-support").await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await?,
            json!({ "hasCapeGrant": false, "capes": [] })
        );
    }
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn rejects_skin_files_above_5_mib_within_the_body_limit_with_413() -> TestResult {
    let server = MockServer::start().await;
    let app = mock_app(&server)?;
    // Larger than the 5 MiB file limit but below the 6 MiB body limit.
    let file = "a".repeat(5 * 1024 * 1024 + 1);
    let body = multipart_upload(UPLOAD_BOUNDARY).replace("png-bytes", &file);

    let response = post_multipart(&app, "/mineskin/skins?waitMs=250", body).await?;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "Skin file must not exceed 5 MiB", "code": "payload_too_large" })
    );
    Ok(())
}

#[tokio::test]
async fn uploads_a_skin_file_sent_without_a_file_name() -> TestResult {
    let server = MockServer::start().await;
    mount_supported_capes(&server, 1).await;
    Mock::given(method("POST"))
        .and(path("/v2/queue"))
        .and(body_string_contains("filename=\"skin.png\""))
        .and(body_string_contains("png-bytes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "job": { "id": "job-1", "status": "waiting", "result": null }
        })))
        .expect(1)
        .mount(&server)
        .await;
    job_status_mock(200, completed_job_response())
        .expect(1)
        .mount(&server)
        .await;
    let app = mock_app(&server)?;
    let body = multipart_upload(UPLOAD_BOUNDARY).replace("; filename=\"skin.png\"", "");

    let response = post_multipart(&app, "/mineskin/skins?waitMs=250", body).await?;

    assert_eq!(response.status(), StatusCode::OK);
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn serves_the_swagger_ui_and_json_for_unknown_swagger_files() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;

    let index = get(&app, "/swagger/").await?;
    assert_eq!(index.status(), StatusCode::OK);

    let missing = get(&app, "/swagger/nope").await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(missing).await?,
        json!({ "error": "Not Found", "code": "not_found" })
    );
    Ok(())
}

#[tokio::test]
async fn reports_a_failed_job_on_the_job_status_route() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/queue/job-failed"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "job": { "id": "job-failed", "status": "failed", "result": null },
            "errors": [{ "code": "invalid_image", "message": "Invalid skin image" }]
        })))
        .mount(&server)
        .await;
    let app = mock_app(&server)?;

    let response = get(&app, "/mineskin/jobs/job-failed").await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "Invalid skin image", "code": "mineskin_error" })
    );
    Ok(())
}

#[tokio::test]
async fn rejects_a_cape_response_without_a_cape_list() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/capes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "success": true })))
        .expect(1)
        .mount(&server)
        .await;
    let app = mock_app(&server)?;

    // Both requests fail: the broken response is not cached as an empty list,
    // which would reject every upload's cape for five minutes.
    for _ in 0..2 {
        let response = get(&app, "/mineskin/capes").await?;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            json_body(response).await?,
            json!({ "error": "Unexpected MineSkin cape response: capes is missing", "code": "mineskin_error" })
        );
    }
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn configures_swagger_ui_without_the_explore_bar() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;

    let response = get(&app, "/swagger/swagger-initializer.js").await?;
    assert_eq!(response.status(), StatusCode::OK);
    let script = String::from_utf8(to_bytes(response.into_body(), 1024 * 1024).await?.to_vec())?;

    for setting in [
        r#""url": "/openapi""#,
        r#""layout": "BaseLayout""#,
        r#""defaultModelsExpandDepth": 0"#,
        r#""displayRequestDuration": true"#,
    ] {
        assert!(script.contains(setting), "missing {setting} in {script}");
    }
    assert!(!script.contains("StandaloneLayout\""), "{script}");
    Ok(())
}

#[tokio::test]
async fn rejects_upload_bodies_that_are_not_multipart_with_the_expected_content_type() -> TestResult
{
    let app = test_app("http://127.0.0.1:9/v2/")?;
    let response = send(
        &app,
        Request::post("/mineskin/skins")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))?,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "Content-Type must be multipart/form-data with a boundary", "code": "invalid_upload" })
    );
    Ok(())
}

#[tokio::test]
async fn rejects_a_blank_skin_name_before_calling_mineskin() -> TestResult {
    let server = MockServer::start().await;
    let app = mock_app(&server)?;
    let body = multipart_upload(UPLOAD_BOUNDARY).replace("integration_skin", "   ");

    let response = post_multipart(&app, "/mineskin/skins", body).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "name must not be blank", "code": "invalid_upload" })
    );
    assert_eq!(upstream_requests(&server, None).await, 0);
    Ok(())
}

#[tokio::test]
async fn reports_a_completed_job_without_skin_data_on_the_job_route() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/queue/job-empty"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "job": { "id": "job-empty", "status": "completed", "result": null }
        })))
        .mount(&server)
        .await;
    let app = mock_app(&server)?;

    let response = get(&app, "/mineskin/jobs/job-empty").await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "MineSkin job completed but no skin data provided", "code": "mineskin_error" })
    );
    Ok(())
}

#[tokio::test]
async fn reports_ready_when_the_required_configuration_is_usable() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;

    let response = get(&app, "/ready").await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await?, json!({ "status": "READY" }));
    Ok(())
}

#[tokio::test]
async fn uses_the_cloudflare_ray_id_as_the_request_id() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;

    let response = send(
        &app,
        Request::get("/health")
            .header("cf-ray", "8f1e2d3c4b5a6978-FRA")
            .header("x-request-id", "chosen-by-the-client")
            .body(Body::empty())?,
    )
    .await?;

    assert_eq!(
        response.headers().get("x-request-id"),
        Some(&header::HeaderValue::from_static("8f1e2d3c4b5a6978-FRA"))
    );
    Ok(())
}

#[tokio::test]
async fn generates_a_request_id_without_a_cloudflare_ray_id() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;
    let mut ids = BTreeSet::new();

    for _ in 0..2 {
        let response = send(
            &app,
            Request::get("/does-not-exist")
                .header("x-request-id", "chosen-by-the-client")
                .body(Body::empty())?,
        )
        .await?;
        let id = response
            .headers()
            .get("x-request-id")
            .ok_or_else(|| io::Error::other("response has no x-request-id header"))?
            .to_str()?
            .to_owned();
        uuid::Uuid::parse_str(&id)?;
        ids.insert(id);
    }

    assert_eq!(ids.len(), 2, "each request needs its own ID: {ids:?}");
    Ok(())
}

#[tokio::test]
async fn reports_the_job_state_so_clients_can_resume_a_pending_upload() -> TestResult {
    for status in ["waiting", "active", "processing"] {
        let server = MockServer::start().await;
        job_status_mock(
            200,
            json!({
                "success": true,
                "job": { "id": "job-1", "status": status, "result": null }
            }),
        )
        .expect(1)
        .mount(&server)
        .await;
        let app = mock_app(&server)?;

        let response = get(&app, "/mineskin/jobs/job-1").await?;

        assert_eq!(response.status(), StatusCode::OK, "status {status}");
        assert_eq!(
            json_body(response).await?,
            json!({
                "success": true,
                "skin": null,
                "warnings": [],
                "messages": [],
                "job": { "id": "job-1", "status": status }
            }),
            "status {status}"
        );
        server.verify().await;
    }
    Ok(())
}

#[test]
fn openapi_document_lists_every_error_code() -> TestResult {
    let value = serde_json::to_value(api_document(4242))?;
    let codes = value
        .pointer("/components/schemas/ErrorCode/enum")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::other("OpenAPI document did not list the error codes"))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();

    for code in [
        "invalid_wait_ms",
        "invalid_upload",
        "unsupported_cape",
        "invalid_job_id",
        "invalid_encrypted_url",
        "payload_too_large",
        "upload_body_timeout",
        "upload_busy",
        "upload_timeout",
        "job_not_found",
        "job_timeout",
        "mineskin_rate_limited",
        "mineskin_error",
        "not_configured",
        "not_found",
        "method_not_allowed",
    ] {
        assert!(codes.contains(code), "missing error code {code}");
    }
    assert_eq!(
        value.pointer("/components/schemas/ErrorResponse/required"),
        Some(&json!(["error", "code"]))
    );
    Ok(())
}

#[tokio::test]
async fn forwards_the_mineskin_retry_after_on_rate_limits() -> TestResult {
    // Every route that calls MineSkin passes its Retry-After on a 429, and only
    // on a 429.
    for (route, upstream_method, upstream_path, upstream_status, retry_after) in [
        ("/mineskin/capes", "GET", "/v2/capes", 429, Some("30")),
        ("/mineskin/capes", "GET", "/v2/capes", 429, None),
        ("/mineskin/capes", "GET", "/v2/capes", 503, Some("30")),
        ("/mineskin/cape-support", "GET", "/v2/me", 429, Some("30")),
        (
            "/mineskin/jobs/job-1",
            "GET",
            "/v2/queue/job-1",
            429,
            Some("30"),
        ),
        ("/mineskin/skins", "POST", "/v2/queue", 429, Some("30")),
    ] {
        let case = format!("{route} after MineSkin {upstream_status} {retry_after:?}");
        let server = MockServer::start().await;
        if upstream_method == "POST" {
            mount_supported_capes(&server, 1).await;
        }
        let mut template = ResponseTemplate::new(upstream_status).set_body_json(json!({
            "success": false,
            "errors": [{ "message": "rate limit exceeded" }]
        }));
        if let Some(value) = retry_after {
            template = template.insert_header("Retry-After", value);
        }
        Mock::given(method(upstream_method))
            .and(path(upstream_path))
            .respond_with(template)
            .expect(1)
            .mount(&server)
            .await;
        let app = mock_app(&server)?;

        let response = if upstream_method == "POST" {
            post_upload(&app, route).await?
        } else {
            get(&app, route).await?
        };

        let (expected_status, expected_retry_after, expected_code) = if upstream_status == 429 {
            (
                StatusCode::TOO_MANY_REQUESTS,
                retry_after,
                "mineskin_rate_limited",
            )
        } else {
            (StatusCode::BAD_GATEWAY, None, "mineskin_error")
        };
        assert_eq!(response.status(), expected_status, "{case}");
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            expected_retry_after,
            "{case}"
        );
        assert_eq!(
            json_body(response).await?,
            json!({ "error": "rate limit exceeded", "code": expected_code }),
            "{case}"
        );
        server.verify().await;
    }
    Ok(())
}

#[tokio::test]
async fn reports_a_mineskin_504_on_the_queue_request_as_a_502() -> TestResult {
    let server = MockServer::start().await;
    mount_supported_capes(&server, 1).await;
    Mock::given(method("POST"))
        .and(path("/v2/queue"))
        .respond_with(ResponseTemplate::new(504).set_body_json(json!({
            "success": false,
            "errors": [{ "message": "upstream timed out" }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let app = mock_app(&server)?;

    let response = post_upload(&app, "/mineskin/skins").await?;

    // Only the polling deadline is a 504. MineSkin's own 504 is a 502.
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        json_body(response).await?,
        json!({ "error": "upstream timed out", "code": "mineskin_error" })
    );
    server.verify().await;
    Ok(())
}

#[test]
fn openapi_document_declares_retry_after_on_every_429_and_503() -> TestResult {
    let value = serde_json::to_value(api_document(4242))?;
    for pointer in [
        "/paths/~1mineskin~1skins/post/responses/429",
        "/paths/~1mineskin~1skins/post/responses/503",
        "/paths/~1mineskin~1jobs~1{jobId}/get/responses/429",
        "/paths/~1mineskin~1capes/get/responses/429",
        "/paths/~1mineskin~1cape-support/get/responses/429",
    ] {
        let schema = value
            .pointer(&format!("{pointer}/headers/Retry-After/schema/type"))
            .and_then(Value::as_str);
        assert_eq!(schema, Some("integer"), "{pointer}");
    }
    Ok(())
}

#[tokio::test]
async fn replaces_a_cloudflare_ray_id_that_is_too_long_or_has_other_characters() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;
    let too_long = "a".repeat(65);
    let longest = "a".repeat(64);

    for (ray, kept) in [
        (too_long.as_bytes(), false),
        (b"has space".as_slice(), false),
        (b"quote\"and;semicolon".as_slice(), false),
        (b"caf\xe9".as_slice(), false),
        (longest.as_bytes(), true),
    ] {
        let response = send(
            &app,
            Request::get("/health")
                .header("cf-ray", header::HeaderValue::from_bytes(ray)?)
                .body(Body::empty())?,
        )
        .await?;
        let id = response
            .headers()
            .get("x-request-id")
            .ok_or_else(|| io::Error::other("response has no x-request-id header"))?;
        if kept {
            assert_eq!(id.as_bytes(), ray);
        } else {
            uuid::Uuid::parse_str(id.to_str()?)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn lets_browser_clients_read_the_request_id_and_retry_after() -> TestResult {
    let app = test_app("http://127.0.0.1:9/v2/")?;

    let response = send(
        &app,
        Request::get("/health")
            .header(header::ORIGIN, "https://example.com")
            .body(Body::empty())?,
    )
    .await?;

    let exposed = response
        .headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .ok_or_else(|| io::Error::other("response exposes no headers"))?
        .to_str()?
        .split(',')
        .map(|name| name.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    assert!(exposed.contains("x-request-id"), "{exposed:?}");
    assert!(exposed.contains("retry-after"), "{exposed:?}");
    Ok(())
}

#[tokio::test]
async fn answers_a_duplicate_skin_upload_from_the_queue_response() -> TestResult {
    let server = MockServer::start().await;
    mount_supported_capes(&server, 1).await;
    let mut duplicate = completed_job_response();
    if let Some(flag) = duplicate.pointer_mut("/skin/duplicate") {
        *flag = json!(true);
    }
    if let Some(messages) = duplicate.get_mut("messages") {
        *messages = json!([{ "code": "skin_found", "message": "Found existing skin" }]);
    }
    Mock::given(method("POST"))
        .and(path("/v2/queue"))
        .respond_with(ResponseTemplate::new(200).set_body_json(duplicate))
        .expect(1)
        .mount(&server)
        .await;
    let app = mock_app(&server)?;

    let response = post_upload(&app, "/mineskin/skins").await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await?;
    let encrypted_url = encrypted_skin_url(&body)?;
    assert_eq!(
        body,
        json!({
            "success": true,
            "skin": { "url": encrypted_url },
            "warnings": [],
            "messages": [{ "code": "skin_found", "message": "Found existing skin" }],
            "job": { "id": "job-1", "status": "completed" }
        })
    );
    assert_eq!(
        upstream_requests(&server, Some("/v2/queue/job-1")).await,
        0,
        "a duplicate skin needs no job poll"
    );
    let decrypted = decrypt(&app, encrypted_url).await?;
    assert_eq!(
        json_body(decrypted).await?,
        json!({ "url": format!("https://minesk.in/{SKIN_ID}") })
    );
    server.verify().await;
    Ok(())
}
