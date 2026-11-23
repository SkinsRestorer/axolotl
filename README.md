# Axolotl

Axolotl is the MineSkin proxy that SkinsRestorer uses to upload skins. It sends requests to MineSkin with its own API key, so clients never see that key. It waits for the MineSkin job to finish and returns the skin as an encrypted `skinsrestorer-axolotl://` URL.

Axolotl is a single Rust binary built with Axum and Tokio. It has no database and keeps no state on disk. Outbound HTTPS requests to MineSkin and Discord use rustls with the `ring` crypto provider, so the build does not need OpenSSL or a C compiler for TLS. Axolotl checks server certificates against the certificate store of the operating system.

This README is for two readers:

- A SkinsRestorer maintainer who calls the API. Read [How it works](#how-it-works) and [API](#api).
- An operator who runs the service. Read [Configuration](#configuration) and the sections after it.

## How it works

1. Upload: a client sends a skin file, a variant, and a cape UUID to `POST /mineskin/skins`. Axolotl checks the request and makes sure that the cape is on the supported cape list.
2. Queue: Axolotl sends the skin to the MineSkin queue (`POST /v2/queue`) with the configured API key. MineSkin returns a job. If MineSkin already knows the skin, it returns a job that is already complete. In that case, Axolotl skips step 3 and returns the skin at once.
3. Poll: Axolotl asks MineSkin for the job status (`GET /v2/queue/{jobId}`) until the job completes or fails, for at most 60 seconds. The client request stays open during this time.
4. Encrypt: when the job completes, Axolotl encrypts the MineSkin skin ID with AES-256-GCM. The response contains a `skinsrestorer-axolotl://v2/...` URL instead of the MineSkin URL.
5. Decrypt: later, a client sends the encrypted URL to `GET /mineskin/decrypt-url`. Axolotl returns `https://minesk.in/<skin-id>`. Only an Axolotl instance with the same `AES_SECRET_KEY` can decrypt the URL.

## API

Every MineSkin route is under `/mineskin`. A running instance serves [Swagger UI](http://localhost:3000/swagger) at `/swagger` and the [OpenAPI 3.1 document](http://localhost:3000/openapi) at `/openapi`. The OpenAPI document is the complete schema. This section gives the contract that clients depend on.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Redirect to Swagger UI. |
| `GET` | `/health` | Tell whether the process runs. See [Health checks](#health-checks). |
| `GET` | `/ready` | Tell whether the configuration lets the service handle requests. See [Health checks](#health-checks). |
| `POST` | `/mineskin/skins` | Upload a skin and wait for its MineSkin job to complete. |
| `GET` | `/mineskin/jobs/{jobId}` | Get the current state of a MineSkin job. |
| `GET` | `/mineskin/capes` | List the capes that MineSkin supports. |
| `GET` | `/mineskin/cape-support` | Tell whether the MineSkin account has a cape grant, and list the capes if it has one. |
| `GET` | `/mineskin/decrypt-url` | Decrypt an Axolotl URL into a `https://minesk.in/<skin-id>` URL. |

CORS allows every origin, and browsers can read the `x-request-id` and `Retry-After` response headers. Every response has an `x-request-id` header. See [Logs and request IDs](#logs-and-request-ids).

### Errors

Every error response has a JSON body with a message and a code:

```json
{ "error": "Requested cape is not supported", "code": "unsupported_cape" }
```

This includes `404` for unknown paths and `405` for a wrong method. The `error` text is for people and can change. Programs must use `code`, which stays the same.

If an upload fails after Axolotl queued the MineSkin job, for example with `job_timeout`, the body also has `jobId`. Pass it to `GET /mineskin/jobs/{jobId}` to check the job instead of uploading the skin again:

```json
{ "error": "Timed out waiting for MineSkin job to finish", "code": "job_timeout", "jobId": "6564b0c2e1f8a1d2c3b4a5f6" }
```

These are all the codes:

| Code | Status | Cause |
| --- | --- | --- |
| `invalid_wait_ms` | `400` | `waitMs` is not an integer from 250 to 10000. |
| `invalid_upload` | `400` | The upload form is not valid, or a field is missing or not valid. |
| `skin_rejected` | `400` | MineSkin rejected the skin, for example because the image is not a valid skin. |
| `unsupported_cape` | `400` | The cape is not in `GET /mineskin/capes`. |
| `invalid_job_id` | `400` | The job ID has the wrong length or characters that are not permitted. |
| `invalid_encrypted_url` | `400` | `encryptedUrl` is missing, repeated, or not a URL that Axolotl encrypted. |
| `payload_too_large` | `413` | The skin file or the request body is too large. |
| `upload_body_timeout` | `408` | The upload body did not arrive within 8 seconds. |
| `upload_busy` | `503` | 16 uploads are already in progress. |
| `upload_timeout` | `504` | The upload did not finish within its 84-second deadline. |
| `job_not_found` | `404` | MineSkin has no job with this ID. |
| `job_timeout` | `504` | The MineSkin job did not finish within 60 seconds of polling. |
| `mineskin_rate_limited` | `429` | MineSkin rate-limited the MineSkin account of Axolotl. |
| `mineskin_error` | `502` | MineSkin returned an error or a response that Axolotl cannot read, or the job failed. This includes a `504` from MineSkin itself. |
| `not_configured` | `500` | Axolotl has no usable `MINESKIN_API_KEY` or `AES_SECRET_KEY`. |
| `not_found` | `404` | No route matches the path. |
| `method_not_allowed` | `405` | The route does not accept the request method. |
| `bad_request` | `400` | Fallback for a `400` without a more specific code. |
| `request_timeout` | `408` | Fallback for a `408` without a more specific code. |
| `too_many_requests` | `429` | Fallback for a `429` without a more specific code. |
| `service_unavailable` | `503` | Fallback for a `503` without a more specific code. |
| `gateway_timeout` | `504` | Fallback for a `504` without a more specific code. |
| `client_error` | Other `4xx` | Fallback for any other client error. |
| `internal_error` | Other | Fallback for any other status. |

Some `429` and `503` responses have a `Retry-After` header. It gives the number of whole seconds to wait before the client tries again:

- `mineskin_rate_limited` (`429`): Axolotl uses the `Retry-After` value that MineSkin sent, as seconds or as an HTTP date. The value is at least 1 and at most 3600. If MineSkin sent no value that Axolotl can read, the response has no header.
- `upload_busy` (`503`): the value is always `5`.

### Upload a skin

Send `POST /mineskin/skins` as `multipart/form-data` with these fields:

| Field | Required | Rules |
| --- | --- | --- |
| `file` | Yes | The skin image. It must not be empty and must be 5 MiB or smaller. |
| `variant` | Yes | `classic` or `slim`. |
| `capeUuid` | Yes | A UUID from `GET /mineskin/capes`. Axolotl also accepts the older field name `cape`. |
| `name` | No | At most 48 characters after Axolotl removes whitespace at the start and end. Each character must be a letter (`A-Z`, `a-z`), a digit, a space, a dot, a hyphen, or an underscore. |

Axolotl checks the name because MineSkin rejects other names with a generic validation error.

The optional `waitMs` query parameter sets the time between job polls in milliseconds. It must be an integer from 250 to 10000. The default is 1000. Other values return `400` with the message `waitMs must be an integer between 250 and 10000`. MineSkin asks clients to poll a job at most once per second, so Axolotl waits at least 1000 ms between polls even when `waitMs` is lower.

If a poll fails with a temporary error, such as a rate limit, Axolotl polls again. Each failed poll in a row doubles the wait, up to 10 seconds. After a successful poll, Axolotl uses the `waitMs` interval again. Axolotl does not queue the skin a second time, because the job already exists. If MineSkin sends a response that Axolotl cannot read three times in a row, the upload fails with `502` and the reason.

The upload returns these status codes:

| Status | Codes | Cause |
| --- | --- | --- |
| `200` | | The job completed. |
| `400` | `invalid_wait_ms`, `invalid_upload`, `unsupported_cape`, `skin_rejected` | A field is missing or not valid, the cape is not supported, or MineSkin rejected the skin. |
| `408` | `upload_body_timeout` | The request body did not arrive within 8 seconds. |
| `413` | `payload_too_large` | The skin file is larger than 5 MiB, or the request body is larger than 6 MiB. |
| `429` | `mineskin_rate_limited` | MineSkin rate-limited the request. The response can have a `Retry-After` header. |
| `500` | `not_configured` | A required secret is missing or not usable. |
| `502` | `mineskin_error` | MineSkin returned an error, or the job failed. The message comes from MineSkin when it gives one. |
| `503` | `upload_busy` | 16 uploads are already in progress. The response has `Retry-After: 5`. |
| `504` | `job_timeout`, `upload_timeout` | The job did not finish within 60 seconds of polling, or the whole upload took longer than 84 seconds. A `job_timeout` body has `jobId`. |

A successful upload returns this body:

```json
{
  "success": true,
  "skin": { "url": "skinsrestorer-axolotl://v2/..." },
  "warnings": [],
  "messages": [],
  "job": { "id": "6650a1b2c3d4e5f6a7b8c9d0", "status": "completed" }
}
```

`warnings` and `messages` contain MineSkin items with optional `code` and `message` fields. `job.id` is the MineSkin job ID. `job.status` is one of `waiting`, `active`, `processing`, `completed`, `failed`, or `unknown`. Axolotl uses `unknown` for a state that MineSkin added after this version of Axolotl, and treats such a job as one that is still running.

### Upload timeouts

An upload has these time limits:

| Limit | Value | Applies to |
| --- | --- | --- |
| Body | 8 seconds | Axolotl reads the multipart body. |
| MineSkin request | 8 seconds | Each request to MineSkin, for example the cape list, the queue request, or one status poll. |
| Polling | 60 seconds | All status polls of one job together. |
| Upload deadline | 84 seconds | The whole upload, from the time it gets an upload slot. |

The upload deadline is the polling time plus three 8-second steps: the body, the cape check, and the queue request. The skinsrestorer.net site stops waiting for Axolotl after 90 seconds, and Cloudflare closes origin requests after about 100 seconds. The 84-second deadline makes sure that Axolotl sends its own `504` with an error code before the client or Cloudflare gives up.

A `504` with `job_timeout` does not cancel the MineSkin job. The error body contains its `jobId`, so the client can check the job later with `GET /mineskin/jobs/{jobId}`.

### Get a job

`GET /mineskin/jobs/{jobId}` asks MineSkin for the job once and does not wait. It returns the same body as an upload, with the `job` object. While the job is still waiting or running, `skin` is `null`. A job ID must have 1 to 64 letters, digits, hyphens, or underscores.

| Status | Code | Cause |
| --- | --- | --- |
| `400` | `invalid_job_id` | The job ID is not valid. |
| `404` | `job_not_found` | MineSkin has no job with this ID. |
| `429` | `mineskin_rate_limited` | MineSkin rate-limited the request. The response can have a `Retry-After` header. |
| `500` | `not_configured` | A required secret is missing or not usable. |
| `502` | `mineskin_error` | The job failed, or MineSkin returned an error. The message comes from MineSkin when it gives one. |

### Capes

`GET /mineskin/capes` returns `{"capes": [{"uuid": "...", "alias": "...", "url": "..."}]}`. The list contains only capes that MineSkin marks as supported.

`GET /mineskin/cape-support` returns `{"hasCapeGrant": true, "capes": [...]}`. If the account has no cape grant, `capes` is empty.

Axolotl keeps the cape list and the cape grant in memory for five minutes. If MineSkin fails during a refresh, Axolotl continues to use the last known value. After a failure, Axolotl waits 5 seconds before it asks MineSkin again. If MineSkin sent `Retry-After`, Axolotl waits that long instead, up to one minute.

### Encrypted URLs

New URLs have the form `skinsrestorer-axolotl://v2/<payload>`. The payload is AES-256-GCM output in URL-safe base64. Each URL uses a new random nonce, so the same skin gives a different URL each time.

Send the URL to `GET /mineskin/decrypt-url?encryptedUrl=<url>`. The response is `{"url": "https://minesk.in/<skin-id>"}`. The skin ID is always 32 hexadecimal digits without hyphens. MineSkin reads a `minesk.in` link only up to the first character that is not a letter or digit, so a hyphenated ID does not work.

The decrypt route also accepts URLs from the earlier AES-CBC service. An encrypted URL that is not valid returns `400`.

## Configuration

Axolotl reads its configuration from environment variables. It also loads a `.env` file when one exists in the current directory or a parent directory.

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `MINESKIN_API_KEY` | For MineSkin routes | None | Authenticates requests to MineSkin. The `Bearer` prefix is optional, in any letter case. URL decryption does not need it. |
| `AES_SECRET_KEY` | For skin and decrypt routes | None | Axolotl derives the AES-256 key from this value with SHA-256. Uploads, job lookups, and URL decryption need it. |
| `DISCORD_WEBHOOK` | No | Disabled | Discord webhook URL for [status reports](#discord-status-reports). A blank value disables reports. |
| `PORT` | No | `3000` | TCP port. Axolotl listens on all interfaces (`0.0.0.0`). |
| `RUST_LOG` | No | `axolotl=info` | Log filter. If the value is not valid, Axolotl logs a warning and uses the default. |

Keep `AES_SECRET_KEY` the same across deployments. If you change it, Axolotl cannot decrypt the URLs that it made before. Whitespace in the value is part of the key.

Axolotl does not start in these cases:

- `PORT` is not a valid TCP port.
- `DISCORD_WEBHOOK` is not a valid HTTPS URL.
- A variable is not valid Unicode. The error names the variable but does not show its value.

Axolotl prints the error as `Error: <message>` and exits with a failure code.

Axolotl starts but logs a warning in these cases:

- `MINESKIN_API_KEY` or `AES_SECRET_KEY` is missing or blank.
- `MINESKIN_API_KEY` is not a usable bearer token, for example the word `Bearer` alone or a key with control characters.
- `AES_SECRET_KEY` has whitespace at the start or end.

The warnings never show the values. A route that needs a missing secret returns `500` with the code `not_configured`. `/health` works without the secrets, but `/ready` returns `503`.

When the server starts, Axolotl logs one `Axolotl server started` line. The line has the version, the Git commit, the address, and whether Discord reports, `MINESKIN_API_KEY`, and `AES_SECRET_KEY` are set. Axolotl reads the commit from the `GIT_SHA` environment variable at compile time. The publish workflow sets it to the full commit SHA. A build without `GIT_SHA` logs `unknown`. To set it for a local build, run:

```bash
GIT_SHA="$(git rev-parse HEAD)" cargo build --release
```

Axolotl stops cleanly on `SIGTERM` or Ctrl+C. It lets open requests finish first.

## Health checks

Axolotl has two health endpoints:

| Path | `200` response | Other response | Use |
| --- | --- | --- | --- |
| `/health` | `{"status":"UP"}` | None | Liveness. The process runs and answers HTTP requests. |
| `/ready` | `{"status":"READY"}` | `503` with `{"status":"NOT_READY","missing":["MINESKIN_API_KEY"]}` | Readiness. The configuration lets Axolotl handle every route. |

`/ready` lists each required variable that is missing or not usable: `MINESKIN_API_KEY`, `AES_SECRET_KEY`, or both. It uses the same checks as the routes that need the values. It does not send a request to MineSkin, so a MineSkin outage does not make it fail.

Use `/ready` for the Dokploy health check. Then Dokploy does not send traffic to a deployment that lost a secret and fails every upload with `500`. `/health` returns `200` even then.

## Logs and request IDs

Axolotl writes logs to standard output. `RUST_LOG` sets the filter. See [Configuration](#configuration).

Each request gets an ID. If the request has a `cf-ray` header from Cloudflare with 1 to 64 letters, digits, or hyphens, Axolotl uses its value. Otherwise, Axolotl makes a random UUID, for example for a probe that connects to the container directly. The response returns the ID in the `x-request-id` header. Every log line that Axolotl writes for the request contains `request_id`. To find a failed request in the logs, ask the user for the `x-request-id` value or look up the Ray ID in Cloudflare.

When a request is complete, Axolotl writes one access log line with the method, the path, the status, and `latency_ms`. The path does not contain the query string, because `decrypt-url` gets encrypted skin URLs in the query. Lines for `/health` and `/ready` use the debug level, so the default filter `axolotl=info` hides them. Server errors (`5xx`) also get an error line with the message. MineSkin rate limits and `upload_busy` rejections get a warning line. Log lines have color codes only when standard output is a terminal.

## Run locally

You need:

- Rustup. The repository contains `rust-toolchain.toml`, so Rustup selects the correct Rust version.
- A MineSkin API key.

Set the two secrets:

```bash
export MINESKIN_API_KEY="your-mineskin-api-key"
export AES_SECRET_KEY="a-long-random-secret"
```

Start the server from the repository root:

```bash
cargo run
```

Open `http://localhost:3000/swagger` to try the API.

## Deploy with Railpack

[Railpack](https://railpack.com/languages/rust) finds the root `Cargo.toml`, selects the Rust version from `rust-toolchain.toml`, builds the release binary, and starts `./bin/axolotl`. You do not need a custom build or start command.

1. Set `MINESKIN_API_KEY` and `AES_SECRET_KEY` in the deployment environment.
2. Deploy the repository.

Railway sets `PORT`, and Axolotl listens on it. Use `/ready` as the health check path. If the build has no `GIT_SHA` variable, the startup log shows the commit as `unknown`.

## Run the published image

The repository publishes a multi-architecture image (`amd64` and `arm64`) to `ghcr.io/skinsrestorer/axolotl`. Each build has three tags:

- `latest` and `main`: the newest build from `main`.
- `sha-<12-character-commit-sha>`: the build of one commit.

Put the environment variables in a `.env` file. Then run:

```bash
docker run -d --name axolotl --restart unless-stopped \
  --env-file .env -p 3000:3000 ghcr.io/skinsrestorer/axolotl:latest
```

The service is available at `http://localhost:3000`.

The image comes from the "Publish GHCR Image" workflow. It runs only after the "Build and test" workflow passes for a push to `main`, and it builds the commit that CI tested. It sets `GIT_SHA` to that commit, so the startup log shows it. After it publishes the image, it starts a Dokploy deployment through a webhook.

### Roll back a deployment

Do this procedure when a new image breaks production and a fix on `main` takes too long:

1. Find the last commit that worked. The startup log of the earlier deployment shows it as `commit`. The `sha-` tag uses the first 12 characters of the commit SHA.
2. In Dokploy, change the image of the Axolotl application from `ghcr.io/skinsrestorer/axolotl:latest` to `ghcr.io/skinsrestorer/axolotl:sha-<12-character-commit-sha>`. Use the tag without an `-amd64` or `-arm64` suffix. That tag points to the image for both architectures.
3. Redeploy the application in Dokploy.
4. Make sure that `/ready` returns `200` and that the startup log shows the commit that you selected.

The `latest` and `main` tags do not change during the rollback. The next push to `main` that passes CI moves them to a new build. While the image is pinned, the webhook of that build redeploys the pinned image. To return to normal deployments, set the image back to `ghcr.io/skinsrestorer/axolotl:latest` and redeploy.

## Discord status reports

If `DISCORD_WEBHOOK` is set, Axolotl sends a report every five minutes. Each report is one Discord embed with these parts:

- Title: `Axolotl: Healthy`, `Axolotl: Degraded`, or `Axolotl: Failing`. The embed color is green, orange, or red.
- Headline: the number of server errors and their share of all requests, the number of MineSkin errors and rate limits, and the number of requests in the period. Example: `4 server errors (2.0%) · 6 MineSkin errors (2 rate limits) · 200 requests in 5 min`. A period without errors shows `No errors`. A period without traffic shows `No requests in 5 min`.
- Uploads and Decryptions: requests, `5xx` and `4xx` responses, and the 95th-percentile latency for `POST /mineskin/skins` and `GET /mineskin/decrypt-url`.
- MineSkin: calls, errors, rate limits, and the 95th-percentile latency of the requests to MineSkin.
- Clients: unique client IPs, the share of requests from the busiest IP, and requests that Axolotl did not assign to an IP.
- Footer: the version, the first 7 characters of the commit, the uptime, the RSS memory, and the 1, 5, and 15-minute system load averages.

The latency values come from histogram buckets. A value such as `p95 ≤ 250 ms` gives the upper limit of the bucket. Above 60 seconds, the report shows `p95 > 60 s`.

The status in the title comes from three error rates in the period. The worst result sets the status:

| Rate | Degraded | Failing |
| --- | --- | --- |
| `5xx` responses / all requests | 1% or more | 5% or more |
| Failed MineSkin calls / all MineSkin calls | 10% or more | 50% or more |
| Rate-limited MineSkin calls / all MineSkin calls | 5% or more | None |

A rate counts fully only when it comes from 3 or more errors. With 1 or 2 errors, a rate at the Failing level gives `Degraded`, and a lower rate gives `Healthy`. Thus one failure in a quiet period does not cause `Failing`, but a quiet service where every request fails does not show `Healthy`. The headline always shows every error. Failed MineSkin calls include rate-limited calls, so a high rate-limit rate can also cause `Failing` through the failed-call rate.

Axolotl takes the client address from the `CF-Connecting-IP` header. If the header is missing, it uses the address of the direct connection. Axolotl does not check where the header comes from. If clients can connect to Axolotl without Cloudflare, they can set any address in it. Raw addresses stay in memory and never go into the Discord message.

Axolotl tracks up to 100,000 client addresses in one reporting period. It still counts requests above that limit, but it shows them as unattributed traffic.

The counters reset only after Discord accepts a report. If delivery fails, the next report covers the full period since the last accepted report. A restart clears the counters.

## Contributing and support

Read [the contribution guide](CONTRIBUTING.md) to set up a checkout and run the same checks as CI. Read [the support guide](SUPPORT.md) for questions and bug reports. Report vulnerabilities as described in [the security policy](SECURITY.md).
