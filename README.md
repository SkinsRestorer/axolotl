# Axolotl

Axolotl is the MineSkin proxy that SkinsRestorer uses to upload skins. It sends requests to MineSkin with its own API key, so clients never see that key. It waits for the MineSkin job to finish and returns the skin as an encrypted `skinsrestorer-axolotl://` URL.

Axolotl is a single Rust binary built with Axum and Tokio. It has no database and keeps no state on disk.

This README is for two readers:

- A SkinsRestorer maintainer who calls the API. Read [How it works](#how-it-works) and [API](#api).
- An operator who runs the service. Read [Configuration](#configuration) and the sections after it.

## How it works

1. Upload: a client sends a skin file, a variant, and a cape UUID to `POST /mineskin/skins`. Axolotl checks the request and makes sure that the cape is on the supported cape list.
2. Queue: Axolotl sends the skin to the MineSkin queue (`POST /v2/queue`) with the configured API key. MineSkin returns a job ID.
3. Poll: Axolotl asks MineSkin for the job status (`GET /v2/queue/{jobId}`) until the job completes or fails. The client request stays open during this time.
4. Encrypt: when the job completes, Axolotl encrypts the MineSkin skin ID with AES-256-GCM. The response contains a `skinsrestorer-axolotl://v2/...` URL instead of the MineSkin URL.
5. Decrypt: later, a client sends the encrypted URL to `GET /mineskin/decrypt-url`. Axolotl returns `https://minesk.in/<skin-id>`. Only an Axolotl instance with the same `AES_SECRET_KEY` can decrypt the URL.

## API

Every MineSkin route is under `/mineskin`. A running instance serves [Swagger UI](http://localhost:3000/swagger) at `/swagger` and the [OpenAPI 3.1 document](http://localhost:3000/openapi) at `/openapi`. The OpenAPI document is the complete schema. This section gives the contract that clients depend on.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Redirect to Swagger UI. |
| `GET` | `/health` | Return `{"status":"UP"}`. |
| `POST` | `/mineskin/skins` | Upload a skin and wait for its MineSkin job to complete. |
| `GET` | `/mineskin/jobs/{jobId}` | Get the current state of a MineSkin job. |
| `GET` | `/mineskin/capes` | List the capes that MineSkin supports. |
| `GET` | `/mineskin/cape-support` | Tell whether the MineSkin account has a cape grant, and list the capes if it has one. |
| `GET` | `/mineskin/decrypt-url` | Decrypt an Axolotl URL into a `https://minesk.in/<skin-id>` URL. |

Every error response has a JSON body of the form `{"error": "<message>"}`. This includes `404` for unknown paths and `405` for a wrong method. CORS allows every origin.

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

| Status | Cause |
| --- | --- |
| `200` | The job completed. |
| `400` | A field is missing or not valid, or the cape is not supported. |
| `408` | The request body did not arrive within 30 seconds. |
| `413` | The skin file is larger than 5 MiB, or the request body is larger than 6 MiB. |
| `429` | MineSkin rate-limited the request. |
| `500` | A required secret is missing or not usable. |
| `502` | MineSkin returned an error, or the job failed. The message comes from MineSkin when it gives one. |
| `503` | 16 uploads are already in progress. |
| `504` | The job did not finish within 5 minutes, or the whole upload took longer than 6 minutes 30 seconds. |

A successful upload returns this body:

```json
{
  "success": true,
  "skin": { "url": "skinsrestorer-axolotl://v2/..." },
  "warnings": [],
  "messages": []
}
```

`warnings` and `messages` contain MineSkin items with optional `code` and `message` fields.

### Get a job

`GET /mineskin/jobs/{jobId}` returns the same body as an upload. While the job is still waiting or running, `skin` is `null`. A failed job returns `502` with the error message from MineSkin. A job ID must have 1 to 64 letters, digits, hyphens, or underscores. Other IDs return `400`.

### Capes

`GET /mineskin/capes` returns `{"capes": [{"uuid": "...", "alias": "...", "url": "..."}]}`. The list contains only capes that MineSkin marks as supported.

`GET /mineskin/cape-support` returns `{"hasCapeGrant": true, "capes": [...]}`. If the account has no cape grant, `capes` is empty.

Axolotl keeps the cape list and the cape grant in memory for five minutes. If MineSkin fails during a refresh, Axolotl continues to use the last known value. After a failure, Axolotl waits 5 seconds before it asks MineSkin again.

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

The warnings never show the values. A route that needs a missing secret returns `500` with a JSON error. `/health` works without the secrets.

Axolotl stops cleanly on `SIGTERM` or Ctrl+C. It lets open requests finish first.

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

Railway sets `PORT`, and Axolotl listens on it. Use `/health` as the health check path.

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

The image comes from the "Publish GHCR Image" workflow. It runs only after the "Build and test" workflow passes for a push to `main`, and it builds the commit that CI tested. After it publishes the image, it starts a Dokploy deployment through a webhook.

## Discord status reports

If `DISCORD_WEBHOOK` is set, Axolotl sends a report every five minutes. Each report contains:

- Process uptime, RSS memory, and the 1, 5, and 15-minute system load averages.
- Request totals for successful responses, redirects, client errors, and server errors.
- Error rates, and the average, median, and 95th-percentile request latency.
- Request counts for uploads, jobs, cape routes, URL decryption, health checks, and other routes.
- MineSkin request totals, errors, rate limits, response bytes, and latency.
- Unique client IPs, clients with one request, average requests per IP, and the traffic share of the busiest IP and the busiest five IPs.
- A traffic pattern label: one dominant client, a few dominant clients, broadly distributed traffic, or a mixed distribution.

Axolotl takes the client address from the `CF-Connecting-IP` header. If the header is missing, it uses the address of the direct connection. Axolotl does not check where the header comes from. If clients can connect to Axolotl without Cloudflare, they can set any address in it. Raw addresses stay in memory and never go into the Discord message.

Axolotl tracks up to 100,000 client addresses in one reporting period. It still counts requests above that limit, but it shows them as unattributed traffic.

The counters reset only after Discord accepts a report. If delivery fails, the next report covers the full period since the last accepted report. A restart clears the counters.

## Contributing and support

Read [the contribution guide](CONTRIBUTING.md) to set up a checkout and run the same checks as CI. Read [the support guide](SUPPORT.md) for questions and bug reports. Report vulnerabilities as described in [the security policy](SECURITY.md).
