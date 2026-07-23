# Axolotl

Axolotl is the MineSkin proxy used by SkinsRestorer. It forwards authenticated skin and cape requests without exposing the MineSkin API key, waits for queued skin jobs, and converts MineSkin URLs into encrypted `skinsrestorer-axolotl://` URLs.

The service is a single Rust binary built with Axum and Tokio. It has no database or persistent local state.

## Requirements

- Rust 1.95.0
- A MineSkin API key
- A stable encryption secret

The repository includes `rust-toolchain.toml`, so Rustup selects the correct toolchain automatically.

## Run locally

Set the required environment variables:

```bash
export MINESKIN_API_KEY="your-mineskin-api-key"
export AES_SECRET_KEY="a-long-random-secret"
```

Start the server:

```bash
cargo run
```

Axolotl listens on port `3000` by default. Open [Swagger UI](http://localhost:3000/swagger) or fetch the [OpenAPI 3.1 document](http://localhost:3000/openapi).

Axolotl also loads variables from a local `.env` file when one exists.

## Configuration

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `MINESKIN_API_KEY` | For MineSkin routes | None | Authenticates outbound MineSkin requests. The `Bearer` prefix is optional. |
| `AES_SECRET_KEY` | For encrypted URL routes | None | Derives the AES-256 key used for existing Axolotl URLs. Keep this value stable across deployments. |
| `PORT` | No | `3000` | TCP port for the HTTP server. Railpack and Railway provide this automatically. |
| `RUST_LOG` | No | `axolotl=info,tower_http=info` | Controls structured log filtering. |

Missing route-specific credentials return a JSON configuration error. The health endpoint remains available without them.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Report service health. |
| `POST` | `/mineskin/skins` | Upload a skin and wait for its MineSkin job to complete. |
| `GET` | `/mineskin/jobs/{jobId}` | Fetch and sanitize a MineSkin job. |
| `GET` | `/mineskin/capes` | List supported capes. Results are cached for five minutes. |
| `GET` | `/mineskin/cape-support` | Check the configured account's cape grant and list usable capes. |
| `GET` | `/mineskin/decrypt-url` | Decrypt an Axolotl URL into its original `https://minesk.in/` URL. |

Skin uploads accept up to 5 MiB. Axolotl processes up to 16 uploads at once and returns `503` when every upload slot is occupied. Upload bodies and complete upload workflows have deadlines, while MineSkin polling can run for at most five minutes and returns `504` if processing does not finish in time.

New encrypted URLs use an authenticated `v2` payload. The decryption endpoint continues to accept URLs created by the legacy AES-CBC service.

## Deploy with Railpack

[Railpack](https://railpack.com/languages/rust) detects the root `Cargo.toml`, selects Rust 1.95.0 from `rust-toolchain.toml`, builds the release binary, and starts `./bin/axolotl`. No custom build or start command is required.

Configure `MINESKIN_API_KEY` and `AES_SECRET_KEY` in the deployment environment, then deploy the repository. On Railway, Axolotl listens on the injected `PORT` and exposes `/health` for deployment health checks.

## Validate changes

Run the same checks used by CI:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo build --release --locked
```

The tests include a fixed compatibility vector from the previous service. This protects existing encrypted URLs while the implementation remains in Rust.
