# Keep the Rust version equal to rust-toolchain.toml, or rustup downloads it during the build.
FROM docker.io/library/rust:1.100.0-slim-trixie@sha256:3b199fd6db7d709274df56565b8f4003f9e30d7bfcff9d53148c86053b7855e2 AS build
WORKDIR /app
COPY . .
# The startup log shows this commit. A build without it logs `unknown`.
ARG GIT_SHA
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:532c7a94f9e96ba9db75eb9388f4227751131c7cb0a411d1a8521af4096135de
COPY --from=build /app/target/release/axolotl /usr/local/bin/axolotl
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/axolotl"]
