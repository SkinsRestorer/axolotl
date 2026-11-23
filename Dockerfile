# Keep the Rust version equal to rust-toolchain.toml, or rustup downloads it during the build.
FROM docker.io/library/rust:1.100.0-slim-trixie@sha256:6f14b2b4b278ec0d50aa1d69541c304ce0f95e0f6268487aa9924af1c2e9aebe AS build
WORKDIR /app
COPY . .
# The startup log shows this commit. A build without it logs `unknown`.
ARG GIT_SHA
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:532c7a94f9e96ba9db75eb9388f4227751131c7cb0a411d1a8521af4096135de
COPY --from=build /app/target/release/axolotl /usr/local/bin/axolotl
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/axolotl"]
