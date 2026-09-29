# syntax=docker/dockerfile:1.18

FROM rust:1.98.1-trixie@sha256:a8a5f0a1e5fe7dfe1d352591e4a1c7dd2c08fd70475cae872cf3458ba0df0546 AS builder

WORKDIR /workspace

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY apps ./apps
COPY crates ./crates
COPY migrations ./migrations
COPY resources ./resources

RUN cargo build --locked --release --bin sahayak-api --bin sahayak-migrator --bin sahayak-worker

FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132 AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        libssl3t64=3.5.7-1~deb13u2 \
        openssl-provider-legacy=3.5.7-1~deb13u2 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 sahayak \
    && useradd --uid 10001 --gid sahayak --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sahayak

WORKDIR /app
USER sahayak:sahayak

FROM runtime AS worker
COPY --from=builder --chown=sahayak:sahayak /workspace/target/release/sahayak-worker /usr/local/bin/sahayak-worker
ENTRYPOINT ["/usr/local/bin/sahayak-worker"]

FROM runtime AS migrator
COPY --from=builder --chown=sahayak:sahayak /workspace/target/release/sahayak-migrator /usr/local/bin/sahayak-migrator
ENTRYPOINT ["/usr/local/bin/sahayak-migrator"]

FROM runtime AS api
COPY --from=builder --chown=sahayak:sahayak /workspace/target/release/sahayak-api /usr/local/bin/sahayak-api
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sahayak-api"]
