# syntax=docker/dockerfile:1
FROM rust:1.98-bookworm AS builder
RUN rustup toolchain install nightly --profile minimal && rustup default nightly
WORKDIR /build/heimdall
COPY Cargo.toml Cargo.lock /build/heimdall/
COPY src /build/heimdall/src
COPY web /build/heimdall/web
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/heimdall/target/release/heimdall /usr/local/bin/heimdall
ENV HEIMDALL_DATA=/data
WORKDIR /data
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["heimdall"]
