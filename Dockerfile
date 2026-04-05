# --- Build stage ---
FROM rust:1.94-bookworm AS builder
ARG FEATURES
RUN test -n "$FEATURES" || (echo "FEATURES required (testnet or mainnet)" && exit 1)
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release --features "$FEATURES"

# --- Runtime stage ---
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/zns-indexer /usr/local/bin/zns-indexer
EXPOSE 3000
ENTRYPOINT ["zns-indexer"]
