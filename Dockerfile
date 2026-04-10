# Ogmara Push Notification Gateway — Multi-stage Docker build
#
# Build:  docker build -t ogmara/ogmara:push-gateway-0.3.1 .
# Run:    docker run -v ./push-gateway.toml:/etc/ogmara/push-gateway.toml:ro \
#           -v push-gw-data:/data -p 41722:41722 \
#           ogmara/ogmara:push-gateway-0.3.1

# --- Stage 1: Build ---
FROM rust:1.94-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

# Build release binary
RUN cargo build --release && strip target/release/ogmara-push-gateway

# --- Stage 2: Runtime ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin ogmara \
    && mkdir -p /data /etc/ogmara \
    && chown ogmara:ogmara /data

COPY --from=builder /build/target/release/ogmara-push-gateway /usr/local/bin/ogmara-push-gateway
COPY push-gateway.example.toml /etc/ogmara/push-gateway.example.toml

USER ogmara
WORKDIR /data

# Push gateway API
EXPOSE 41722/tcp

ENTRYPOINT ["ogmara-push-gateway"]
CMD ["--config", "/etc/ogmara/push-gateway.toml"]
