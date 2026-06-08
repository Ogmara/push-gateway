# Changelog

All notable changes to the Ogmara Push Gateway will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.1] - 2026-06-08

### Fixed

- `init` (default config) now emits the `[gateway] public_url` key with guidance
  — it was required (registration fails closed without it / `OGMARA_GATEWAY_URL`)
  but missing from the generated config, so fresh installs hit a silent 503.

### Removed

- Cleanup (audit 2026-06-07 Batch 5): dropped unused dependencies `chrono`,
  `hmac`, `thiserror` (kept `hex` — used by registry-key parsing) and the dead
  `preview` field on `PushTrigger`.

## [0.6.0] - 2026-06-08

Hardening (audit 2026-06-07 fix-plan B4.4).

### Security

- **Token-at-rest encryption (W3).** Push tokens in `registry.json` are now
  AES-256-GCM encrypted with `OGMARA_REGISTRY_KEY` (32-byte base64/hex);
  per-record nonce, versioned blob, transparent legacy-plaintext load + re-encrypt.
  If the key is unset, a loud warning is logged and tokens stay plaintext (dev).
- **Real rate limiting (W1).** Per-IP sliding-window limiter (bounded, evicting)
  on `/register` + `/unregister`, driven by the previously-dead
  `rate_limit_per_sec`. (Keys on peer IP — documented reverse-proxy caveat.)
- **SSRF allowlist via `url::Url` (W7).** The Web Push endpoint host is parsed
  (rejecting embedded userinfo / non-https) and suffix-matched, replacing the
  bypassable string-slicing.

### Changed

- **Bounded registry + debounced persistence + TTL (W2).** Max 100k addresses;
  `persist()` is debounced (≤ every 10s + on shutdown) instead of rewriting the
  whole file per request; stale registrations (>30d) are swept hourly.
- **Parallel push fan-out (W6)** — `send_to_address` dispatches to a wallet's
  devices concurrently (bounded).

### Removed

- **Dead WS listener (W9)** — the empty `listener.rs` stub (idle ws://localhost
  reconnect loop, no dispatch) and `tokio-tungstenite` dep removed; mentions/DMs
  arrive via authenticated `POST /push`.

### Added

- Tests (W8): SSRF allowlist, registry cap/TTL, token encrypt/decrypt, rate
  limiter (27 total, was effectively 0).

## [0.5.0] - 2026-06-08

Security hardening from the 2026-06-07 audit campaign (fix-plan B1.2).

### Security

- **`/register` + `/unregister` now verify a Klever wallet signature (audit
  C1/C2).** Previously these endpoints checked only that auth headers were
  *present* — anyone could register their own push token under any victim
  address and receive that victim's mention pushes (channel_id + msg_id →
  fetchable content). They now Ed25519-verify `x-ogmara-auth` (Klever message
  format) against the public key decoded from `x-ogmara-address`, over a
  canonical claim, and require the signing address to equal the registered
  address (self-registration; device-key delegation is a documented follow-up).
  Both `klv1…` and `ogd1…` addresses are accepted as signers.
- **Host-binding + replay protection (audit C3).** The signed claim is
  `ogmara-push:{action}:{gateway_host}:{nonce}:{timestamp}:{address}:{token}`.
  Binding `gateway_host` (the gateway's configured `public_url` /
  `OGMARA_GATEWAY_URL`) defeats cross-gateway replay; a bounded TTL nonce cache
  rejects same-gateway replay within the ±5min window.
- **rustls-webpki 0.103.10 → 0.103.13 (RUSTSEC-2026-0098/0099/0104,
  cross-cutting B1.5)** — fixes weakened cert-chain validation + a reachable CRL
  panic on outbound TLS (push provider APIs, node WS).

### Added

- `crypto` module: Klever signature verification + bech32 address decoding.
- `[gateway] public_url` config / `OGMARA_GATEWAY_URL` env — the gateway's
  canonical public URL that registration signatures bind to (must match the URL
  clients POST to). Requires sdk-js ≥0.25.0 clients.
- Tests for signature verification and nonce-replay (previously 0 tests).

## [0.4.0] - 2026-04-10

### Added
- Dockerfile with multi-stage build (Rust builder + Debian slim runtime)
- Docker deployment instructions in BUILDING.md and README.md
- Docker Hub badge and image tags (`push-gateway-latest`, `push-gateway-0.4.0`)
- Configuration reference tables (config paths per deployment, env vars for secrets)
- Docker quick start as recommended deployment in README

### Changed
- README rewritten with Docker-first quick start, config location table, and
  environment variable reference

## [0.3.1] - 2026-04-04

### Fixed
- `/register` and `/unregister` no longer reject device-key delegation — the
  auth header address (device key) may legitimately differ from the body
  address (wallet) when using Klever Extension or K5 delegation. Validates
  auth address format (`klv1...`) instead of requiring exact match.

## [0.3.0] - 2026-04-04

### Added
- RFC 8291 Web Push payload encryption via `ece` crate — browsers now accept
  push payloads (previously sent plaintext, which was silently rejected)
- `GET /vapid-key` endpoint — returns the VAPID public key for Web Push
  subscriptions (`PushManager.subscribe({ applicationServerKey })`)
- Persistent device registry — registrations survive gateway restarts via
  atomic JSON file writes (configurable via `registry_file` in config)
- Bearer token authentication on `/push` — accepts both `X-Push-Secret`
  header and `Authorization: Bearer <token>` (compatible with L2 node)
- "reply" notification type support (treated same as mention)

### Changed
- `PushTrigger.channel_id` now accepts both string and number JSON values
  (L2 node sends u64, some clients send string)
- `WebPushKeys.p256dh` and `WebPushKeys.auth` are now required fields
  (were optional, but encryption requires them)
- Web Push body uses `Content-Type: application/octet-stream` with encrypted
  payload instead of raw JSON

### Security
- Constant-time push secret comparison — prevents timing attacks (C1)
- `/unregister` now requires auth headers (was unauthenticated — C3)
- `/push` refuses to serve when no push secret is configured (C4)
- Timestamp validation now rejects both past and future drift > 5 min (W4)

### Fixed
- Auth mismatch: L2 node sends `Authorization: Bearer` but gateway only
  checked `X-Push-Secret` header — now accepts both

## [0.2.0] - 2026-03-29

### Added
- Real FCM HTTP v1 API dispatch with OAuth2 service account JWT (RS256)
  - Automatic access token caching and refresh
  - Full message payload with notification + data fields
- Real APNs HTTP/2 API dispatch with ES256 JWT authentication
  - .p8 auth key support
  - Sandbox/production endpoint selection
  - Device token hex validation
- Real Web Push VAPID dispatch with ES256 JWT
  - SSRF protection: allowlisted push service domains only
    (Mozilla, Apple, Google, Microsoft)
  - Subscription endpoint URL validation (HTTPS required)
- Shared secret authentication on `/push` endpoint (`X-Push-Secret` header)
  - Configurable via `OGMARA_PUSH_SECRET` env var or config
- Wallet signature authentication on `/register` endpoint
  - `X-Ogmara-Auth/Address/Timestamp` header validation
  - Address match enforcement (header must match body)
  - 5-minute timestamp expiry to prevent replay attacks
- Device registration cap (max 10 per address, oldest evicted)
- Error body truncation in logs (200 char max, prevents secret leakage)
- `push_secret` and `rate_limit_per_sec` config fields

### Changed
- CORS restricted to `ogmara.org` + `localhost` (was permissive `*`)
- Custom `Debug` impl for `Config` — redacts FCM/APNs/WebPush secrets
- Removed `Serialize` derive from secret-containing config structs

### Security
- Fixed SSRF vector via Web Push subscription endpoint (C1)
- Fixed unauthenticated /push and /register endpoints (C2)
- Fixed unbounded device registrations per address — DDoS amplification (W1)
- Fixed APNs device token path injection risk (W5)
- Fixed verbose error response body logging (W6)

## [0.1.0] - 2026-03-29

### Added
- Device registration API (POST /register, POST /unregister)
  - Multi-device support per address
  - Platform-specific tokens (FCM, APNs, Web Push)
  - Channel subscription filtering
- Push notification trigger API (POST /push)
  - Mention notifications with channel context
  - DM notifications (no content — privacy preserving)
  - Dispatches to all registered devices for the target address
- WebSocket listener for L2 node connections
  - Auto-reconnect with 5-second backoff
  - Monitors public channel messages for mentions
- Push providers (placeholder — ready for credential integration)
  - FCM (Firebase Cloud Messaging) for Android
  - APNs (Apple Push Notification Service) for iOS
  - Web Push with VAPID for browsers
- Configuration via TOML with safe defaults (localhost-only)
- CLI with run and init subcommands
- Health check and stats endpoints
