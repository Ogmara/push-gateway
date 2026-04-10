# Changelog

All notable changes to the Ogmara Push Gateway will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
