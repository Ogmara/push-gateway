# Changelog

All notable changes to the Ogmara Push Gateway will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
