# Changelog

All notable changes to the Ogmara Push Gateway will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.1] - 2026-10-21

### Security

- **Dependency (runtime, Rust):** `rustls-webpki` 0.103.15 → 0.103.16
  (RUSTSEC-2026-0382) and `webpki-root-certs` 1.0.6 → 1.0.10
  (RUSTSEC-2026-0383) via `cargo update` (lockfile only). Shipped code: the
  TLS certificate verification used for every outbound push-provider
  connection. `cargo audit` reports 0 vulnerabilities; tests (35), clippy and
  the build pass.

## [0.8.0] - 2026-10-20

### Added

- **`channel_invite` push notifications** (spec 05 §6.4). The L2 node has
  sent `channel_invite` triggers to `POST /push` since l2-node 0.128.0, but
  the gateway answered every one of them with HTTP 400 ("unknown
  notification type"), so invites never produced a push. The gateway now
  accepts them and delivers `{"title": "Ogmara", "body": "You were invited
  to a channel"}` with `data = {type, channel_id, sender, msg_id,
  timestamp}` over FCM, APNs and Web Push.

### Security

- **Invite triggers are strictly validated and minimised.** `channel_id`
  must be a `u64` (JSON number or decimal string), `sender` a bounded
  `klv1…`/`ogd1…` bech32-charset address, and `msg_id` exactly 64 hex
  chars; anything else is rejected with 400 instead of being defaulted to an
  empty string. The outgoing payload is rebuilt from typed fields only, so an
  `invite_envelope` / `invite_expires_at` / `anchor_node` sent by a node is
  dropped and never reaches a third-party push provider. The channel name is
  deliberately left out of the invite text: invites usually target private
  channels and the rendered text is shown on lock screens and handled by
  FCM/APNs. Unit tests pin the Web Push JSON and FCM string-map wire forms
  to the five allowed keys (the APNs custom-data arm mirrors them).
- The caller-supplied notification `type` is length-capped before it is
  logged on rejection.
- **Dependency advisories cleared (`cargo audit`: 4 → 0)** via a targeted
  `cargo update`, no manifest changes:
  - `rustls` 0.23.37 → 0.23.46 (RUSTSEC-2026-0285 and RUSTSEC-2026-0346/0347/0348/0349, TLS 1.3 handshake
    messages accepted across encryption-level boundaries, medium).
    **Runtime code**: every outbound TLS connection to FCM/APNs/Web Push.
    Pulled `aws-lc-rs` 1.16.2 → 1.18.2 / `aws-lc-sys` 0.39.1 → 0.46.0 and
    `rustls-webpki` 0.103.13 → 0.103.15 along; the RS256 OpenSSL test vector
    still matches byte-for-byte.
  - `quinn-proto` 0.11.17 → 0.11.19 (RUSTSEC-2026-0338, -0340, -0343).
    Lockfile-only: reqwest's HTTP/3 feature is not enabled, so the crate is
    not compiled into the gateway.
  - `chacha20` 0.10.1 → 0.10.2 (yanked-version warning). Lockfile-only, not
    compiled into the gateway.

### Changed

- `POST /push` payload construction moved into a pure `build_payload()`
  function (unit-testable); `mention`, `reply` and `dm` behaviour is
  unchanged.

## [0.7.0] - 2026-08-25

Pre-mainnet dependency-security pass. `cargo audit` now reports
**0 vulnerabilities** for this component (was 3).

### Security

- **Replaced the `rsa` crate with `aws-lc-rs` for RS256 signing**
  (RUSTSEC-2023-0071, "Marvin Attack" — potential RSA key recovery through
  timing sidechannels, medium/5.9). **Runtime code**: the affected path is the
  FCM HTTP v1 service-account JWT signature, i.e. every push we send through
  Firebase. The advisory has **no patched release** of `rsa` — 0.9.x is the
  latest stable and the fix only exists in the unreleased 0.10 line — so the
  only real remediation was to change backend. `aws-lc-rs` was already present
  in the dependency tree via `rustls`, so this removes a dependency rather than
  adding one, and brings a constant-time AWS-LC implementation.
  RSASSA-PKCS1-v1_5 is deterministic, so a new test pins the output against an
  OpenSSL-generated vector — signatures are byte-identical to before, and FCM
  authentication behaviour is unchanged.
- **Bumped `h2` 0.4.13 → 0.4.19** (RUSTSEC-2026-0258, unbounded empty DATA
  frames). **Runtime code**: reached via both `axum` (our inbound registration
  API) and `reqwest` (outbound provider calls). Lockfile-only bump.
- **Bumped `quinn-proto` 0.11.14 → 0.11.17** (RUSTSEC-2026-0185, remote memory
  exhaustion via unbounded out-of-order stream reassembly, high/7.5).
  **Runtime code**, reached transitively through `reqwest`. Lockfile-only bump.
- **Bumped `anyhow` 1.0.102 → 1.0.104** (RUSTSEC-2026-0190, unsoundness in
  `Error::downcast_mut()`, memory-corruption category). Informational advisory,
  cleared for completeness.

### Added

- Tests: `sign_rsa_matches_openssl_rs256_vector` (cross-implementation vector
  proving the `aws-lc-rs` migration is byte-compatible) and
  `sign_rsa_rejects_malformed_key`.

### Changed

- `PushDispatcher::sign_rsa` is now an associated function rather than a method
  — it never used `self`, and this makes it directly testable.

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
