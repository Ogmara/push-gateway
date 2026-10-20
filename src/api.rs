//! REST API for device registration and push notification triggers.
//!
//! Endpoints:
//!   POST /register   — register a device for push notifications (requires wallet sig)
//!   POST /unregister — remove a device registration
//!   POST /push       — receive a push notification from an L2 node (requires shared secret)
//!   GET  /health     — health check
//!   GET  /stats      — gateway statistics

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Extension};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use std::net::SocketAddr;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::warn;

use dashmap::DashMap;

use crate::crypto;
use crate::push::{self, PushDispatcher};
use crate::registry::{DeviceRegistry, RegisterRequest};

/// Max age of a registration auth timestamp in the PAST (5 minutes).
const REG_AUTH_WINDOW_MS: u64 = 300_000;
/// Max tolerated clock skew into the FUTURE (60s) — asymmetric, like the node
/// verifier. Shrinks the pre-mintable-token / replay surface (audit follow-up).
const REG_AUTH_FUTURE_SKEW_MS: u64 = 60_000;
/// Nonce-replay cache TTL. Must outlive the *entire* acceptance span of a
/// timestamp (a claim stamped at max future skew stays valid as "past" until
/// `ts + REG_AUTH_WINDOW_MS`), else a request could be replayed after its nonce
/// evicts but before its timestamp ages out (audit follow-up W1). Span =
/// future-skew + past-window; +1 future-skew margin.
pub const NONCE_TTL_MS: u64 = REG_AUTH_WINDOW_MS + 2 * REG_AUTH_FUTURE_SKEW_MS;
/// Nonce length bounds (hex chars): the SDK mints 16 bytes → 32 hex.
const MIN_NONCE_LEN: usize = 32;
const MAX_NONCE_LEN: usize = 128;
/// Max distinct live nonces tracked before new registrations are refused
/// (bounds replay-cache memory).
const MAX_NONCES: usize = 100_000;

/// Constant-time string comparison to prevent timing attacks on secrets.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes()
        .iter()
        .zip(b.as_bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Replay-protection cache for registration nonces (audit 2026-06-07 C3).
/// Maps `"{address}:{nonce}"` → expiry unix-ms. Bounded; lazily sweeps
/// expired entries when it grows.
pub struct NonceCache {
    seen: DashMap<String, u64>,
    ttl_ms: u64,
}

impl NonceCache {
    pub fn new(ttl_ms: u64) -> Self {
        Self { seen: DashMap::new(), ttl_ms }
    }

    /// Record `key` as used. Returns `true` if it was fresh, `false` if it is
    /// a replay (still-live) or the cache is full of live entries. The
    /// get-then-set is atomic per key via the DashMap entry API (the shard
    /// lock is held across read+write), so a nonce is strictly single-use even
    /// under concurrent requests.
    pub fn claim(&self, key: String) -> bool {
        let now = now_ms();
        // Bound memory: sweep expired entries when full; refuse if still full
        // of live entries. Done BEFORE taking an entry lock (len()/retain lock
        // shards and would deadlock against a held entry).
        if self.seen.len() >= MAX_NONCES {
            self.seen.retain(|_, exp| *exp > now);
            if self.seen.len() >= MAX_NONCES {
                return false;
            }
        }
        match self.seen.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut e) => {
                if *e.get() > now {
                    return false; // still-live → replay
                }
                *e.get_mut() = now + self.ttl_ms; // expired → reclaim
                true
            }
            dashmap::mapref::entry::Entry::Vacant(v) => {
                v.insert(now + self.ttl_ms);
                true
            }
        }
    }
}

/// Per-IP sliding-window rate limiter (audit 2026-06-07 W1).
///
/// `config.rate_limit_per_sec` was deserialized but never enforced — the router
/// only installed CORS + Trace. This bounds the abuse surface on the
/// signature-verifying `/register` + `/unregister` endpoints (each request
/// triggers an Ed25519 verify and a nonce-cache write, so flooding them is a
/// CPU/memory DoS vector).
///
/// Implementation: a bounded `DashMap<IpAddr, window>` where each window holds
/// the count of requests in the current 1-second bucket. Buckets reset on the
/// second boundary. Memory is capped at `MAX_TRACKED_IPS`; when full, stale
/// (expired-window) entries are swept, and if still full the limiter fails
/// CLOSED for *new* IPs (refuses) to avoid unbounded growth under a spoofed-IP
/// flood.
///
/// LIMITATION: behind a reverse proxy the peer address is the proxy, so all
/// traffic shares one bucket. A full `X-Forwarded-For` trust set (which hops to
/// trust) is out of scope here; deployments behind a proxy should rate-limit at
/// the proxy. We deliberately key on the real peer IP rather than a spoofable
/// header.
///
/// LIMITATION (audit follow-up B4.4 W-1): this bounds MEMORY, not an L3
/// source-IP-spoofing flood. An attacker spamming distinct spoofed source IPs
/// within one second pins the map at the cap; the limiter then fails closed for
/// new IPs (collateral refusal of legitimate new clients) until the window
/// rolls. Real L3/L4 DoS resistance must come from the proxy / network layer —
/// this limiter is for honest-but-abusive single-IP clients.
pub struct RateLimiter {
    /// IP → (window-start unix-secs, count-in-window).
    buckets: DashMap<IpAddr, (u64, u32)>,
    /// Max requests per IP per second.
    limit: u32,
}

/// Max distinct IPs tracked before eviction kicks in (bounds limiter memory).
const MAX_TRACKED_IPS: usize = 100_000;

impl RateLimiter {
    pub fn new(limit: u32) -> Self {
        Self {
            buckets: DashMap::new(),
            // A limit of 0 would lock everyone out; treat it as "disabled" via
            // a very high effective cap is wrong for a security control, so we
            // clamp to at least 1.
            limit: limit.max(1),
        }
    }

    /// Returns `true` if a request from `ip` is allowed, `false` if it exceeds
    /// the per-second limit. Atomic per key via the DashMap entry API.
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = now_ms() / 1000; // 1-second buckets

        // Bound memory: when full, sweep entries whose window has rolled over,
        // then refuse new IPs if still full.
        if self.buckets.len() >= MAX_TRACKED_IPS && !self.buckets.contains_key(&ip) {
            self.buckets.retain(|_, (start, _)| *start == now);
            if self.buckets.len() >= MAX_TRACKED_IPS {
                return false;
            }
        }

        let mut entry = self.buckets.entry(ip).or_insert((now, 0));
        let (start, count) = &mut *entry;
        if *start != now {
            // New 1-second window — reset.
            *start = now;
            *count = 0;
        }
        if *count >= self.limit {
            return false;
        }
        *count += 1;
        true
    }
}

/// Axum middleware enforcing [`RateLimiter`] on the wrapped routes (audit
/// 2026-06-07 W1). Keyed on the peer IP from `ConnectInfo`.
async fn rate_limit_middleware(
    Extension(state): Extension<Arc<ApiState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
    next: Next,
) -> axum::response::Response {
    if !state.rate_limiter.check(peer.ip()) {
        warn!(ip = %peer.ip(), "rate limit exceeded");
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    next.run(req).await
}

/// Shared state for API handlers.
pub struct ApiState {
    pub registry: Arc<DeviceRegistry>,
    pub dispatcher: Arc<PushDispatcher>,
    /// Shared secret for L2 node → gateway authentication on /push.
    pub push_secret: String,
    /// VAPID public key (base64url-encoded uncompressed P-256 point).
    /// Empty if Web Push is not configured.
    pub vapid_public_key: String,
    /// Canonical public URL of this gateway. Registration auth signatures are
    /// bound to this (audit 2026-06-07 host-binding); must match the URL
    /// clients POST to. Empty = host-binding misconfigured (registrations will
    /// fail unless clients also sign an empty host — dev only).
    pub gateway_host: String,
    /// Replay-protection cache for registration nonces.
    pub nonces: NonceCache,
    /// Per-IP rate limiter for the registration endpoints (audit 2026-06-07 W1).
    pub rate_limiter: RateLimiter,
}

/// Header value as &str, or "" if absent/non-ascii.
fn header<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}

/// Verify a `/register` or `/unregister` auth claim (audit 2026-06-07
/// C1/C2/C3). Requires: a fresh nonce, a timestamp in-window, the signing
/// address to equal the registering address (self-registration; device-key
/// delegation is deferred), an Ed25519 signature over the gateway-host-bound
/// canonical claim, and a non-replayed nonce.
fn verify_registration_auth(
    state: &ApiState,
    headers: &HeaderMap,
    action: &str,
    address: &str,
    token: &str,
) -> Result<(), (StatusCode, &'static str)> {
    // Fail closed if host-binding isn't configured: without a gateway host we
    // cannot bind the signature to this gateway, so refuse to serve host-bound
    // auth rather than accept an empty-host claim (audit follow-up W2).
    if state.gateway_host.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway public_url not configured",
        ));
    }

    let auth_address = header(headers, "x-ogmara-address");
    let auth_sig = header(headers, "x-ogmara-auth");
    let auth_ts = header(headers, "x-ogmara-timestamp");
    let nonce = header(headers, "x-ogmara-nonce");

    if auth_sig.is_empty() || auth_ts.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "auth headers required"));
    }
    if nonce.len() < MIN_NONCE_LEN
        || nonce.len() > MAX_NONCE_LEN
        || !nonce.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err((StatusCode::UNAUTHORIZED, "invalid nonce"));
    }
    // Self-registration: the key that signs must BE the address it registers
    // for. Device-key delegation (ogd1 device → klv1 wallet) needs a
    // wallet-signed delegation proof and is a documented follow-up.
    if auth_address != address {
        return Err((StatusCode::UNAUTHORIZED, "auth address must match registration address"));
    }
    let ts: u64 = match auth_ts.parse() {
        Ok(t) => t,
        Err(_) => return Err((StatusCode::BAD_REQUEST, "invalid timestamp")),
    };
    // Asymmetric freshness: up to 5min in the past, only 60s into the future.
    let now = now_ms();
    if ts > now {
        if ts - now > REG_AUTH_FUTURE_SKEW_MS {
            return Err((StatusCode::UNAUTHORIZED, "timestamp too far in future"));
        }
    } else if now - ts > REG_AUTH_WINDOW_MS {
        return Err((StatusCode::UNAUTHORIZED, "timestamp expired"));
    }
    // Reconstruct the canonical claim using OUR gateway host — a signature
    // captured for another gateway won't verify here.
    let claim = crypto::build_push_claim(action, &state.gateway_host, nonce, ts, address, token);
    if crypto::verify_klever_signature(auth_address, &claim, auth_sig).is_err() {
        return Err((StatusCode::UNAUTHORIZED, "signature verification failed"));
    }
    // Burn the nonce (replay protection).
    if !state.nonces.claim(format!("{auth_address}:{nonce}")) {
        return Err((StatusCode::UNAUTHORIZED, "nonce already used (replay rejected)"));
    }
    Ok(())
}

/// Build the API router.
pub fn build_router(state: Arc<ApiState>) -> Router {
    // Only allow CORS from Ogmara origins (not fully permissive)
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin, _| {
            origin
                .to_str()
                .map(|s| s.contains("ogmara.org") || s.starts_with("http://localhost"))
                .unwrap_or(false)
        }))
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any);

    // Rate-limited subtree: the abuse surface (each request runs an Ed25519
    // verify + nonce-cache write). /push is authed by a shared secret and
    // /health, /stats, /vapid-key are cheap reads, so they stay unthrottled
    // here (audit 2026-06-07 W1).
    let throttled = Router::new()
        .route("/register", post(register_device))
        .route("/unregister", post(unregister_device))
        .layer(middleware::from_fn(rate_limit_middleware));

    Router::new()
        .route("/health", get(health))
        .route("/push", post(receive_push))
        .route("/stats", get(stats))
        .route("/vapid-key", get(vapid_public_key))
        .merge(throttled)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(Extension(state))
}

/// GET /health
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "ogmara-push-gateway",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// GET /stats
async fn stats(Extension(state): Extension<Arc<ApiState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "registered_devices": state.registry.device_count(),
        "registered_addresses": state.registry.registered_addresses().len(),
    }))
}

/// GET /vapid-key — return the VAPID public key for Web Push subscriptions.
///
/// Clients use this key with `PushManager.subscribe({ applicationServerKey })`.
async fn vapid_public_key(
    Extension(state): Extension<Arc<ApiState>>,
) -> impl IntoResponse {
    if state.vapid_public_key.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, "Web Push not configured").into_response();
    }
    Json(serde_json::json!({
        "publicKey": state.vapid_public_key,
    }))
    .into_response()
}

/// POST /register — register a device for push notifications.
///
/// Requires the same auth headers as the L2 node API:
///   X-Ogmara-Auth:      base64(Ed25519 signature)
///   X-Ogmara-Address:   klv1... address (must match body address)
///   X-Ogmara-Timestamp: unix timestamp in ms
async fn register_device(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    if req.address.is_empty() || req.token.is_empty() {
        return (StatusCode::BAD_REQUEST, "address and token required").into_response();
    }

    if !req.address.starts_with("klv1") && !req.address.starts_with("ogd1") {
        return (StatusCode::BAD_REQUEST, "invalid Klever address").into_response();
    }

    // Verify the request is signed by the wallet/device it registers for
    // (audit 2026-06-07 C1/C3): Ed25519 over a gateway-host-bound, nonced
    // canonical claim, signing address == registration address.
    if let Err((status, msg)) =
        verify_registration_auth(&state, &headers, "register", &req.address, &req.token)
    {
        warn!(address = %req.address, "register auth rejected: {}", msg);
        return (status, msg).into_response();
    }

    // Registry may refuse a brand-new address when at capacity (audit
    // 2026-06-07 W2). Existing addresses always succeed.
    if !state.registry.register(req) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "registry at capacity, cannot register new address",
        )
            .into_response();
    }
    Json(serde_json::json!({ "ok": true })).into_response()
}

/// POST /unregister — remove a device registration.
///
/// Requires the same auth headers as /register to prevent unauthorized removal.
#[derive(Deserialize)]
struct UnregisterRequest {
    address: String,
    token: String,
}

async fn unregister_device(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    Json(req): Json<UnregisterRequest>,
) -> impl IntoResponse {
    // Verify the request is signed by the address owner (same scheme as
    // /register; audit 2026-06-07 C2/C3).
    if let Err((status, msg)) =
        verify_registration_auth(&state, &headers, "unregister", &req.address, &req.token)
    {
        warn!(address = %req.address, "unregister auth rejected: {}", msg);
        return (status, msg).into_response();
    }

    state.registry.unregister(&req.address, &req.token);
    Json(serde_json::json!({ "ok": true })).into_response()
}

/// POST /push — receive a push notification trigger from an L2 node.
///
/// Called by the L2 node's notification engine when it detects a mention
/// or DM for a user that has push notifications configured.
///
/// Accepts auth via either `X-Push-Secret` header or `Authorization: Bearer <token>`.
#[derive(Deserialize)]
struct PushTrigger {
    /// Target address to notify (klv1...).
    address: String,
    /// Notification type: "mention", "reply", "dm" or "channel_invite".
    ///
    /// Unknown extra fields the node may send (e.g. a future
    /// `invite_envelope`) are ignored by serde and never reach the push
    /// provider: the outgoing payload is rebuilt from the typed fields only.
    #[serde(rename = "type")]
    notification_type: String,
    /// Channel name (for display in mention notifications).
    channel_name: Option<String>,
    /// Channel ID (may be sent as string or number by the L2 node).
    channel_id: Option<serde_json::Value>,
    /// Conversation ID (for DMs).
    conversation_id: Option<String>,
    /// Sender/author address.
    sender: Option<String>,
    /// Message ID (hex-encoded).
    msg_id: Option<String>,
    /// Timestamp (Unix ms).
    timestamp: Option<u64>,
}

impl PushTrigger {
    /// Extract channel_id as a string regardless of whether the L2 node
    /// sent it as a JSON string or number.
    fn channel_id_str(&self) -> Option<String> {
        self.channel_id.as_ref().map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            other => other.to_string(),
        })
    }
}

async fn receive_push(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    Json(trigger): Json<PushTrigger>,
) -> impl IntoResponse {
    // Authenticate: require shared secret via X-Push-Secret or Bearer token.
    // Refuse to serve /push if no secret is configured (prevents open relay).
    if state.push_secret.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "push secret not configured",
        )
            .into_response();
    }
    {
        let provided = headers
            .get("x-push-secret")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        // Fall back to Authorization: Bearer <token>
        let provided = if provided.is_empty() {
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or("")
        } else {
            provided
        };

        if !constant_time_eq(provided, &state.push_secret) {
            warn!("Unauthorized /push attempt");
            return (StatusCode::UNAUTHORIZED, "invalid push secret").into_response();
        }
    }

    let devices = state.registry.get_devices(&trigger.address);
    if devices.is_empty() {
        return (StatusCode::NOT_FOUND, "no devices registered for address").into_response();
    }

    let payload = match build_payload(&trigger) {
        Ok(p) => p,
        Err(msg) => {
            warn!(
                notification_type = %truncate_type_for_log(&trigger.notification_type),
                reason = msg,
                "Rejected push trigger"
            );
            return (StatusCode::BAD_REQUEST, msg).into_response();
        }
    };

    state.dispatcher.send_to_address(&devices, &payload).await;

    Json(serde_json::json!({
        "ok": true,
        "devices_notified": devices.len(),
    }))
    .into_response()
}

/// Max chars of a caller-supplied `type` string echoed into logs.
const MAX_LOGGED_TYPE_LEN: usize = 32;

/// Bound a caller-supplied notification type before it is logged.
fn truncate_type_for_log(t: &str) -> String {
    t.chars().take(MAX_LOGGED_TYPE_LEN).collect()
}

/// Max length of a bech32 address (BIP-173 caps the whole string at 90).
const MAX_ADDRESS_LEN: usize = 90;

/// Hex length of a message id (32-byte Keccak/Blake digest → 64 hex chars).
const MSG_ID_HEX_LEN: usize = 64;

/// Map a validated push trigger to the outgoing push payload.
///
/// Returns `Err(reason)` (→ HTTP 400) for an unknown type or, for
/// `channel_invite`, a malformed field. The payload is built from explicit
/// typed fields only, so nothing the node sends beyond them (in particular
/// an invite envelope or expiry) can be forwarded to a push provider.
fn build_payload(trigger: &PushTrigger) -> Result<push::PushPayload, &'static str> {
    match trigger.notification_type.as_str() {
        "mention" | "reply" => Ok(push::mention_payload(
            trigger.channel_name.as_deref().unwrap_or("unknown"),
            &trigger.channel_id_str().unwrap_or_default(),
            trigger.msg_id.as_deref().unwrap_or(""),
            trigger.timestamp.unwrap_or(0),
        )),
        "dm" => Ok(push::dm_payload(
            trigger.conversation_id.as_deref().unwrap_or(""),
            trigger.sender.as_deref().unwrap_or(""),
            trigger.msg_id.as_deref().unwrap_or(""),
            trigger.timestamp.unwrap_or(0),
        )),
        "channel_invite" => {
            // Strict: an invite is always about a concrete channel, from a
            // concrete wallet, identified by a concrete message. Anything
            // else is a malformed trigger, not something to paper over with
            // an empty-string default the app would then act on.
            let channel_id = parse_channel_id(trigger.channel_id.as_ref())
                .ok_or("channel_invite: invalid or missing channel_id")?;
            let sender = trigger
                .sender
                .as_deref()
                .filter(|s| is_valid_address(s))
                .ok_or("channel_invite: invalid or missing sender")?;
            let msg_id = trigger
                .msg_id
                .as_deref()
                .filter(|m| m.len() == MSG_ID_HEX_LEN && m.bytes().all(|b| b.is_ascii_hexdigit()))
                .ok_or("channel_invite: invalid or missing msg_id")?;
            // channel_name is deliberately NOT used: invites usually target
            // private channels and the rendered text goes to a third party.
            Ok(push::channel_invite_payload(
                &channel_id.to_string(),
                sender,
                msg_id,
                trigger.timestamp.unwrap_or(0),
            ))
        }
        _ => Err("unknown notification type"),
    }
}

/// Parse a channel id sent as a JSON number or a decimal string into `u64`.
/// Rejects negatives, floats, non-numeric strings and anything else.
fn parse_channel_id(v: Option<&serde_json::Value>) -> Option<u64> {
    match v? {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse().ok()
        }
        _ => None,
    }
}

/// Shape check for an Ogmara author address: `klv1…` wallet or `ogd1…`
/// device key, lowercase bech32 data charset, bounded length. Not a checksum
/// verification — the node already verified the envelope signature; this
/// only keeps junk/oversized strings out of the provider payload.
fn is_valid_address(s: &str) -> bool {
    const BECH32_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let data = match s.strip_prefix("klv1").or_else(|| s.strip_prefix("ogd1")) {
        Some(d) => d,
        None => return false,
    };
    s.len() <= MAX_ADDRESS_LEN
        && data.len() >= 6
        && data.bytes().all(|b| BECH32_CHARSET.contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SENDER: &str = "klv1qqqqqqqqqqqqqpgqxwakt2g7u9atsnr03gqcgmhcv38pt7mkd94q6shuwt";

    fn trigger(json: serde_json::Value) -> PushTrigger {
        serde_json::from_value(json).expect("trigger deserializes")
    }

    fn invite_json() -> serde_json::Value {
        serde_json::json!({
            "address": VALID_SENDER,
            "type": "channel_invite",
            "channel_id": 42,
            "channel_name": "secret-room",
            "msg_id": "ab".repeat(32),
            "sender": VALID_SENDER,
            "timestamp": 1_700_000_000_000u64,
        })
    }

    #[test]
    fn channel_invite_accepted() {
        let p = build_payload(&trigger(invite_json())).expect("valid invite accepted");
        assert_eq!(p.notification.body, "You were invited to a channel");
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["data"]["type"], "channel_invite");
        assert_eq!(v["data"]["channel_id"], "42");
        assert_eq!(v["data"]["sender"], VALID_SENDER);
        assert_eq!(v["data"]["msg_id"], "ab".repeat(32));
        assert_eq!(v["data"]["timestamp"], 1_700_000_000_000u64);
    }

    #[test]
    fn channel_invite_accepts_string_channel_id_and_null_name() {
        let mut j = invite_json();
        j["channel_id"] = serde_json::json!("18446744073709551615");
        j["channel_name"] = serde_json::Value::Null;
        let p = build_payload(&trigger(j)).expect("string u64 channel id accepted");
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["data"]["channel_id"], "18446744073709551615");
    }

    #[test]
    fn channel_invite_strips_envelope_and_private_name() {
        let mut j = invite_json();
        j["invite_envelope"] = serde_json::json!("c2VjcmV0LWludml0ZS1wcm9vZg==");
        j["invite_expires_at"] = serde_json::json!(1_800_000_000_000u64);
        j["anchor_node"] = serde_json::json!("https://node.example");
        let p = build_payload(&trigger(j)).expect("extra fields ignored, not rejected");
        let rendered = serde_json::to_string(&p).unwrap();
        for leaked in [
            "invite_envelope",
            "invite_expires_at",
            "c2VjcmV0LWludml0ZS1wcm9vZg==",
            "anchor_node",
            "secret-room",
        ] {
            assert!(!rendered.contains(leaked), "push payload leaked {leaked}: {rendered}");
        }
    }

    #[test]
    fn channel_invite_rejects_malformed() {
        let cases: Vec<(&str, serde_json::Value)> = vec![
            ("channel_id", serde_json::Value::Null),
            ("channel_id", serde_json::json!(-1)),
            ("channel_id", serde_json::json!(1.5)),
            ("channel_id", serde_json::json!("12a")),
            ("channel_id", serde_json::json!("")),
            ("channel_id", serde_json::json!("99999999999999999999999")),
            ("channel_id", serde_json::json!({"x": 1})),
            ("sender", serde_json::Value::Null),
            ("sender", serde_json::json!("")),
            ("sender", serde_json::json!("abc1qqqqqqqq")),
            ("sender", serde_json::json!("klv1QQQQQQQQ")),
            ("sender", serde_json::json!("klv1qqqqqbio")),
            ("sender", serde_json::json!(format!("klv1{}", "q".repeat(90)))),
            ("msg_id", serde_json::Value::Null),
            ("msg_id", serde_json::json!("ab")),
            ("msg_id", serde_json::json!("zz".repeat(32))),
            ("msg_id", serde_json::json!("ab".repeat(33))),
        ];
        for (field, bad) in cases {
            let mut j = invite_json();
            j[field] = bad.clone();
            assert!(
                build_payload(&trigger(j)).is_err(),
                "channel_invite with {field}={bad} must be rejected"
            );
        }
    }

    #[test]
    fn unknown_type_still_rejected_and_existing_types_unchanged() {
        let mut j = invite_json();
        j["type"] = serde_json::json!("bogus");
        assert!(build_payload(&trigger(j)).is_err());

        let mut j = invite_json();
        j["type"] = serde_json::json!("mention");
        let v = serde_json::to_value(build_payload(&trigger(j)).unwrap()).unwrap();
        assert_eq!(v["data"]["type"], "mention");
        assert_eq!(v["notification"]["body"], "New mention in #secret-room");

        let mut j = invite_json();
        j["type"] = serde_json::json!("dm");
        let v = serde_json::to_value(build_payload(&trigger(j)).unwrap()).unwrap();
        assert_eq!(v["data"]["type"], "dm");
    }

    #[test]
    fn nonce_cache_rejects_replay() {
        let cache = NonceCache::new(360_000);
        let key = "klv1abc:deadbeefdeadbeef".to_string();
        assert!(cache.claim(key.clone()), "first use should be fresh");
        assert!(!cache.claim(key.clone()), "second use is a replay");
        assert!(!cache.claim(key), "third use still a replay");
    }

    #[test]
    fn nonce_cache_distinct_keys_independent() {
        let cache = NonceCache::new(360_000);
        assert!(cache.claim("a:1111111111111111".to_string()));
        assert!(cache.claim("a:2222222222222222".to_string()));
        assert!(cache.claim("b:1111111111111111".to_string()));
        // but each is single-use
        assert!(!cache.claim("a:1111111111111111".to_string()));
    }

    #[test]
    fn rate_limiter_allows_up_to_limit_then_blocks() {
        use std::net::Ipv4Addr;
        let rl = RateLimiter::new(3);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // First 3 in the same 1-second window pass.
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        // 4th in the same window is blocked.
        assert!(!rl.check(ip), "request over the limit must be blocked");
    }

    #[test]
    fn rate_limiter_separate_ips_independent() {
        use std::net::Ipv4Addr;
        let rl = RateLimiter::new(1);
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(rl.check(a));
        assert!(!rl.check(a)); // a is now over its limit
        assert!(rl.check(b)); // b has its own bucket
    }

    #[test]
    fn rate_limiter_clamps_zero_limit() {
        use std::net::Ipv4Addr;
        // limit 0 would lock everyone out; we clamp to >=1.
        let rl = RateLimiter::new(0);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(rl.check(ip));
    }

    #[test]
    fn nonce_cache_expired_entry_is_reclaimable() {
        // TTL 0 → entry expires immediately, so a later claim of the same key
        // is treated as fresh (the signing timestamp would already be stale,
        // so the auth layer rejects it before we get here — this just checks
        // the cache doesn't pin forever).
        let cache = NonceCache::new(0);
        assert!(cache.claim("k:abcabcabcabcabca".to_string()));
        assert!(cache.claim("k:abcabcabcabcabca".to_string()));
    }
}
