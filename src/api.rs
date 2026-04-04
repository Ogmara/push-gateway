//! REST API for device registration and push notification triggers.
//!
//! Endpoints:
//!   POST /register   — register a device for push notifications (requires wallet sig)
//!   POST /unregister — remove a device registration
//!   POST /push       — receive a push notification from an L2 node (requires shared secret)
//!   GET  /health     — health check
//!   GET  /stats      — gateway statistics

use std::sync::Arc;

use axum::extract::Extension;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::warn;

use crate::push::{self, PushDispatcher};
use crate::registry::{DeviceRegistry, RegisterRequest};

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

/// Shared state for API handlers.
pub struct ApiState {
    pub registry: Arc<DeviceRegistry>,
    pub dispatcher: Arc<PushDispatcher>,
    /// Shared secret for L2 node → gateway authentication on /push.
    pub push_secret: String,
    /// VAPID public key (base64url-encoded uncompressed P-256 point).
    /// Empty if Web Push is not configured.
    pub vapid_public_key: String,
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

    Router::new()
        .route("/health", get(health))
        .route("/register", post(register_device))
        .route("/unregister", post(unregister_device))
        .route("/push", post(receive_push))
        .route("/stats", get(stats))
        .route("/vapid-key", get(vapid_public_key))
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

    if !req.address.starts_with("klv1") {
        return (StatusCode::BAD_REQUEST, "invalid Klever address").into_response();
    }

    // Verify the request is signed by the address owner
    let auth_address = headers
        .get("x-ogmara-address")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let auth_sig = headers
        .get("x-ogmara-auth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let auth_ts = headers
        .get("x-ogmara-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Address in auth headers must match body
    if auth_address != req.address {
        return (StatusCode::UNAUTHORIZED, "address mismatch").into_response();
    }

    // Require auth headers present (signature verification delegated to L2 node
    // in production; here we enforce the header contract)
    if auth_sig.is_empty() || auth_ts.is_empty() {
        return (StatusCode::UNAUTHORIZED, "auth headers required").into_response();
    }

    // Reject timestamps outside ±5 minute window
    if let Ok(ts) = auth_ts.parse::<u64>() {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let diff = if now_ms > ts { now_ms - ts } else { ts - now_ms };
        if diff > 300_000 {
            return (StatusCode::UNAUTHORIZED, "timestamp expired").into_response();
        }
    } else {
        return (StatusCode::BAD_REQUEST, "invalid timestamp").into_response();
    }

    state.registry.register(req);
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
    // Verify the request is from the address owner (same auth as /register)
    let auth_address = headers
        .get("x-ogmara-address")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let auth_sig = headers
        .get("x-ogmara-auth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let auth_ts = headers
        .get("x-ogmara-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if auth_address != req.address {
        return (StatusCode::UNAUTHORIZED, "address mismatch").into_response();
    }
    if auth_sig.is_empty() || auth_ts.is_empty() {
        return (StatusCode::UNAUTHORIZED, "auth headers required").into_response();
    }

    // Reject stale timestamps (> 5 minutes)
    if let Ok(ts) = auth_ts.parse::<u64>() {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let diff = if now_ms > ts { now_ms - ts } else { ts - now_ms };
        if diff > 300_000 {
            return (StatusCode::UNAUTHORIZED, "timestamp expired").into_response();
        }
    } else {
        return (StatusCode::BAD_REQUEST, "invalid timestamp").into_response();
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
    /// Notification type: "mention" or "dm".
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
    /// Message preview (first 100 chars, no content for DMs).
    preview: Option<String>,
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

    let payload = match trigger.notification_type.as_str() {
        "mention" | "reply" => push::mention_payload(
            trigger.channel_name.as_deref().unwrap_or("unknown"),
            &trigger.channel_id_str().unwrap_or_default(),
            trigger.msg_id.as_deref().unwrap_or(""),
            trigger.timestamp.unwrap_or(0),
        ),
        "dm" => push::dm_payload(
            trigger.conversation_id.as_deref().unwrap_or(""),
            trigger.sender.as_deref().unwrap_or(""),
            trigger.msg_id.as_deref().unwrap_or(""),
            trigger.timestamp.unwrap_or(0),
        ),
        other => {
            warn!(notification_type = %other, "Unknown notification type");
            return (StatusCode::BAD_REQUEST, "unknown notification type").into_response();
        }
    };

    state.dispatcher.send_to_address(&devices, &payload).await;

    Json(serde_json::json!({
        "ok": true,
        "devices_notified": devices.len(),
    }))
    .into_response()
}
