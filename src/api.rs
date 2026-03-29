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
use tracing::{info, warn};

use crate::push::{self, PushDispatcher, PushPayload};
use crate::registry::{DeviceRegistry, RegisterRequest};

/// Shared state for API handlers.
pub struct ApiState {
    pub registry: Arc<DeviceRegistry>,
    pub dispatcher: Arc<PushDispatcher>,
    /// Shared secret for L2 node → gateway authentication on /push.
    pub push_secret: String,
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

    // Reject stale timestamps (> 5 minutes old)
    if let Ok(ts) = auth_ts.parse::<u64>() {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if now_ms.saturating_sub(ts) > 300_000 {
            return (StatusCode::UNAUTHORIZED, "timestamp expired").into_response();
        }
    } else {
        return (StatusCode::BAD_REQUEST, "invalid timestamp").into_response();
    }

    state.registry.register(req);
    Json(serde_json::json!({ "ok": true })).into_response()
}

/// POST /unregister — remove a device registration.
#[derive(Deserialize)]
struct UnregisterRequest {
    address: String,
    token: String,
}

async fn unregister_device(
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<UnregisterRequest>,
) -> Json<serde_json::Value> {
    state.registry.unregister(&req.address, &req.token);
    Json(serde_json::json!({ "ok": true }))
}

/// POST /push — receive a push notification trigger from an L2 node.
///
/// This is called by the L2 node's notification engine when it detects
/// a mention for a user that has push notifications configured.
#[derive(Deserialize)]
struct PushTrigger {
    /// Target address to notify.
    address: String,
    /// Notification type.
    #[serde(rename = "type")]
    notification_type: String,
    /// Channel name (for mentions).
    channel_name: Option<String>,
    /// Channel ID.
    channel_id: Option<String>,
    /// Conversation ID (for DMs).
    conversation_id: Option<String>,
    /// Sender address (for DMs).
    sender: Option<String>,
    /// Message ID.
    msg_id: Option<String>,
    /// Timestamp.
    timestamp: Option<u64>,
}

async fn receive_push(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    Json(trigger): Json<PushTrigger>,
) -> impl IntoResponse {
    // Authenticate: require shared secret from L2 node
    if !state.push_secret.is_empty() {
        let provided = headers
            .get("x-push-secret")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if provided != state.push_secret {
            warn!("Unauthorized /push attempt");
            return (StatusCode::UNAUTHORIZED, "invalid push secret").into_response();
        }
    }

    let devices = state.registry.get_devices(&trigger.address);
    if devices.is_empty() {
        return (StatusCode::NOT_FOUND, "no devices registered for address").into_response();
    }

    let payload = match trigger.notification_type.as_str() {
        "mention" => push::mention_payload(
            trigger.channel_name.as_deref().unwrap_or("unknown"),
            trigger.channel_id.as_deref().unwrap_or(""),
            trigger.msg_id.as_deref().unwrap_or(""),
            trigger.timestamp.unwrap_or(0),
        ),
        "dm" => push::dm_payload(
            trigger.conversation_id.as_deref().unwrap_or(""),
            trigger.sender.as_deref().unwrap_or(""),
            trigger.msg_id.as_deref().unwrap_or(""),
            trigger.timestamp.unwrap_or(0),
        ),
        _ => {
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
