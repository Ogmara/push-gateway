//! REST API for device registration and push notification triggers.
//!
//! Endpoints:
//!   POST /register   — register a device for push notifications
//!   POST /unregister — remove a device registration
//!   POST /push       — receive a push notification from an L2 node (internal)
//!   GET  /health     — health check

use std::sync::Arc;

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::push::{self, PushDispatcher, PushPayload};
use crate::registry::{DeviceRegistry, RegisterRequest};

/// Shared state for API handlers.
pub struct ApiState {
    pub registry: Arc<DeviceRegistry>,
    pub dispatcher: Arc<PushDispatcher>,
}

/// Build the API router.
pub fn build_router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/register", post(register_device))
        .route("/unregister", post(unregister_device))
        .route("/push", post(receive_push))
        .route("/stats", get(stats))
        .layer(CorsLayer::permissive())
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
async fn register_device(
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    if req.address.is_empty() || req.token.is_empty() {
        return (StatusCode::BAD_REQUEST, "address and token required").into_response();
    }

    if !req.address.starts_with("klv1") {
        return (StatusCode::BAD_REQUEST, "invalid Klever address").into_response();
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
    Json(trigger): Json<PushTrigger>,
) -> impl IntoResponse {
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
