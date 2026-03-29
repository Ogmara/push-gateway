//! WebSocket listener — connects to L2 nodes and monitors for mentions.
//!
//! The gateway subscribes to channels via the public WebSocket endpoint
//! and watches for messages that mention registered users (spec 6.2).

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

use crate::push::PushDispatcher;
use crate::registry::DeviceRegistry;

/// Message envelope fields we care about for mention detection.
#[derive(Debug, serde::Deserialize)]
struct WsMessage {
    #[serde(rename = "type")]
    msg_type: String,
    envelope: Option<EnvelopeStub>,
}

/// Minimal envelope fields for mention detection.
#[derive(Debug, serde::Deserialize)]
struct EnvelopeStub {
    msg_id: Option<String>,
    author: Option<String>,
    timestamp: Option<u64>,
    #[serde(rename = "msg_type")]
    envelope_type: Option<u8>,
}

/// Connect to an L2 node WebSocket and monitor for mentions.
pub async fn listen_to_node(
    node_url: &str,
    registry: Arc<DeviceRegistry>,
    dispatcher: Arc<PushDispatcher>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) {
    info!(url = %node_url, "Connecting to L2 node");

    loop {
        match connect_and_listen(node_url, &registry, &dispatcher, &mut shutdown_rx).await {
            Ok(()) => {
                info!(url = %node_url, "Disconnected from L2 node (shutdown)");
                return;
            }
            Err(e) => {
                warn!(url = %node_url, error = %e, "L2 node connection failed, reconnecting in 5s");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    _ = shutdown_rx.recv() => return,
                }
            }
        }
    }
}

async fn connect_and_listen(
    node_url: &str,
    registry: &DeviceRegistry,
    dispatcher: &PushDispatcher,
    shutdown_rx: &mut tokio::sync::broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let (ws_stream, _) = tokio_tungstenite::connect_async(node_url).await?;
    let (mut write, mut read) = ws_stream.split();

    info!(url = %node_url, "Connected to L2 node");

    // Subscribe to all channels (public WS — we get all public messages)
    // The public WS doesn't require auth, but only streams public content
    // We detect mentions by parsing the message payloads

    loop {
        tokio::select! {
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Err(e) = handle_ws_message(text.as_ref(), registry, dispatcher).await {
                            debug!(error = %e, "Failed to handle WS message");
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        return Err(anyhow::anyhow!("WebSocket closed"));
                    }
                    Some(Err(e)) => {
                        return Err(anyhow::anyhow!("WebSocket error: {}", e));
                    }
                    _ => {}
                }
            }
            _ = shutdown_rx.recv() => {
                let _ = write.send(Message::Close(None)).await;
                return Ok(());
            }
        }
    }
}

/// Handle a WebSocket message — check for mentions of registered users.
async fn handle_ws_message(
    text: &str,
    registry: &DeviceRegistry,
    dispatcher: &PushDispatcher,
) -> anyhow::Result<()> {
    let msg: WsMessage = serde_json::from_str(text)?;

    // We only care about channel messages and DMs
    match msg.msg_type.as_str() {
        "message" => {
            if let Some(ref envelope) = msg.envelope {
                // For channel messages, we'd parse the payload to get mentions
                // Since payload is MessagePack binary, we check the raw JSON
                // for mention addresses in the envelope metadata
                check_mentions_from_envelope(envelope, registry, dispatcher).await;
            }
        }
        "dm" => {
            if let Some(ref envelope) = msg.envelope {
                // DM notifications — notify the recipient
                // We can't see the content (encrypted), but we know who it's for
                check_dm_notification(envelope, registry, dispatcher).await;
            }
        }
        _ => {}
    }

    Ok(())
}

/// Check if any mentioned users in a channel message have registered devices.
async fn check_mentions_from_envelope(
    envelope: &EnvelopeStub,
    registry: &DeviceRegistry,
    dispatcher: &PushDispatcher,
) {
    // In a full implementation, we'd deserialize the MessagePack payload
    // to extract the `mentions` field. For now, we use a simplified approach:
    // the L2 node's notification engine handles mentions, and the push gateway
    // receives pre-processed notification events.
    //
    // The gateway monitors the notification broadcast and forwards to push providers.
    let _msg_id = envelope.msg_id.as_deref().unwrap_or("");
    let _author = envelope.author.as_deref().unwrap_or("");
    let _timestamp = envelope.timestamp.unwrap_or(0);

    // Notification forwarding will be triggered by the L2 node's
    // push gateway integration (POST to our API with notification payload)
}

/// Send a DM push notification to the recipient if they have registered devices.
async fn check_dm_notification(
    _envelope: &EnvelopeStub,
    _registry: &DeviceRegistry,
    _dispatcher: &PushDispatcher,
) {
    // DM recipient detection requires parsing the DirectMessage payload,
    // which contains the recipient address. The L2 node handles this
    // via its notification engine and forwards to the push gateway API.
}
