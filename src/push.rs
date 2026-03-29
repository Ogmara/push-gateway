//! Push notification dispatcher — sends notifications via FCM, APNs, Web Push.
//!
//! Routes notifications to the correct platform provider based on the
//! device's registered platform (spec 6.4).

use serde::Serialize;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::registry::{DeviceRegistration, Platform};

/// Push notification payload (spec 6.4).
#[derive(Debug, Clone, Serialize)]
pub struct PushPayload {
    pub notification: PushNotification,
    pub data: PushData,
}

#[derive(Debug, Clone, Serialize)]
pub struct PushNotification {
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum PushData {
    Mention {
        channel_id: String,
        msg_id: String,
        timestamp: u64,
    },
    Dm {
        conversation_id: String,
        sender: String,
        msg_id: String,
        timestamp: u64,
    },
}

/// The push dispatcher handles sending notifications to platform providers.
pub struct PushDispatcher {
    http: reqwest::Client,
    fcm_enabled: bool,
    apns_enabled: bool,
    webpush_enabled: bool,
}

impl PushDispatcher {
    pub fn new(config: &Config) -> Self {
        Self {
            http: reqwest::Client::new(),
            fcm_enabled: config.fcm.enabled,
            apns_enabled: config.apns.enabled,
            webpush_enabled: config.webpush.enabled,
        }
    }

    /// Send a push notification to a specific device.
    pub async fn send(&self, device: &DeviceRegistration, payload: &PushPayload) {
        match device.platform {
            Platform::Fcm => {
                if self.fcm_enabled {
                    self.send_fcm(&device.token, payload).await;
                }
            }
            Platform::Apns => {
                if self.apns_enabled {
                    self.send_apns(&device.token, payload).await;
                }
            }
            Platform::Web => {
                if self.webpush_enabled {
                    self.send_webpush(&device.token, payload).await;
                }
            }
        }
    }

    /// Send to all devices registered for an address.
    pub async fn send_to_address(
        &self,
        devices: &[DeviceRegistration],
        payload: &PushPayload,
    ) {
        for device in devices {
            self.send(device, payload).await;
        }
    }

    /// Send via Firebase Cloud Messaging.
    async fn send_fcm(&self, token: &str, payload: &PushPayload) {
        // FCM HTTP v1 API: POST https://fcm.googleapis.com/v1/projects/{project}/messages:send
        // Full implementation requires OAuth2 token from service account credentials.
        // For now, log the intent — actual FCM integration requires the credentials.
        debug!(
            platform = "fcm",
            token_prefix = &token[..token.len().min(8)],
            "Would send FCM push"
        );
        info!(platform = "fcm", title = %payload.notification.title, "Push notification queued");
    }

    /// Send via Apple Push Notification Service.
    async fn send_apns(&self, token: &str, payload: &PushPayload) {
        // APNs HTTP/2 API: POST https://api.push.apple.com/3/device/{token}
        // Requires JWT signed with the .p8 auth key.
        debug!(
            platform = "apns",
            token_prefix = &token[..token.len().min(8)],
            "Would send APNs push"
        );
        info!(platform = "apns", title = %payload.notification.title, "Push notification queued");
    }

    /// Send via Web Push.
    async fn send_webpush(&self, subscription: &str, payload: &PushPayload) {
        // Web Push: POST to the subscription endpoint with VAPID headers.
        // Requires VAPID key signing.
        debug!(
            platform = "webpush",
            "Would send Web Push"
        );
        info!(platform = "webpush", title = %payload.notification.title, "Push notification queued");
    }
}

/// Build a mention push payload (spec 6.4).
pub fn mention_payload(channel_name: &str, channel_id: &str, msg_id: &str, timestamp: u64) -> PushPayload {
    PushPayload {
        notification: PushNotification {
            title: "Ogmara".to_string(),
            body: format!("New mention in #{}", channel_name),
        },
        data: PushData::Mention {
            channel_id: channel_id.to_string(),
            msg_id: msg_id.to_string(),
            timestamp,
        },
    }
}

/// Build a DM push payload (spec 6.4).
pub fn dm_payload(conversation_id: &str, sender: &str, msg_id: &str, timestamp: u64) -> PushPayload {
    PushPayload {
        notification: PushNotification {
            title: "Ogmara".to_string(),
            body: "New direct message".to_string(),
        },
        data: PushData::Dm {
            conversation_id: conversation_id.to_string(),
            sender: sender.to_string(),
            msg_id: msg_id.to_string(),
            timestamp,
        },
    }
}
