//! Push notification dispatcher — sends notifications via FCM, APNs, Web Push.
//!
//! Routes notifications to the correct platform provider based on the
//! device's registered platform (spec 6.4).
//!
//! - FCM: HTTP v1 API with OAuth2 service account credentials
//! - APNs: HTTP/2 API with JWT (ES256) authentication via .p8 key
//! - Web Push: VAPID-signed POST to subscription endpoint

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

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

/// Cached OAuth2 access token for FCM.
struct FcmToken {
    token: String,
    expires_at: u64,
}

/// FCM HTTP v1 API message wrapper.
#[derive(Serialize)]
struct FcmRequest {
    message: FcmMessage,
}

#[derive(Serialize)]
struct FcmMessage {
    token: String,
    notification: FcmNotification,
    data: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
struct FcmNotification {
    title: String,
    body: String,
}

/// APNs payload wrapper.
#[derive(Serialize)]
struct ApnsPayload {
    aps: ApnsAps,
    #[serde(flatten)]
    custom: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Serialize)]
struct ApnsAps {
    alert: ApnsAlert,
    sound: String,
    #[serde(rename = "mutable-content")]
    mutable_content: u8,
}

#[derive(Serialize)]
struct ApnsAlert {
    title: String,
    body: String,
}

/// OAuth2 token response from Google.
#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    expires_in: u64,
}

/// The push dispatcher handles sending notifications to platform providers.
pub struct PushDispatcher {
    http: reqwest::Client,
    fcm_enabled: bool,
    apns_enabled: bool,
    webpush_enabled: bool,
    // FCM state
    fcm_project_id: String,
    fcm_credentials: Option<FcmCredentials>,
    fcm_token: Arc<RwLock<Option<FcmToken>>>,
    // APNs state
    apns_key_id: String,
    apns_team_id: String,
    apns_key_bytes: Option<Vec<u8>>,
    apns_production: bool,
    // Web Push state
    vapid_private_key: Option<Vec<u8>>,
    vapid_subject: String,
}

/// Parsed FCM service account credentials.
#[derive(Deserialize)]
struct FcmCredentials {
    client_email: String,
    private_key: String,
    project_id: String,
    token_uri: String,
}

impl PushDispatcher {
    pub fn new(config: &Config) -> Self {
        // Load FCM credentials from file if configured
        let fcm_credentials = if config.fcm.enabled && !config.fcm.credentials_file.is_empty() {
            match std::fs::read_to_string(&config.fcm.credentials_file) {
                Ok(content) => match serde_json::from_str::<FcmCredentials>(&content) {
                    Ok(creds) => {
                        info!(project_id = %creds.project_id, "FCM credentials loaded");
                        Some(creds)
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to parse FCM credentials");
                        None
                    }
                },
                Err(e) => {
                    error!(path = %config.fcm.credentials_file, error = %e, "Failed to read FCM credentials");
                    None
                }
            }
        } else {
            None
        };

        let fcm_project_id = fcm_credentials
            .as_ref()
            .map(|c| c.project_id.clone())
            .unwrap_or_default();

        // Load APNs .p8 key if configured
        let apns_key_bytes = if config.apns.enabled && !config.apns.key_file.is_empty() {
            match std::fs::read_to_string(&config.apns.key_file) {
                Ok(content) => {
                    // Strip PEM headers and decode base64
                    let key_b64: String = content
                        .lines()
                        .filter(|l| !l.starts_with("-----"))
                        .collect();
                    match BASE64.decode(&key_b64) {
                        Ok(bytes) => {
                            info!("APNs auth key loaded");
                            Some(bytes)
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to decode APNs key");
                            None
                        }
                    }
                }
                Err(e) => {
                    error!(path = %config.apns.key_file, error = %e, "Failed to read APNs key");
                    None
                }
            }
        } else {
            None
        };

        // Load VAPID private key if configured
        let vapid_private_key = if config.webpush.enabled && !config.webpush.vapid_private_key.is_empty() {
            match BASE64URL.decode(&config.webpush.vapid_private_key) {
                Ok(bytes) => Some(bytes),
                Err(e) => {
                    error!(error = %e, "Failed to decode VAPID private key");
                    None
                }
            }
        } else {
            None
        };

        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            fcm_enabled: config.fcm.enabled,
            apns_enabled: config.apns.enabled,
            webpush_enabled: config.webpush.enabled,
            fcm_project_id,
            fcm_credentials,
            fcm_token: Arc::new(RwLock::new(None)),
            apns_key_id: config.apns.key_id.clone(),
            apns_team_id: config.apns.team_id.clone(),
            apns_key_bytes,
            apns_production: false, // default to sandbox; config could add this
            vapid_private_key,
            vapid_subject: config.webpush.vapid_subject.clone(),
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

    // --- FCM (Firebase Cloud Messaging) HTTP v1 API ---

    /// Get a valid OAuth2 access token for FCM, refreshing if expired.
    async fn fcm_access_token(&self) -> Option<String> {
        // Check cached token
        {
            let cached = self.fcm_token.read().await;
            if let Some(ref token) = *cached {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now < token.expires_at.saturating_sub(60) {
                    return Some(token.token.clone());
                }
            }
        }

        // Refresh token via service account JWT -> Google OAuth2
        let creds = self.fcm_credentials.as_ref()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Build JWT: header.payload.signature
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });
        let claims = serde_json::json!({
            "iss": creds.client_email,
            "scope": "https://www.googleapis.com/auth/firebase.messaging",
            "aud": creds.token_uri,
            "iat": now,
            "exp": now + 3600,
        });

        let header_b64 = BASE64URL.encode(header.to_string().as_bytes());
        let claims_b64 = BASE64URL.encode(claims.to_string().as_bytes());
        let signing_input = format!("{}.{}", header_b64, claims_b64);

        // Sign with RSA private key from service account
        let signature = match self.sign_rsa(&creds.private_key, signing_input.as_bytes()) {
            Ok(sig) => sig,
            Err(e) => {
                error!(error = %e, "Failed to sign FCM JWT");
                return None;
            }
        };
        let sig_b64 = BASE64URL.encode(&signature);
        let jwt = format!("{}.{}", signing_input, sig_b64);

        // Exchange JWT for access token (URL-encoded form body)
        let form_body = format!(
            "grant_type={}&assertion={}",
            urlencoding::encode("urn:ietf:params:oauth:grant-type:jwt-bearer"),
            urlencoding::encode(&jwt),
        );

        let resp = self
            .http
            .post(&creds.token_uri)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form_body)
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                match r.json::<GoogleTokenResponse>().await {
                    Ok(token_resp) => {
                        let expires_at = now + token_resp.expires_in;
                        let token = token_resp.access_token.clone();
                        let mut cached = self.fcm_token.write().await;
                        *cached = Some(FcmToken {
                            token: token_resp.access_token,
                            expires_at,
                        });
                        info!("FCM OAuth2 token refreshed");
                        Some(token)
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to parse FCM token response");
                        None
                    }
                }
            }
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                error!(status = %status, body = %truncate_for_log(&body, 200), "FCM token request failed");
                None
            }
            Err(e) => {
                error!(error = %e, "FCM token request error");
                None
            }
        }
    }

    /// Sign data with an RSA private key (PEM-encoded PKCS#8 from Google service account).
    fn sign_rsa(&self, pem_key: &str, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};

        // Parse PEM to DER
        let key_b64: String = pem_key
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let der = BASE64.decode(&key_b64)?;

        // Parse PKCS#8 DER to RSA private key
        let rsa_key = rsa::RsaPrivateKey::from_pkcs8_der(&der)
            .map_err(|e| anyhow::anyhow!("RSA key parse error: {}", e))?;

        // RS256 signing (PKCS1v15 + SHA-256)
        let signing_key = SigningKey::<sha2::Sha256>::new(rsa_key);
        let signature = signing_key.sign(data);
        Ok(signature.to_bytes().into_vec())
    }

    /// Send notification via FCM HTTP v1 API.
    async fn send_fcm(&self, token: &str, payload: &PushPayload) {
        let access_token = match self.fcm_access_token().await {
            Some(t) => t,
            None => {
                warn!(platform = "fcm", "No FCM access token available, skipping push");
                return;
            }
        };

        let data_map = payload_to_string_map(&payload.data);
        let request = FcmRequest {
            message: FcmMessage {
                token: token.to_string(),
                notification: FcmNotification {
                    title: payload.notification.title.clone(),
                    body: payload.notification.body.clone(),
                },
                data: data_map,
            },
        };

        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.fcm_project_id
        );

        match self
            .http
            .post(&url)
            .bearer_auth(&access_token)
            .json(&request)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                debug!(platform = "fcm", "Push notification sent");
                info!(platform = "fcm", title = %payload.notification.title, "Push sent via FCM");
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                warn!(platform = "fcm", status = %status, body = %truncate_for_log(&body, 200), "FCM send failed");
            }
            Err(e) => {
                error!(platform = "fcm", error = %e, "FCM request error");
            }
        }
    }

    // --- APNs (Apple Push Notification Service) HTTP/2 API ---

    /// Build an APNs JWT (ES256) for authentication.
    fn build_apns_jwt(&self) -> Option<String> {
        let key_bytes = self.apns_key_bytes.as_ref()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // JWT header
        let header = serde_json::json!({
            "alg": "ES256",
            "kid": self.apns_key_id,
        });
        // JWT claims
        let claims = serde_json::json!({
            "iss": self.apns_team_id,
            "iat": now,
        });

        let header_b64 = BASE64URL.encode(header.to_string().as_bytes());
        let claims_b64 = BASE64URL.encode(claims.to_string().as_bytes());
        let signing_input = format!("{}.{}", header_b64, claims_b64);

        // Sign with ES256 (P-256 ECDSA)
        match self.sign_es256(key_bytes, signing_input.as_bytes()) {
            Ok(sig) => {
                let sig_b64 = BASE64URL.encode(&sig);
                Some(format!("{}.{}", signing_input, sig_b64))
            }
            Err(e) => {
                error!(error = %e, "Failed to sign APNs JWT");
                None
            }
        }
    }

    /// Sign data with ES256 (ECDSA P-256) using the raw PKCS#8 key bytes.
    fn sign_es256(&self, key_der: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use p256::pkcs8::DecodePrivateKey;

        let signing_key = SigningKey::from_pkcs8_der(key_der)
            .map_err(|e| anyhow::anyhow!("ES256 key parse error: {}", e))?;
        let signature: Signature = signing_key.sign(data);
        // APNs expects raw r||s format (64 bytes), not DER
        Ok(signature.to_bytes().to_vec())
    }

    /// Send notification via APNs HTTP/2 API.
    async fn send_apns(&self, device_token: &str, payload: &PushPayload) {
        // Validate device token is hex-only (APNs tokens are 64-char hex strings)
        if !device_token.chars().all(|c| c.is_ascii_hexdigit()) || device_token.is_empty() {
            warn!(platform = "apns", "Invalid device token format, skipping");
            return;
        }

        let jwt = match self.build_apns_jwt() {
            Some(t) => t,
            None => {
                warn!(platform = "apns", "No APNs JWT available, skipping push");
                return;
            }
        };

        let host = if self.apns_production {
            "https://api.push.apple.com"
        } else {
            "https://api.sandbox.push.apple.com"
        };
        let url = format!("{}/3/device/{}", host, device_token);

        let mut custom_data = std::collections::HashMap::new();
        match &payload.data {
            PushData::Mention { channel_id, msg_id, timestamp } => {
                custom_data.insert("type".to_string(), serde_json::json!("mention"));
                custom_data.insert("channel_id".to_string(), serde_json::json!(channel_id));
                custom_data.insert("msg_id".to_string(), serde_json::json!(msg_id));
                custom_data.insert("timestamp".to_string(), serde_json::json!(timestamp));
            }
            PushData::Dm { conversation_id, sender, msg_id, timestamp } => {
                custom_data.insert("type".to_string(), serde_json::json!("dm"));
                custom_data.insert("conversation_id".to_string(), serde_json::json!(conversation_id));
                custom_data.insert("sender".to_string(), serde_json::json!(sender));
                custom_data.insert("msg_id".to_string(), serde_json::json!(msg_id));
                custom_data.insert("timestamp".to_string(), serde_json::json!(timestamp));
            }
        }

        let apns_payload = ApnsPayload {
            aps: ApnsAps {
                alert: ApnsAlert {
                    title: payload.notification.title.clone(),
                    body: payload.notification.body.clone(),
                },
                sound: "default".to_string(),
                mutable_content: 1,
            },
            custom: custom_data,
        };

        match self
            .http
            .post(&url)
            .bearer_auth(&jwt)
            .header("apns-topic", "org.ogmara.app")
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .json(&apns_payload)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                debug!(platform = "apns", "Push notification sent");
                info!(platform = "apns", title = %payload.notification.title, "Push sent via APNs");
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                warn!(platform = "apns", status = %status, body = %truncate_for_log(&body, 200), "APNs send failed");
            }
            Err(e) => {
                error!(platform = "apns", error = %e, "APNs request error");
            }
        }
    }

    // --- Web Push (VAPID) ---

    /// Send notification via Web Push with VAPID authentication.
    async fn send_webpush(&self, subscription_json: &str, payload: &PushPayload) {
        let vapid_key = match &self.vapid_private_key {
            Some(k) => k,
            None => {
                warn!(platform = "webpush", "No VAPID key available, skipping push");
                return;
            }
        };

        // Parse the subscription (endpoint + keys from the browser Push API)
        let sub: WebPushSubscription = match serde_json::from_str(subscription_json) {
            Ok(s) => s,
            Err(e) => {
                warn!(platform = "webpush", error = %e, "Failed to parse subscription");
                return;
            }
        };

        // SSRF protection: only allow HTTPS endpoints to known push service domains
        if !is_allowed_push_endpoint(&sub.endpoint) {
            warn!(platform = "webpush", "Rejected subscription with disallowed endpoint");
            return;
        }

        let payload_json = match serde_json::to_string(payload) {
            Ok(j) => j,
            Err(e) => {
                error!(platform = "webpush", error = %e, "Failed to serialize payload");
                return;
            }
        };

        // Build VAPID JWT for the subscription endpoint
        let jwt = match self.build_vapid_jwt(&sub.endpoint, vapid_key) {
            Some(t) => t,
            None => {
                warn!(platform = "webpush", "Failed to build VAPID JWT");
                return;
            }
        };

        // Derive VAPID public key for the Authorization header
        let vapid_pub = self.vapid_public_key(vapid_key);

        let auth_header = format!(
            "vapid t={}, k={}",
            jwt,
            BASE64URL.encode(&vapid_pub)
        );

        match self
            .http
            .post(&sub.endpoint)
            .header("Authorization", &auth_header)
            .header("Content-Encoding", "aes128gcm")
            .header("TTL", "86400")
            .header("Urgency", "high")
            .body(payload_json.into_bytes())
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() || resp.status().as_u16() == 201 => {
                debug!(platform = "webpush", "Push notification sent");
                info!(platform = "webpush", title = %payload.notification.title, "Push sent via Web Push");
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                warn!(platform = "webpush", status = %status, body = %truncate_for_log(&body, 200), "Web Push send failed");
            }
            Err(e) => {
                error!(platform = "webpush", error = %e, "Web Push request error");
            }
        }
    }

    /// Build a VAPID JWT for Web Push authorization.
    fn build_vapid_jwt(&self, endpoint: &str, key_bytes: &[u8]) -> Option<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Extract origin from endpoint URL
        let audience = endpoint
            .find("://")
            .and_then(|i| {
                let rest = &endpoint[i + 3..];
                rest.find('/').map(|j| &endpoint[..i + 3 + j])
            })
            .unwrap_or(endpoint);

        let header = serde_json::json!({ "alg": "ES256", "typ": "JWT" });
        let claims = serde_json::json!({
            "aud": audience,
            "exp": now + 86400,
            "sub": self.vapid_subject,
        });

        let header_b64 = BASE64URL.encode(header.to_string().as_bytes());
        let claims_b64 = BASE64URL.encode(claims.to_string().as_bytes());
        let signing_input = format!("{}.{}", header_b64, claims_b64);

        match self.sign_es256(key_bytes, signing_input.as_bytes()) {
            Ok(sig) => {
                let sig_b64 = BASE64URL.encode(&sig);
                Some(format!("{}.{}", signing_input, sig_b64))
            }
            Err(e) => {
                error!(error = %e, "Failed to sign VAPID JWT");
                None
            }
        }
    }

    /// Derive the uncompressed ECDSA public key from a VAPID private key (raw 32 bytes).
    fn vapid_public_key(&self, key_bytes: &[u8]) -> Vec<u8> {
        use p256::ecdsa::SigningKey;

        match SigningKey::from_bytes(key_bytes.into()) {
            Ok(sk) => {
                let pk = sk.verifying_key();
                pk.to_sec1_bytes().to_vec()
            }
            Err(_) => {
                warn!("Failed to derive VAPID public key");
                Vec::new()
            }
        }
    }
}

/// Web Push subscription from the browser Push API.
#[derive(Deserialize)]
struct WebPushSubscription {
    endpoint: String,
    #[allow(dead_code)]
    keys: Option<WebPushKeys>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct WebPushKeys {
    p256dh: Option<String>,
    auth: Option<String>,
}

/// SSRF protection: validate that a Web Push endpoint is an HTTPS URL
/// pointing to a known push service domain. Rejects internal IPs,
/// non-HTTPS, and unknown domains.
fn is_allowed_push_endpoint(endpoint: &str) -> bool {
    // Must be HTTPS
    if !endpoint.starts_with("https://") {
        return false;
    }

    // Extract host from URL
    let host = match endpoint.get(8..) {
        Some(rest) => rest.split('/').next().unwrap_or(""),
        None => return false,
    };
    // Strip port if present
    let host = host.split(':').next().unwrap_or(host);

    // Allow known Web Push provider domains
    const ALLOWED_SUFFIXES: &[&str] = &[
        ".push.services.mozilla.com",
        ".push.apple.com",
        ".fcm.googleapis.com",
        ".notify.windows.com",
        ".push.services.mozilla.org",
        ".web.push.apple.com",
    ];

    ALLOWED_SUFFIXES
        .iter()
        .any(|suffix| host.ends_with(suffix) || host.eq(&suffix[1..]))
}

/// Truncate a string for safe logging (avoids leaking sensitive data in error bodies).
fn truncate_for_log(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...[truncated]", &s[..max])
    }
}

/// Convert PushData to a flat string map for FCM data payload.
fn payload_to_string_map(data: &PushData) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    match data {
        PushData::Mention { channel_id, msg_id, timestamp } => {
            map.insert("type".to_string(), "mention".to_string());
            map.insert("channel_id".to_string(), channel_id.clone());
            map.insert("msg_id".to_string(), msg_id.clone());
            map.insert("timestamp".to_string(), timestamp.to_string());
        }
        PushData::Dm { conversation_id, sender, msg_id, timestamp } => {
            map.insert("type".to_string(), "dm".to_string());
            map.insert("conversation_id".to_string(), conversation_id.clone());
            map.insert("sender".to_string(), sender.clone());
            map.insert("msg_id".to_string(), msg_id.clone());
            map.insert("timestamp".to_string(), timestamp.to_string());
        }
    }
    map
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
