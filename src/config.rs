//! Configuration loading for the push gateway.
//!
//! Loads from `push-gateway.toml` (spec 6.5).
//! All secrets (API keys, credentials) must come from environment variables.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Top-level gateway configuration.
///
/// Note: `Debug` is manually implemented to redact secrets.
#[derive(Clone, Deserialize)]
pub struct Config {
    pub gateway: GatewayConfig,
    #[serde(default)]
    pub ogmara: OgmaraConfig,
    #[serde(default)]
    pub fcm: FcmConfig,
    #[serde(default)]
    pub apns: ApnsConfig,
    #[serde(default)]
    pub webpush: WebPushConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("gateway", &self.gateway)
            .field("ogmara", &self.ogmara)
            .field("fcm", &format_args!("FcmConfig {{ enabled: {} }}", self.fcm.enabled))
            .field("apns", &format_args!("ApnsConfig {{ enabled: {} }}", self.apns.enabled))
            .field("webpush", &format_args!("WebPushConfig {{ enabled: {} }}", self.webpush.enabled))
            .field("logging", &self.logging)
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    /// API listen port (default: 41722).
    #[serde(default = "default_port")]
    pub listen_port: u16,
    /// Listen address (default: 127.0.0.1).
    #[serde(default = "default_addr")]
    pub listen_addr: String,
    /// Shared secret for L2 node → gateway authentication on /push.
    /// Must be set via environment variable OGMARA_PUSH_SECRET in production.
    #[serde(default)]
    pub push_secret: String,
    /// Maximum requests per second per IP (rate limiting, default: 20).
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_sec: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OgmaraConfig {
    /// L2 node WebSocket URLs to subscribe to.
    #[serde(default)]
    pub node_urls: Vec<String>,
}

impl Default for OgmaraConfig {
    fn default() -> Self {
        Self {
            node_urls: vec!["ws://localhost:41721/api/v1/ws/public".to_string()],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FcmConfig {
    /// Whether FCM push is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Path to Firebase credentials JSON (loaded from env var in production).
    #[serde(default)]
    pub credentials_file: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ApnsConfig {
    /// Whether APNs push is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Path to APNs auth key (.p8 file).
    #[serde(default)]
    pub key_file: String,
    /// APNs key ID.
    #[serde(default)]
    pub key_id: String,
    /// Apple team ID.
    #[serde(default)]
    pub team_id: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WebPushConfig {
    /// Whether Web Push is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// VAPID private key (from env var in production).
    #[serde(default)]
    pub vapid_private_key: String,
    /// VAPID subject (e.g., "mailto:admin@ogmara.org").
    #[serde(default)]
    pub vapid_subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "json".to_string(),
        }
    }
}

fn default_rate_limit() -> u32 {
    20
}

fn default_port() -> u16 {
    41722
}

fn default_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: Config =
            toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
        Ok(config)
    }

    /// Generate a default configuration file.
    pub fn default_toml() -> String {
        r#"[gateway]
listen_port = 41722
listen_addr = "127.0.0.1"
# Shared secret for L2 node -> gateway auth. Set via OGMARA_PUSH_SECRET env var.
push_secret = ""
rate_limit_per_sec = 20

[ogmara]
node_urls = ["ws://localhost:41721/api/v1/ws/public"]

[fcm]
enabled = false
credentials_file = ""

[apns]
enabled = false
key_file = ""
key_id = ""
team_id = ""

[webpush]
enabled = false
vapid_private_key = ""
vapid_subject = ""

[logging]
level = "info"
format = "json"
"#
        .to_string()
    }
}
