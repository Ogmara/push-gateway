//! Device registration — maps Klever addresses to push tokens.
//!
//! Clients register their device tokens with the gateway so it knows
//! where to send push notifications when mentions are detected.

use std::collections::HashMap;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Push notification platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// Firebase Cloud Messaging (Android).
    Fcm,
    /// Apple Push Notification Service (iOS).
    Apns,
    /// Web Push (browsers).
    Web,
}

/// A registered device for push notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistration {
    /// Klever address of the user.
    pub address: String,
    /// Platform-specific push token.
    pub token: String,
    /// Push platform.
    pub platform: Platform,
    /// Channels the user is subscribed to (for filtering mentions).
    #[serde(default)]
    pub channels: Vec<u64>,
    /// When this registration was created/updated.
    pub registered_at: u64,
}

/// Registration request from a client.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterRequest {
    /// Klever address.
    pub address: String,
    /// Device push token.
    pub token: String,
    /// Platform (fcm, apns, web).
    pub platform: Platform,
    /// Channels to receive push notifications for.
    #[serde(default)]
    pub channels: Vec<u64>,
}

/// Maximum number of devices per address (prevents amplification attacks).
const MAX_DEVICES_PER_ADDRESS: usize = 10;

/// The device registry — thread-safe mapping of addresses to push tokens.
pub struct DeviceRegistry {
    /// Address → list of registered devices (a user can have multiple devices).
    devices: DashMap<String, Vec<DeviceRegistration>>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self {
            devices: DashMap::new(),
        }
    }

    /// Register or update a device for push notifications.
    pub fn register(&self, req: RegisterRequest) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let registration = DeviceRegistration {
            address: req.address.clone(),
            token: req.token.clone(),
            platform: req.platform,
            channels: req.channels,
            registered_at: now,
        };

        let mut entry = self.devices.entry(req.address.clone()).or_default();
        // Update existing registration with same token, or add new
        if let Some(existing) = entry.iter_mut().find(|d| d.token == req.token) {
            *existing = registration;
        } else if entry.len() >= MAX_DEVICES_PER_ADDRESS {
            // Evict oldest registration to stay within the cap
            entry.sort_by_key(|d| d.registered_at);
            entry.remove(0);
            entry.push(registration);
            info!(address = %req.address, platform = ?req.platform, "Device registered (evicted oldest)");
            return;
        } else {
            entry.push(registration);
        }

        info!(address = %req.address, platform = ?req.platform, "Device registered");
    }

    /// Unregister a device token.
    pub fn unregister(&self, address: &str, token: &str) {
        if let Some(mut entry) = self.devices.get_mut(address) {
            entry.retain(|d| d.token != token);
            debug!(address, "Device unregistered");
        }
    }

    /// Get all devices registered for a given address.
    pub fn get_devices(&self, address: &str) -> Vec<DeviceRegistration> {
        self.devices
            .get(address)
            .map(|entry| entry.clone())
            .unwrap_or_default()
    }

    /// Get all addresses that have registered devices.
    pub fn registered_addresses(&self) -> Vec<String> {
        self.devices
            .iter()
            .filter(|entry| !entry.value().is_empty())
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Check if an address has any registered devices.
    pub fn has_devices(&self, address: &str) -> bool {
        self.devices
            .get(address)
            .map(|entry| !entry.is_empty())
            .unwrap_or(false)
    }

    /// Get total registered device count.
    pub fn device_count(&self) -> usize {
        self.devices.iter().map(|e| e.value().len()).sum()
    }
}
