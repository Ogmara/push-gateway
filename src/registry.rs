//! Device registration — maps Klever addresses to push tokens.
//!
//! Clients register their device tokens with the gateway so it knows
//! where to send push notifications when mentions are detected.
//!
//! Registrations are persisted to a JSON file so they survive restarts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

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
///
/// Optionally persists to a JSON file for durability across restarts.
pub struct DeviceRegistry {
    /// Address → list of registered devices (a user can have multiple devices).
    devices: DashMap<String, Vec<DeviceRegistration>>,
    /// Path to the persistence file. `None` = in-memory only.
    persist_path: Option<PathBuf>,
}

impl DeviceRegistry {
    /// Create an empty in-memory registry (no persistence).
    pub fn new() -> Self {
        Self {
            devices: DashMap::new(),
            persist_path: None,
        }
    }

    /// Load a registry from a JSON file, or create a new one if the file
    /// doesn't exist yet. Registrations will be persisted to this path.
    pub fn load(path: &Path) -> Self {
        let devices = DashMap::new();

        if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    match serde_json::from_str::<HashMap<String, Vec<DeviceRegistration>>>(&content)
                    {
                        Ok(data) => {
                            let count: usize = data.values().map(|v| v.len()).sum();
                            for (addr, devs) in data {
                                devices.insert(addr, devs);
                            }
                            info!(
                                path = %path.display(),
                                addresses = devices.len(),
                                devices = count,
                                "Loaded device registry from disk"
                            );
                        }
                        Err(e) => {
                            error!(
                                path = %path.display(),
                                error = %e,
                                "Failed to parse registry file, starting fresh"
                            );
                        }
                    }
                }
                Err(e) => {
                    error!(
                        path = %path.display(),
                        error = %e,
                        "Failed to read registry file, starting fresh"
                    );
                }
            }
        } else {
            info!(path = %path.display(), "No existing registry file, starting fresh");
        }

        Self {
            devices,
            persist_path: Some(path.to_path_buf()),
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

        let evicted = {
            let mut entry = self.devices.entry(req.address.clone()).or_default();
            // Update existing registration with same token, or add new
            if let Some(existing) = entry.iter_mut().find(|d| d.token == req.token) {
                *existing = registration;
                false
            } else if entry.len() >= MAX_DEVICES_PER_ADDRESS {
                // Evict oldest registration to stay within the cap
                entry.sort_by_key(|d| d.registered_at);
                entry.remove(0);
                entry.push(registration);
                true
            } else {
                entry.push(registration);
                false
            }
            // DashMap entry lock dropped here
        };

        if evicted {
            info!(address = %req.address, platform = ?req.platform, "Device registered (evicted oldest)");
        } else {
            info!(address = %req.address, platform = ?req.platform, "Device registered");
        }
        self.persist();
    }

    /// Unregister a device token.
    pub fn unregister(&self, address: &str, token: &str) {
        if let Some(mut entry) = self.devices.get_mut(address) {
            let before = entry.len();
            entry.retain(|d| d.token != token);
            if entry.len() < before {
                debug!(address, "Device unregistered");
            }
        }
        self.persist();
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

    /// Persist the registry to disk (atomic write via temp file + rename).
    fn persist(&self) {
        let path = match &self.persist_path {
            Some(p) => p,
            None => return,
        };

        // Collect into a regular HashMap for serialization
        let snapshot: HashMap<String, Vec<DeviceRegistration>> = self
            .devices
            .iter()
            .filter(|e| !e.value().is_empty())
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();

        let json = match serde_json::to_string_pretty(&snapshot) {
            Ok(j) => j,
            Err(e) => {
                error!(error = %e, "Failed to serialize registry");
                return;
            }
        };

        // Atomic write: write to .tmp, then rename
        let tmp_path = path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp_path, &json) {
            error!(path = %tmp_path.display(), error = %e, "Failed to write registry temp file");
            return;
        }
        if let Err(e) = std::fs::rename(&tmp_path, path) {
            error!(error = %e, "Failed to rename registry temp file");
            return;
        }

        debug!(
            path = %path.display(),
            addresses = snapshot.len(),
            "Registry persisted to disk"
        );
    }
}
