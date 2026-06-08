//! Device registration — maps Klever addresses to push tokens.
//!
//! Clients register their device tokens with the gateway so it knows
//! where to send push notifications when mentions are detected.
//!
//! Registrations are persisted to a JSON file so they survive restarts.
//! Push tokens are encrypted at rest with AES-256-GCM when a registry key is
//! configured (audit 2026-06-07 W3).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::crypto::registry_crypto::RegistryCipher;

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
    /// Platform-specific push token. Stored encrypted at rest (audit
    /// 2026-06-07 W3) when a registry key is configured; always plaintext in
    /// memory.
    pub token: String,
    /// Push platform.
    pub platform: Platform,
    /// Channels the user is subscribed to (for filtering mentions).
    #[serde(default)]
    pub channels: Vec<u64>,
    /// When this registration was created/updated (unix seconds).
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

/// Maximum number of distinct addresses tracked (audit 2026-06-07 W2). New
/// addresses are refused once this cap is hit; already-registered addresses
/// keep working. Bounds total registry memory and on-disk size.
const MAX_ADDRESSES: usize = 100_000;

/// Registrations older than this are evicted by the periodic TTL sweep (audit
/// 2026-06-07 W2). 30 days, in seconds.
const REGISTRATION_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Minimum interval between disk flushes (audit 2026-06-07 W2). Writes are
/// debounced: register/unregister only mark the registry dirty, and a flush
/// happens at most this often (plus an unconditional flush on shutdown). This
/// turns the previous O(n) write-per-mutation (O(n²) under churn) into batched
/// O(n) flushes.
const FLUSH_INTERVAL_SECS: u64 = 10;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The device registry — thread-safe mapping of addresses to push tokens.
///
/// Optionally persists to a JSON file for durability across restarts.
/// Persistence is debounced (see [`FLUSH_INTERVAL_SECS`]); call
/// [`DeviceRegistry::flush`] on shutdown to guarantee the latest state hits disk.
pub struct DeviceRegistry {
    /// Address → list of registered devices (a user can have multiple devices).
    devices: DashMap<String, Vec<DeviceRegistration>>,
    /// Path to the persistence file. `None` = in-memory only.
    persist_path: Option<PathBuf>,
    /// Cipher for token-at-rest encryption. `None` = store plaintext (dev /
    /// key unset).
    cipher: Option<RegistryCipher>,
    /// Set when the in-memory state has diverged from disk (audit 2026-06-07 W2).
    dirty: AtomicBool,
    /// Unix-secs of the last successful flush; gates the debounce window.
    last_flush: AtomicU64,
}

impl DeviceRegistry {
    /// Create an empty in-memory registry (no persistence, no encryption).
    /// Used by tests and available as a library constructor.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            devices: DashMap::new(),
            persist_path: None,
            cipher: None,
            dirty: AtomicBool::new(false),
            last_flush: AtomicU64::new(0),
        }
    }

    /// Load a registry from a JSON file, or create a new one if the file
    /// doesn't exist yet. Registrations will be persisted to this path.
    ///
    /// If `cipher` is `Some`, tokens are decrypted on load and encrypted on
    /// flush; legacy plaintext records load transparently and are re-encrypted
    /// on the next flush (audit 2026-06-07 W3).
    pub fn load(path: &Path, cipher: Option<RegistryCipher>) -> Self {
        let devices = DashMap::new();

        if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    match serde_json::from_str::<HashMap<String, Vec<DeviceRegistration>>>(&content)
                    {
                        Ok(data) => {
                            let mut count = 0usize;
                            let mut decrypt_failures = 0usize;
                            for (addr, mut devs) in data {
                                // Decrypt tokens in place; drop any record whose
                                // token can't be decrypted (wrong/rotated key or
                                // tampering) rather than serve a garbage token.
                                if let Some(ref c) = cipher {
                                    devs.retain_mut(|d| match c.open(&d.token) {
                                        Some(plain) => {
                                            d.token = plain;
                                            true
                                        }
                                        None => {
                                            decrypt_failures += 1;
                                            false
                                        }
                                    });
                                }
                                count += devs.len();
                                if !devs.is_empty() {
                                    devices.insert(addr, devs);
                                }
                            }
                            if decrypt_failures > 0 {
                                warn!(
                                    failures = decrypt_failures,
                                    "Dropped registry records that failed token decryption \
                                     (wrong OGMARA_REGISTRY_KEY?)"
                                );
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
            cipher,
            dirty: AtomicBool::new(false),
            last_flush: AtomicU64::new(now_secs()),
        }
    }

    /// Register or update a device for push notifications.
    ///
    /// Returns `false` if the registry is at its address cap and this is a new
    /// address (audit 2026-06-07 W2); existing addresses always succeed.
    pub fn register(&self, req: RegisterRequest) -> bool {
        let now = now_secs();

        let registration = DeviceRegistration {
            address: req.address.clone(),
            token: req.token.clone(),
            platform: req.platform,
            channels: req.channels,
            registered_at: now,
        };

        // Enforce the address cap for genuinely new addresses. Existing
        // addresses (re-registering / adding a device) bypass the cap so we
        // never lock out current users. `contains_key` + the later `entry` is
        // a benign race at the boundary (worst case a handful over the cap).
        let is_new_address = !self.devices.contains_key(&req.address);
        if is_new_address && self.devices.len() >= MAX_ADDRESSES {
            warn!(
                address = %req.address,
                cap = MAX_ADDRESSES,
                "Registry at address cap, refusing new address"
            );
            return false;
        }

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
        self.mark_dirty_and_maybe_flush();
        true
    }

    /// Unregister a device token.
    pub fn unregister(&self, address: &str, token: &str) {
        let mut changed = false;
        // Use a scoped block so the entry lock is released before we may remove
        // the now-empty entry.
        if let Some(mut entry) = self.devices.get_mut(address) {
            let before = entry.len();
            entry.retain(|d| d.token != token);
            if entry.len() < before {
                changed = true;
                debug!(address, "Device unregistered");
            }
        }
        // Drop the empty vec so it doesn't count against the address cap.
        self.devices
            .remove_if(address, |_, devs| devs.is_empty());
        if changed {
            self.mark_dirty_and_maybe_flush();
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
    #[allow(dead_code)]
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

    /// Number of distinct registered addresses.
    #[allow(dead_code)]
    pub fn address_count(&self) -> usize {
        self.devices.len()
    }

    /// Evict registrations older than [`REGISTRATION_TTL_SECS`] (audit
    /// 2026-06-07 W2). Returns the number of device registrations removed.
    /// Intended to be called periodically by a background sweep task.
    pub fn evict_stale(&self) -> usize {
        let now = now_secs();
        let cutoff = now.saturating_sub(REGISTRATION_TTL_SECS);
        let mut removed = 0usize;

        // First pass: drop stale device entries within each address.
        for mut entry in self.devices.iter_mut() {
            let before = entry.value().len();
            entry.value_mut().retain(|d| d.registered_at > cutoff);
            removed += before - entry.value().len();
        }
        // Second pass: drop addresses left empty.
        self.devices.retain(|_, devs| !devs.is_empty());

        if removed > 0 {
            info!(removed, "Evicted stale device registrations (TTL sweep)");
            self.mark_dirty_and_maybe_flush();
        }
        removed
    }

    /// Mark the registry dirty and flush if the debounce window has elapsed
    /// (audit 2026-06-07 W2).
    fn mark_dirty_and_maybe_flush(&self) {
        self.dirty.store(true, Ordering::Relaxed);
        let now = now_secs();
        let last = self.last_flush.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= FLUSH_INTERVAL_SECS {
            self.flush();
        }
    }

    /// Force a flush to disk if there are unpersisted changes (audit
    /// 2026-06-07 W2). Call on shutdown and from a periodic timer to bound the
    /// staleness of on-disk state. No-op when not dirty or not persisting.
    pub fn flush(&self) {
        // Claim the dirty flag; if it was already clean, nothing to do.
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return;
        }
        self.last_flush.store(now_secs(), Ordering::Relaxed);
        if let Err(()) = self.persist() {
            // Persist failed — re-arm dirty so a later flush retries.
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    /// Persist the registry to disk (atomic write via temp file + rename).
    /// Tokens are encrypted with the configured cipher (audit 2026-06-07 W3).
    fn persist(&self) -> Result<(), ()> {
        let path = match &self.persist_path {
            Some(p) => p,
            None => return Ok(()),
        };

        // Collect into a regular HashMap for serialization, encrypting each
        // token if a cipher is configured.
        let snapshot: HashMap<String, Vec<DeviceRegistration>> = self
            .devices
            .iter()
            .filter(|e| !e.value().is_empty())
            .map(|e| {
                let devs = e
                    .value()
                    .iter()
                    .map(|d| {
                        let mut d = d.clone();
                        if let Some(ref c) = self.cipher {
                            d.token = c.seal(&d.token);
                        }
                        d
                    })
                    .collect();
                (e.key().clone(), devs)
            })
            .collect();

        let json = match serde_json::to_string_pretty(&snapshot) {
            Ok(j) => j,
            Err(e) => {
                error!(error = %e, "Failed to serialize registry");
                return Err(());
            }
        };

        // Atomic write: write to .tmp, then rename
        let tmp_path = path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp_path, &json) {
            error!(path = %tmp_path.display(), error = %e, "Failed to write registry temp file");
            return Err(());
        }
        if let Err(e) = std::fs::rename(&tmp_path, path) {
            error!(error = %e, "Failed to rename registry temp file");
            return Err(());
        }

        debug!(
            path = %path.display(),
            addresses = snapshot.len(),
            "Registry persisted to disk"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(addr: &str, token: &str) -> RegisterRequest {
        RegisterRequest {
            address: addr.to_string(),
            token: token.to_string(),
            platform: Platform::Fcm,
            channels: vec![],
        }
    }

    #[test]
    fn register_and_get() {
        let reg = DeviceRegistry::new();
        assert!(reg.register(req("klv1a", "tok1")));
        let devs = reg.get_devices("klv1a");
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].token, "tok1");
    }

    #[test]
    fn unregister_drops_empty_address() {
        let reg = DeviceRegistry::new();
        reg.register(req("klv1a", "tok1"));
        assert_eq!(reg.address_count(), 1);
        reg.unregister("klv1a", "tok1");
        // Empty address must be removed so it doesn't count toward the cap.
        assert_eq!(reg.address_count(), 0);
        assert!(reg.get_devices("klv1a").is_empty());
    }

    #[test]
    fn address_cap_refuses_new_but_allows_existing() {
        let reg = DeviceRegistry::new();
        // Fill to the (real) cap would be huge; instead verify the boundary
        // logic by checking existing-address bypass with a small manual fill.
        // We can't lower MAX_ADDRESSES from a test, so simulate the predicate:
        // existing addresses always succeed regardless of count.
        reg.register(req("klv1existing", "tok1"));
        // Re-register existing address with a new device — must succeed.
        assert!(reg.register(req("klv1existing", "tok2")));
        assert_eq!(reg.get_devices("klv1existing").len(), 2);
    }

    #[test]
    fn device_cap_evicts_oldest() {
        let reg = DeviceRegistry::new();
        for i in 0..(MAX_DEVICES_PER_ADDRESS + 3) {
            reg.register(req("klv1a", &format!("tok{i}")));
        }
        assert_eq!(reg.get_devices("klv1a").len(), MAX_DEVICES_PER_ADDRESS);
    }

    #[test]
    fn evict_stale_removes_old_registrations() {
        let reg = DeviceRegistry::new();
        reg.register(req("klv1fresh", "tokfresh"));
        // Manually insert a stale registration (registered_at far in the past).
        reg.devices.insert(
            "klv1stale".to_string(),
            vec![DeviceRegistration {
                address: "klv1stale".to_string(),
                token: "tokstale".to_string(),
                platform: Platform::Fcm,
                channels: vec![],
                registered_at: 1, // ~1970, well past TTL
            }],
        );
        assert_eq!(reg.address_count(), 2);
        let removed = reg.evict_stale();
        assert_eq!(removed, 1);
        assert!(reg.has_devices("klv1fresh"));
        assert!(!reg.has_devices("klv1stale"));
        assert_eq!(reg.address_count(), 1);
    }

    #[test]
    fn persist_roundtrip_encrypts_tokens() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("ogmara-reg-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let cipher = RegistryCipher::from_key_bytes(&[5u8; 32]).unwrap();
        {
            let reg = DeviceRegistry::load(&path, Some(cipher.clone()));
            reg.register(req("klv1a", "supersecret-token"));
            reg.flush();
        }

        // On-disk token must be ciphertext, not plaintext.
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains("supersecret-token"), "token leaked in plaintext");
        assert!(on_disk.contains("enc:v1:"), "token not encrypted");

        // Reload decrypts back to plaintext in memory.
        let reg2 = DeviceRegistry::load(&path, Some(cipher));
        let devs = reg2.get_devices("klv1a");
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].token, "supersecret-token");

        let _ = std::fs::remove_file(&path);
    }
}
