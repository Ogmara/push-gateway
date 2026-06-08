//! Klever wallet signature verification for device registration.
//!
//! The push gateway must verify that a `/register` (or `/unregister`) request
//! is signed by the wallet/device whose notifications it controls — otherwise
//! anyone could register their own push token under a victim's address and
//! receive that victim's mention pushes (audit 2026-06-07 C1/C2).
//!
//! The signature uses the same Klever message-signing format as the rest of
//! Ogmara (protocol spec 4.1.1):
//!   prefix `\x17Klever Signed Message:\n` + decimal length + message
//!   → Keccak-256 → Ed25519.

use ed25519_dalek::{Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

/// Klever message signing prefix (from kos-rs).
const KLEVER_MSG_PREFIX: &[u8] = b"\x17Klever Signed Message:\n";

/// Bech32 HRPs accepted as a signing identity: wallet (`klv`) or delegated
/// device key (`ogd`).
const WALLET_HRP: &str = "klv";
const DEVICE_HRP: &str = "ogd";

/// Errors from registration-auth verification.
#[derive(Debug)]
pub enum AuthError {
    /// Address is not a valid klv1/ogd1 bech32 address.
    InvalidAddress,
    /// Signature bytes are malformed or the wrong length.
    InvalidSignature,
    /// Signature did not verify against the address's public key.
    VerificationFailed,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidAddress => write!(f, "invalid address"),
            AuthError::InvalidSignature => write!(f, "invalid signature"),
            AuthError::VerificationFailed => write!(f, "signature verification failed"),
        }
    }
}

/// Decode a bech32 Klever address (`klv1…` wallet or `ogd1…` device) to its
/// 32-byte Ed25519 public key.
pub fn address_to_verifying_key(address: &str) -> Result<VerifyingKey, AuthError> {
    let (hrp, data) = bech32::decode(address).map_err(|_| AuthError::InvalidAddress)?;
    let hrp_str = hrp.as_str();
    if hrp_str != WALLET_HRP && hrp_str != DEVICE_HRP {
        return Err(AuthError::InvalidAddress);
    }
    if data.len() != 32 {
        return Err(AuthError::InvalidAddress);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data);
    VerifyingKey::from_bytes(&bytes).map_err(|_| AuthError::InvalidAddress)
}

/// Compute the Klever message hash for `message`: prefix + decimal-length +
/// message → Keccak-256.
fn klever_message_hash(message: &[u8]) -> [u8; 32] {
    let length_str = message.len().to_string();
    let mut data =
        Vec::with_capacity(KLEVER_MSG_PREFIX.len() + length_str.len() + message.len());
    data.extend_from_slice(KLEVER_MSG_PREFIX);
    data.extend_from_slice(length_str.as_bytes());
    data.extend_from_slice(message);
    Keccak256::digest(&data).into()
}

/// Verify a base64 Ed25519 signature over `message` (in Klever message format)
/// against the public key decoded from `address`.
pub fn verify_klever_signature(
    address: &str,
    message: &str,
    sig_b64: &str,
) -> Result<(), AuthError> {
    let verifying_key = address_to_verifying_key(address)?;

    let sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        sig_b64,
    )
    .map_err(|_| AuthError::InvalidSignature)?;
    if sig_bytes.len() != 64 {
        return Err(AuthError::InvalidSignature);
    }
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| AuthError::InvalidSignature)?;

    let hash = klever_message_hash(message.as_bytes());
    verifying_key
        .verify_strict(&hash, &signature)
        .map_err(|_| AuthError::VerificationFailed)
}

/// Build the canonical registration-claim string a client signs (audit
/// 2026-06-07 host-binding). `action` is `"register"` or `"unregister"`.
/// Binding `gateway_host` defeats cross-service replay; the single-use
/// `nonce` defeats same-gateway replay; `address` + `token` bind the claim to
/// exactly this registration.
pub fn build_push_claim(
    action: &str,
    gateway_host: &str,
    nonce: &str,
    timestamp: u64,
    address: &str,
    token: &str,
) -> String {
    format!("ogmara-push:{action}:{gateway_host}:{nonce}:{timestamp}:{address}:{token}")
}

/// Token-at-rest encryption for the device registry (audit 2026-06-07 W3).
///
/// The spec claims push tokens are encrypted at rest, but `registry.json`
/// previously stored them in plaintext. `RegistryCipher` wraps AES-256-GCM with
/// a 32-byte key loaded from the `OGMARA_REGISTRY_KEY` env var. Each record is
/// sealed with a fresh random 96-bit nonce; the on-disk form is
/// `base64(nonce ‖ ciphertext ‖ tag)` prefixed with a version tag so plaintext
/// (legacy / key-unset) records remain distinguishable and loadable.
pub mod registry_crypto {
    use aes_gcm::aead::{Aead, KeyInit, OsRng};
    use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    /// Marker prefixing every encrypted token blob on disk. Tokens that don't
    /// start with this are treated as legacy plaintext (key was unset when they
    /// were written), so enabling encryption is non-destructive.
    const ENC_PREFIX: &str = "enc:v1:";

    /// AES-256-GCM cipher over registry push tokens.
    #[derive(Clone)]
    pub struct RegistryCipher {
        cipher: Aes256Gcm,
    }

    impl RegistryCipher {
        /// Build a cipher from a 32-byte key. Returns `None` if the key isn't
        /// exactly 32 bytes.
        pub fn from_key_bytes(key: &[u8]) -> Option<Self> {
            if key.len() != 32 {
                return None;
            }
            let key = Key::<Aes256Gcm>::from_slice(key);
            Some(Self {
                cipher: Aes256Gcm::new(key),
            })
        }

        /// Parse a 32-byte key from a hex or base64 string (the
        /// `OGMARA_REGISTRY_KEY` env value).
        ///
        /// HEX is tried FIRST whenever the value is unambiguously hex (exactly
        /// 64 chars, all `[0-9a-fA-F]`) — otherwise a 64-hex key, which also
        /// happens to be a valid base64 string (decoding to 48 bytes, then
        /// rejected → falling through), risked an operator's hex key being
        /// silently misread (audit follow-up B4.4 W-2). A 44-char base64 of 32
        /// bytes isn't valid hex, so it falls to the base64 branch.
        pub fn from_env_value(value: &str) -> Option<Self> {
            let value = value.trim();
            let looks_hex = value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit());
            if looks_hex {
                if let Ok(bytes) = hex::decode(value) {
                    if let Some(c) = Self::from_key_bytes(&bytes) {
                        return Some(c);
                    }
                }
            }
            if let Ok(bytes) = BASE64.decode(value) {
                if let Some(c) = Self::from_key_bytes(&bytes) {
                    return Some(c);
                }
            }
            // Final fallback: hex for any other length (e.g. with separators
            // stripped by the operator) — best-effort.
            if let Ok(bytes) = hex::decode(value) {
                if let Some(c) = Self::from_key_bytes(&bytes) {
                    return Some(c);
                }
            }
            None
        }

        /// Encrypt a token for storage. Output is `enc:v1:base64(nonce‖ct‖tag)`.
        /// On encryption failure the plaintext is returned unchanged (logged by
        /// the caller); GCM only fails on absurd input sizes.
        pub fn seal(&self, plaintext: &str) -> String {
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            match self.cipher.encrypt(&nonce, plaintext.as_bytes()) {
                Ok(mut ct) => {
                    // Prepend the nonce so decrypt is self-contained.
                    let mut blob = nonce.to_vec();
                    blob.append(&mut ct);
                    format!("{ENC_PREFIX}{}", BASE64.encode(&blob))
                }
                Err(_) => plaintext.to_string(),
            }
        }

        /// Decrypt a stored token. Records without the `enc:v1:` prefix are
        /// returned verbatim (legacy plaintext). Returns `None` only if a
        /// prefixed blob is malformed or fails authentication (wrong key /
        /// tampering).
        pub fn open(&self, stored: &str) -> Option<String> {
            let body = match stored.strip_prefix(ENC_PREFIX) {
                Some(b) => b,
                None => return Some(stored.to_string()), // legacy plaintext
            };
            let blob = BASE64.decode(body).ok()?;
            if blob.len() < 12 {
                return None;
            }
            let (nonce_bytes, ct) = blob.split_at(12);
            let nonce = Nonce::from_slice(nonce_bytes);
            let pt = self.cipher.decrypt(nonce, ct).ok()?;
            String::from_utf8(pt).ok()
        }

        /// Whether a stored value is in encrypted form.
        #[allow(dead_code)]
        pub fn is_encrypted(stored: &str) -> bool {
            stored.starts_with(ENC_PREFIX)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn roundtrip() {
            let cipher = RegistryCipher::from_key_bytes(&[7u8; 32]).unwrap();
            let token = "fcm-token-abc123";
            let sealed = cipher.seal(token);
            assert!(RegistryCipher::is_encrypted(&sealed));
            assert_ne!(sealed, token);
            assert_eq!(cipher.open(&sealed).as_deref(), Some(token));
        }

        #[test]
        fn distinct_nonces_per_seal() {
            let cipher = RegistryCipher::from_key_bytes(&[1u8; 32]).unwrap();
            let a = cipher.seal("same");
            let b = cipher.seal("same");
            assert_ne!(a, b, "each seal must use a fresh random nonce");
            assert_eq!(cipher.open(&a).as_deref(), Some("same"));
            assert_eq!(cipher.open(&b).as_deref(), Some("same"));
        }

        #[test]
        fn legacy_plaintext_passes_through() {
            let cipher = RegistryCipher::from_key_bytes(&[2u8; 32]).unwrap();
            assert_eq!(cipher.open("raw-plaintext-token").as_deref(), Some("raw-plaintext-token"));
        }

        #[test]
        fn wrong_key_fails_to_open() {
            let a = RegistryCipher::from_key_bytes(&[3u8; 32]).unwrap();
            let b = RegistryCipher::from_key_bytes(&[4u8; 32]).unwrap();
            let sealed = a.seal("secret");
            assert!(b.open(&sealed).is_none(), "wrong key must not decrypt");
        }

        #[test]
        fn rejects_wrong_key_length() {
            assert!(RegistryCipher::from_key_bytes(&[0u8; 16]).is_none());
            assert!(RegistryCipher::from_key_bytes(&[0u8; 31]).is_none());
        }

        #[test]
        fn from_env_accepts_base64_and_hex() {
            let key = [9u8; 32];
            let b64 = base64::engine::general_purpose::STANDARD.encode(key);
            let hexed = hex::encode(key);
            assert!(RegistryCipher::from_env_value(&b64).is_some());
            assert!(RegistryCipher::from_env_value(&hexed).is_some());
            assert!(RegistryCipher::from_env_value("too-short").is_none());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // Deterministic test keys — no RNG dependency needed.
    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    // Re-derive a klv1 address from a signing key the same way the SDK does.
    fn address_of(key: &SigningKey) -> String {
        let hrp = bech32::Hrp::parse("klv").unwrap();
        bech32::encode::<bech32::Bech32>(hrp, key.verifying_key().as_bytes()).unwrap()
    }

    fn sign(key: &SigningKey, msg: &str) -> String {
        let hash = klever_message_hash(msg.as_bytes());
        let sig = key.sign(&hash);
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
    }

    #[test]
    fn valid_signature_verifies() {
        let key = test_key(1);
        let addr = address_of(&key);
        let msg = build_push_claim("register", "https://gw.ogmara.org", "abcdef0123456789", 1700, &addr, "tok");
        let sig = sign(&key, &msg);
        assert!(verify_klever_signature(&addr, &msg, &sig).is_ok());
    }

    #[test]
    fn tampered_message_fails() {
        let key = test_key(2);
        let addr = address_of(&key);
        let msg = build_push_claim("register", "https://gw.ogmara.org", "abcdef0123456789", 1700, &addr, "tok");
        let sig = sign(&key, &msg);
        let other = build_push_claim("register", "https://gw.ogmara.org", "abcdef0123456789", 1700, &addr, "DIFFERENT");
        assert!(verify_klever_signature(&addr, &other, &sig).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let key = test_key(3);
        let attacker = test_key(4);
        let addr = address_of(&key);
        let msg = build_push_claim("register", "https://gw.ogmara.org", "abcdef0123456789", 1700, &addr, "tok");
        let sig = sign(&attacker, &msg); // signed by someone else
        assert!(verify_klever_signature(&addr, &msg, &sig).is_err());
    }

    #[test]
    fn rejects_non_klever_hrp() {
        assert!(address_to_verifying_key("bc1qexampleexampleexample").is_err());
    }
}
