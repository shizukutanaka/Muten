//! Admin PIN storage: a salted, iterated SHA-256 record.
//!
//! The PIN gates *temporary unmute grants only*. It is a deterrent
//! against casual unmuting by the PC's everyday user — it is not a
//! cryptographic vault, and the README says so. What we do guarantee:
//!
//! - The PIN itself is never written to disk, the policy file, or the
//!   audit log — only `salt`, `iterations`, and the derived hash are.
//! - Verification compares in constant time.
//! - The KDF is iterated SHA-256 (100k rounds). That is weaker than
//!   Argon2id; it was chosen to stay dependency-light and offline, and
//!   the threat model (a local user guessing at a console prompt, with
//!   every failure written to the audit log) makes online guessing the
//!   realistic attack — not offline cracking of a stolen policy file.
//!   An admin who can read `policy.json` can also simply replace the
//!   hash, which is one more reason the PIN is a deterrent, not a wall.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default KDF iteration count for newly created PIN records.
pub const PIN_ITERATIONS: u32 = 100_000;

/// Salt length in bytes for newly created PIN records.
pub const SALT_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinRecord {
    /// Hex-encoded salt (per-install, unique — secrecy is not required,
    /// uniqueness is).
    pub salt_hex: String,
    /// Hex-encoded derived hash.
    pub hash_hex: String,
    /// KDF iteration count used for this record.
    pub iterations: u32,
}

/// Derive the hash: `h0 = SHA256(salt ‖ pin)`, then
/// `h(i+1) = SHA256(h(i) ‖ salt)`, for `iterations` rounds total.
fn derive(pin: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(pin.as_bytes());
    let mut out: [u8; 32] = h.finalize().into();
    for _ in 1..iterations.max(1) {
        let mut h = Sha256::new();
        h.update(out);
        h.update(salt);
        out = h.finalize().into();
    }
    out
}

impl PinRecord {
    /// Create a record for `pin` with the given salt and the default
    /// iteration count.
    pub fn new(pin: &str, salt: &[u8]) -> PinRecord {
        PinRecord {
            salt_hex: hex::encode(salt),
            hash_hex: hex::encode(derive(pin, salt, PIN_ITERATIONS)),
            iterations: PIN_ITERATIONS,
        }
    }

    /// Verify a candidate PIN in constant time.
    pub fn verify(&self, pin: &str) -> bool {
        let salt = match hex::decode(&self.salt_hex) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let expected = match hex::decode(&self.hash_hex) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let actual = derive(pin, &salt, self.iterations);
        if expected.len() != actual.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in actual.iter().zip(expected.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// Generate a salt without an RNG dependency: SHA-256 over the current
/// time (nanosecond resolution), the process id, and a process-local
/// counter, truncated to [`SALT_LEN`] bytes. A salt needs uniqueness,
/// not secrecy; two installs colliding is what this prevents.
pub fn generate_salt() -> [u8; SALT_LEN] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h = Sha256::new();
    h.update(nanos.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    h.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    let digest: [u8; 32] = h.finalize().into();
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&digest[..SALT_LEN]);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_pin_verifies_wrong_pin_does_not() {
        let rec = PinRecord::new("4821", &[1, 2, 3, 4]);
        assert!(rec.verify("4821"));
        assert!(!rec.verify("4822"));
        assert!(!rec.verify(""));
        assert!(!rec.verify("48210"));
    }

    #[test]
    fn different_salts_give_different_hashes() {
        let a = PinRecord::new("1234", &[0u8; 16]);
        let b = PinRecord::new("1234", &[9u8; 16]);
        assert_ne!(a.hash_hex, b.hash_hex);
    }

    #[test]
    fn record_never_contains_the_pin() {
        let rec = PinRecord::new("9753", &[5u8; 16]);
        let json = serde_json::to_string(&rec).unwrap();
        assert!(!json.contains("9753"));
    }

    #[test]
    fn corrupted_record_fails_closed() {
        let rec = PinRecord {
            salt_hex: "not-hex".into(),
            hash_hex: "zz".into(),
            iterations: 10,
        };
        assert!(!rec.verify("1234"));
    }

    #[test]
    fn generated_salts_are_unique() {
        assert_ne!(generate_salt(), generate_salt());
    }

    #[test]
    fn derive_is_deterministic() {
        assert_eq!(derive("0000", b"salt", 10), derive("0000", b"salt", 10));
        assert_ne!(derive("0000", b"salt", 10), derive("0001", b"salt", 10));
    }
}
