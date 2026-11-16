//! A temporary-unmute grant: the one legitimate way sound comes back.
//!
//! A grant is created by the `unmute` CLI command after the admin PIN
//! verifies. It lives in its own small file (`grant.json`) so the
//! resident agent can re-read it on every poll — a grant created while
//! the agent is already running takes effect on the next poll, and a
//! grant whose time has run out is ignored (and the endpoint re-muted)
//! on the next poll after expiry. Grants are never extended by the
//! agent; a new grant needs the PIN again.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// Unix seconds when the grant was created.
    pub granted_at_unix: i64,
    /// Unix seconds when the grant stops being honoured.
    pub expires_at_unix: i64,
    /// Length of the grant in minutes, as granted (after policy clamp).
    pub minutes: u32,
}

impl Grant {
    pub fn new(now_unix: i64, minutes: u32) -> Grant {
        Grant {
            granted_at_unix: now_unix,
            expires_at_unix: now_unix + i64::from(minutes) * 60,
            minutes,
        }
    }

    /// A grant is active strictly before its expiry instant.
    pub fn is_active(&self, now_unix: i64) -> bool {
        now_unix >= self.granted_at_unix && now_unix < self.expires_at_unix
    }

    /// Seconds left, or a negative/zero value once expired.
    pub fn remaining_secs(&self, now_unix: i64) -> i64 {
        self.expires_at_unix - now_unix
    }

    /// Load a grant file. A missing file is `Ok(None)`; a corrupt file
    /// is an error — silently treating corruption as "no grant" would
    /// hide tampering, and treating it as "grant" would be worse.
    pub fn load(path: &std::path::Path) -> Result<Option<Grant>, crate::Error> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Some(serde_json::from_str(&text)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Persist a grant (pretty JSON, written via a temp file + rename so
    /// a crash mid-write cannot leave a torn grant behind).
    pub fn save(&self, path: &std::path::Path) -> Result<(), crate::Error> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Remove the grant file if present (e.g. after it has expired and
    /// been acted on).
    pub fn clear(path: &std::path::Path) -> Result<(), crate::Error> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_lifecycle() {
        let g = Grant::new(1_000, 30);
        assert!(!g.is_active(999));
        assert!(g.is_active(1_000));
        assert!(g.is_active(1_000 + 29 * 60));
        assert!(!g.is_active(1_000 + 30 * 60)); // expiry instant: over
        assert_eq!(g.remaining_secs(1_000), 30 * 60);
        assert!(g.remaining_secs(1_000 + 31 * 60) < 0);
    }

    #[test]
    fn save_load_clear_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grant.json");
        assert_eq!(Grant::load(&path).unwrap(), None);
        let g = Grant::new(42, 15);
        g.save(&path).unwrap();
        assert_eq!(Grant::load(&path).unwrap(), Some(g));
        Grant::clear(&path).unwrap();
        assert_eq!(Grant::load(&path).unwrap(), None);
        // Clearing twice is fine.
        Grant::clear(&path).unwrap();
    }

    #[test]
    fn corrupt_grant_file_is_an_error_not_a_grant() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grant.json");
        std::fs::write(&path, "{not json").unwrap();
        assert!(Grant::load(&path).is_err());
    }
}
