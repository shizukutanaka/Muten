//! Tamper-evident audit log: append-only JSON Lines with a SHA-256
//! hash chain, in the same spirit as muten-overlay's audit chain.
//!
//! Each line is `{"ts":…,"kind":…,"detail":{…},"prev":…,"hash":…}`
//! where `hash = SHA256(prev ‖ "\n" ‖ canonical_json({ts,kind,detail}))`
//! and the first line's `prev` is the literal `"GENESIS"`.
//!
//! Honest wording: this makes the log tamper-**evident**, not
//! tamper-**proof**. A local administrator can delete the whole file;
//! what they cannot do is quietly edit or remove an entry in the
//! middle without breaking every subsequent hash — *provided* someone
//! compares against a copy or a recorded head hash kept elsewhere
//! (e.g. forwarded to a file share by a scheduled task). [`verify_chain`]
//! performs that check.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Event kinds written to the audit log. The PIN itself, and any
/// candidate PIN, are **never** logged — a denied attempt records only
/// that it happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    AgentStarted,
    AgentStopped,
    PolicyLoaded,
    PolicyError,
    /// The agent muted the endpoint (startup, volume raised, grant
    /// expired, schedule started — the reason is in the detail).
    Muted,
    /// The endpoint was found unmuted without a grant (recorded just
    /// before the re-mute, so a raise is never silently swallowed).
    VolumeRaisedDetected,
    /// Sound was restored because a grant is active.
    UnmutedForGrant,
    UnmuteGranted,
    UnmuteDenied,
    GrantExpired,
    HelperError,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub ts_unix: i64,
    pub kind: EventKind,
    #[serde(default)]
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ChainedLine {
    ts_unix: i64,
    kind: EventKind,
    detail: serde_json::Value,
    prev: String,
    hash: String,
}

fn line_hash(prev: &str, ts_unix: i64, kind: EventKind, detail: &serde_json::Value) -> String {
    // Canonical form: serde_json serializes struct fields in declaration
    // order and map keys in insertion order; `detail` values built by
    // this crate use `serde_json::json!`, whose object is a BTreeMap
    // (sorted keys) unless the preserve_order feature is on — it is not.
    let canonical = serde_json::json!({
        "ts_unix": ts_unix,
        "kind": kind,
        "detail": detail,
    });
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(canonical.to_string().as_bytes());
    hex::encode(h.finalize())
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("audit chain broken at line {line}: {reason}")]
    Broken { line: usize, reason: String },
}

/// Append-only writer. Opening a log that already exists continues the
/// chain from its last line; a corrupt existing tail is an error, not
/// something to paper over.
pub struct AuditLog {
    path: PathBuf,
    head: String,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<AuditLog, AuditError> {
        let head = match std::fs::read_to_string(path) {
            Ok(text) => {
                let status = verify_chain(&text)?;
                status.head
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => "GENESIS".to_string(),
            Err(e) => return Err(e.into()),
        };
        Ok(AuditLog {
            path: path.to_path_buf(),
            head,
        })
    }

    /// Append one event; returns the new chain head hash.
    pub fn append(&mut self, event: &Event) -> Result<String, AuditError> {
        let hash = line_hash(&self.head, event.ts_unix, event.kind, &event.detail);
        let line = ChainedLine {
            ts_unix: event.ts_unix,
            kind: event.kind,
            detail: event.detail.clone(),
            prev: self.head.clone(),
            hash: hash.clone(),
        };
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(&line)?)?;
        self.head = hash.clone();
        Ok(hash)
    }

    pub fn head(&self) -> &str {
        &self.head
    }
}

/// Result of a successful chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainStatus {
    pub events: usize,
    pub head: String,
}

/// Verify a whole log's text. Empty text is a valid empty chain.
pub fn verify_chain(text: &str) -> Result<ChainStatus, AuditError> {
    let mut prev = "GENESIS".to_string();
    let mut count = 0usize;
    for (i, raw) in text.lines().enumerate() {
        if raw.trim().is_empty() {
            continue;
        }
        let line: ChainedLine = serde_json::from_str(raw).map_err(|e| AuditError::Broken {
            line: i + 1,
            reason: format!("unparseable line: {e}"),
        })?;
        if line.prev != prev {
            return Err(AuditError::Broken {
                line: i + 1,
                reason: "prev hash does not match the previous line".into(),
            });
        }
        let expect = line_hash(&line.prev, line.ts_unix, line.kind, &line.detail);
        if expect != line.hash {
            return Err(AuditError::Broken {
                line: i + 1,
                reason: "hash mismatch (entry was edited)".into(),
            });
        }
        prev = line.hash;
        count += 1;
    }
    Ok(ChainStatus {
        events: count,
        head: prev,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: EventKind) -> Event {
        Event {
            ts_unix: 1_700_000_000,
            kind,
            detail: serde_json::json!({"reason": "test"}),
        }
    }

    #[test]
    fn append_and_verify_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        {
            let mut log = AuditLog::open(&path).unwrap();
            log.append(&ev(EventKind::AgentStarted)).unwrap();
            log.append(&ev(EventKind::Muted)).unwrap();
        }
        // Reopening continues the chain instead of restarting it.
        let mut log = AuditLog::open(&path).unwrap();
        log.append(&ev(EventKind::AgentStopped)).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let status = verify_chain(&text).unwrap();
        assert_eq!(status.events, 3);
        assert_eq!(status.head, log.head());
    }

    #[test]
    fn edited_entry_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut log = AuditLog::open(&path).unwrap();
        log.append(&ev(EventKind::AgentStarted)).unwrap();
        log.append(&ev(EventKind::Muted)).unwrap();
        drop(log);

        let text = std::fs::read_to_string(&path).unwrap();
        let tampered = text.replace("\"test\"", "\"forged\"");
        assert!(verify_chain(&tampered).is_err());
    }

    #[test]
    fn removed_middle_entry_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut log = AuditLog::open(&path).unwrap();
        for _ in 0..3 {
            log.append(&ev(EventKind::Muted)).unwrap();
        }
        drop(log);
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.remove(1);
        assert!(verify_chain(&lines.join("\n")).is_err());
    }

    #[test]
    fn corrupt_existing_log_is_an_error_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "{broken\n").unwrap();
        assert!(AuditLog::open(&path).is_err());
    }

    #[test]
    fn empty_text_is_a_valid_empty_chain() {
        let status = verify_chain("").unwrap();
        assert_eq!(status.events, 0);
        assert_eq!(status.head, "GENESIS");
    }
}
