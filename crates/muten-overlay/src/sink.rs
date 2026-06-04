//! A self-contained, tamper-evident audit sink for overlay events.
//!
//! In the full muten workspace, overlay events flow into `muten-events`
//! and the `muten-audit-chain` SHA-256 chain. While this crate is
//! built standalone, it carries a minimal compatible implementation so
//! the overlay monitor can produce a tamper-evident log on its own.
//! The on-disk format and chaining rule match `muten-audit-chain`
//! exactly, so when the workspace is reassembled the two are
//! interchangeable and a log written here verifies there (and vice
//! versa).
//!
//! ## Format
//!
//! One JSON object per line:
//!
//! ```json
//! {"seq":0,"prev_hash":"000…0","kind":"overlay_blocked","window_id":"w1",
//!  "detail":{…},"hash":"<sha256>"}
//! ```
//!
//! `hash = SHA-256(prev_hash || "\0" || kind || "\0" || window_id ||
//! "\0" || detail_json || "\0" || seq_be_bytes)`. The first event's
//! `prev_hash` is [`GENESIS`] (64 zero hex chars). Editing or deleting
//! any line except the last breaks the chain at a detectable point —
//! the defense for threat-model S3 (audit-log tampering).

use crate::monitor::{AuditEvent, AuditSink};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

/// First event's `prev_hash`: 32 zero bytes as hex.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Compute one link's hash from its predecessor + the event content.
#[must_use]
pub fn link_hash(
    prev_hash: &str,
    timestamp_ms: u64,
    kind: &str,
    window_id: &str,
    detail: &serde_json::Value,
    seq: u64,
) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(b"\x00");
    h.update(timestamp_ms.to_be_bytes());
    h.update(b"\x00");
    h.update(kind.as_bytes());
    h.update(b"\x00");
    h.update(window_id.as_bytes());
    h.update(b"\x00");
    h.update(serde_json::to_vec(detail).unwrap_or_default());
    h.update(b"\x00");
    h.update(seq.to_be_bytes());
    hex::encode(h.finalize())
}

/// A file-backed, hash-chained audit sink. Appends one JSONL line per
/// event; holds the running head + seq behind a mutex so concurrent
/// sweeps can't interleave a broken chain.
pub struct ChainedFileSink {
    path: PathBuf,
    state: Mutex<ChainState>,
}

struct ChainState {
    head: String,
    seq: u64,
}

impl ChainedFileSink {
    /// Open (or create) a chained log at `path`. If the file already
    /// exists and verifies, we resume from its head; if it's missing
    /// we start at GENESIS. A pre-existing *broken* file is an error —
    /// we refuse to append onto a tampered log.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, ChainError> {
        let path = path.into();
        let (head, seq) = if path.is_file() {
            let text = std::fs::read_to_string(&path).map_err(|e| ChainError::Io(e.to_string()))?;
            let (count, head) = verify_chain(&text)?;
            (head, count)
        } else {
            (GENESIS.to_string(), 0)
        };
        Ok(Self {
            path,
            state: Mutex::new(ChainState { head, seq }),
        })
    }

    /// Current chain head (for out-of-band verification / Prometheus).
    pub fn head(&self) -> String {
        self.state.lock().unwrap().head.clone()
    }
}

impl AuditSink for ChainedFileSink {
    fn emit(&self, ev: &AuditEvent) {
        let mut st = self.state.lock().unwrap();
        let hash = link_hash(
            &st.head,
            ev.timestamp_ms,
            ev.kind,
            &ev.window_id,
            &ev.detail,
            st.seq,
        );
        let line = serde_json::json!({
            "seq": st.seq,
            "prev_hash": st.head,
            "timestamp_ms": ev.timestamp_ms,
            "kind": ev.kind,
            "window_id": ev.window_id,
            "detail": ev.detail,
            "hash": hash,
        });
        // Best-effort append; an IO failure here is logged to stderr
        // rather than panicking the daemon (the sink is on the audit
        // path, not the enforcement path).
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(f, "{line}");
        } else {
            eprintln!(
                "muten-overlay: audit append failed for {}",
                self.path.display()
            );
            return;
        }
        st.head = hash;
        st.seq += 1;
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("invalid JSON on line {0}: {1}")]
    InvalidJson(usize, String),
    #[error("missing field {0} on line {1}")]
    MissingField(&'static str, usize),
    #[error("chain broken at line {line}: expected prev_hash {expected}, got {actual}")]
    Broken {
        line: usize,
        expected: String,
        actual: String,
    },
    #[error("seq out of order at line {line}: expected {expected}, got {actual}")]
    SeqGap {
        line: usize,
        expected: u64,
        actual: u64,
    },
    #[error("io: {0}")]
    Io(String),
}

/// Verify a chained log's integrity. Returns `(event_count, head)` on
/// success, or the first break with its line number.
pub fn verify_chain(text: &str) -> Result<(u64, String), ChainError> {
    let mut prev = GENESIS.to_string();
    let mut expected_seq: u64 = 0;
    let mut count: u64 = 0;
    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        if raw.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(raw)
            .map_err(|e| ChainError::InvalidJson(line_no, e.to_string()))?;

        let prev_hash = v
            .get("prev_hash")
            .and_then(|x| x.as_str())
            .ok_or(ChainError::MissingField("prev_hash", line_no))?;
        if prev_hash != prev {
            return Err(ChainError::Broken {
                line: line_no,
                expected: prev.clone(),
                actual: prev_hash.to_string(),
            });
        }
        let seq = v
            .get("seq")
            .and_then(serde_json::Value::as_u64)
            .ok_or(ChainError::MissingField("seq", line_no))?;
        if seq != expected_seq {
            return Err(ChainError::SeqGap {
                line: line_no,
                expected: expected_seq,
                actual: seq,
            });
        }
        let kind = v
            .get("kind")
            .and_then(|x| x.as_str())
            .ok_or(ChainError::MissingField("kind", line_no))?;
        let timestamp_ms = v
            .get("timestamp_ms")
            .and_then(serde_json::Value::as_u64)
            .ok_or(ChainError::MissingField("timestamp_ms", line_no))?;
        let window_id = v
            .get("window_id")
            .and_then(|x| x.as_str())
            .ok_or(ChainError::MissingField("window_id", line_no))?;
        let detail = v.get("detail").cloned().unwrap_or(serde_json::json!({}));
        let recomputed = link_hash(prev_hash, timestamp_ms, kind, window_id, &detail, seq);
        let stored = v
            .get("hash")
            .and_then(|x| x.as_str())
            .ok_or(ChainError::MissingField("hash", line_no))?;
        if recomputed != stored {
            return Err(ChainError::Broken {
                line: line_no,
                expected: recomputed,
                actual: stored.to_string(),
            });
        }
        prev = recomputed;
        expected_seq += 1;
        count += 1;
    }
    Ok((count, prev))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn ev(kind: &'static str, id: &str) -> AuditEvent {
        AuditEvent {
            timestamp_ms: 1_000,
            kind,
            window_id: id.into(),
            detail: serde_json::json!({"x": id}),
        }
    }

    #[test]
    fn empty_log_verifies_to_genesis() {
        let (count, head) = verify_chain("").unwrap();
        assert_eq!(count, 0);
        assert_eq!(head, GENESIS);
    }

    #[test]
    fn writes_and_verifies() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("audit.log");
        let sink = ChainedFileSink::open(&p).unwrap();
        sink.emit(&ev("overlay_blocked", "w1"));
        sink.emit(&ev("scareware_detected", "w2"));
        sink.emit(&ev("overlay_suspicious", "w3"));
        let text = std::fs::read_to_string(&p).unwrap();
        let (count, head) = verify_chain(&text).unwrap();
        assert_eq!(count, 3);
        assert_eq!(head, sink.head());
    }

    #[test]
    fn tampering_breaks_chain() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("audit.log");
        let sink = ChainedFileSink::open(&p).unwrap();
        sink.emit(&ev("overlay_blocked", "w1"));
        sink.emit(&ev("overlay_blocked", "w2"));
        let text = std::fs::read_to_string(&p).unwrap();
        let tampered = text.replacen("\"x\":\"w1\"", "\"x\":\"HACKED\"", 1);
        let err = verify_chain(&tampered).unwrap_err();
        assert!(matches!(err, ChainError::Broken { line: 1, .. }));
    }

    #[test]
    fn timestamp_is_recorded_and_chained() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("audit.log");
        let sink = ChainedFileSink::open(&p).unwrap();
        sink.emit(&AuditEvent {
            timestamp_ms: 1_717_000_000_000,
            kind: "overlay_blocked",
            window_id: "w1".into(),
            detail: serde_json::json!({}),
        });
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("\"timestamp_ms\":1717000000000"));
        let (count, _) = verify_chain(&text).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn tampering_with_timestamp_breaks_chain() {
        // The timestamp is part of the hash, so altering it after the
        // fact is detected — an event can't be backdated/forward-dated
        // without breaking the chain.
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("audit.log");
        let sink = ChainedFileSink::open(&p).unwrap();
        sink.emit(&AuditEvent {
            timestamp_ms: 1_000,
            kind: "overlay_blocked",
            window_id: "w1".into(),
            detail: serde_json::json!({}),
        });
        let text = std::fs::read_to_string(&p).unwrap();
        let tampered = text.replacen("\"timestamp_ms\":1000", "\"timestamp_ms\":9999", 1);
        let err = verify_chain(&tampered).unwrap_err();
        assert!(matches!(err, ChainError::Broken { line: 1, .. }));
    }

    #[test]
    fn deleting_a_line_breaks_chain() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("audit.log");
        let sink = ChainedFileSink::open(&p).unwrap();
        sink.emit(&ev("a", "w1"));
        sink.emit(&ev("b", "w2"));
        sink.emit(&ev("c", "w3"));
        let text = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // Drop the middle line.
        let bad = format!("{}\n{}\n", lines[0], lines[2]);
        let err = verify_chain(&bad).unwrap_err();
        match err {
            ChainError::Broken { line, .. } | ChainError::SeqGap { line, .. } => {
                assert_eq!(line, 2);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn resume_from_existing_log_continues_chain() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("audit.log");
        {
            let sink = ChainedFileSink::open(&p).unwrap();
            sink.emit(&ev("a", "w1"));
            sink.emit(&ev("b", "w2"));
        }
        // Re-open: should resume at seq 2 and keep the chain intact.
        let sink2 = ChainedFileSink::open(&p).unwrap();
        sink2.emit(&ev("c", "w3"));
        let text = std::fs::read_to_string(&p).unwrap();
        let (count, _) = verify_chain(&text).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn refuses_to_open_tampered_log() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("audit.log");
        {
            let sink = ChainedFileSink::open(&p).unwrap();
            sink.emit(&ev("a", "w1"));
        }
        // Corrupt it, then try to re-open.
        let text = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, text.replacen("\"x\":\"w1\"", "\"x\":\"evil\"", 1)).unwrap();
        assert!(ChainedFileSink::open(&p).is_err());
    }
}
