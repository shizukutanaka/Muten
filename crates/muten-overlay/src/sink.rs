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
//! {"seq":0,"prev_hash":"000…0","timestamp_ms":1700000000000,
//!  "kind":"overlay_blocked","window_id":"w1","detail":{…},"hash":"<sha256>"}
//! ```
//!
//! `hash = SHA-256(prev_hash || "\0" || timestamp_ms_be || "\0" || kind
//! || "\0" || window_id || "\0" || detail_json || "\0" || seq_be)` — see
//! [`link_hash`] for the exact byte layout. `timestamp_ms` is part of the
//! hash, so events cannot be backdated. The first event's `prev_hash` is
//! [`GENESIS`] (64 zero hex chars). Editing or deleting any line except
//! the last breaks the chain at a detectable point — the defense for
//! threat-model S3 (audit-log tampering).

use crate::monitor::{AuditEvent, AuditSink};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

/// Canonical JSON serialization: sorts object keys lexicographically at every
/// nesting level, uses no whitespace. This is the deterministic byte form fed
/// into [`link_hash`] for the `detail` field, so the hash is independent of
/// `serde_json`'s internal map ordering (which could change between feature
/// flags or versions). Scalars, arrays, and strings use `serde_json`'s own
/// encoding for correctness (proper Unicode escaping, compact number form).
fn canonical_json(v: &serde_json::Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(&mut out, v);
    out
}

fn write_canonical(out: &mut Vec<u8>, v: &serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            out.push(b'{');
            let mut pairs: Vec<(&str, &Value)> = map.iter().map(|(k, v)| (k.as_str(), v)).collect();
            pairs.sort_unstable_by_key(|(k, _)| *k);
            for (i, (key, val)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                // Use serde_json for string key encoding (proper escaping).
                out.extend_from_slice(serde_json::to_string(key).unwrap_or_default().as_bytes());
                out.push(b':');
                write_canonical(out, val);
            }
            out.push(b'}');
        }
        Value::Array(arr) => {
            out.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(out, item);
            }
            out.push(b']');
        }
        // Scalars: serde_json's encoding is canonical for null/bool/number/string.
        other => out.extend_from_slice(serde_json::to_string(other).unwrap_or_default().as_bytes()),
    }
}

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
    h.update(canonical_json(detail));
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
    /// we start at GENESIS.
    ///
    /// A **torn final line** — the signature of a crash mid-`emit`,
    /// before the terminating newline — is recovered: the unverifiable
    /// partial line is dropped and we resume from the surviving prefix,
    /// but only if that prefix is itself an intact chain. Any other
    /// break (a tampered *complete* line, which always ends in a
    /// newline) is still an error: we refuse to append onto a tampered
    /// log, preserving tamper-evidence (threat-model S3).
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, ChainError> {
        let path = path.into();
        let (head, seq) = if path.is_file() {
            let text = std::fs::read_to_string(&path).map_err(|e| ChainError::Io(e.to_string()))?;
            match verify_chain(&text) {
                Ok((count, head)) => (head, count),
                Err(e) => match recover_torn_tail(&text) {
                    Some((prefix, count, head)) => {
                        // Truncate the partial tail so the next append
                        // continues a verifiable chain.
                        std::fs::write(&path, &prefix)
                            .map_err(|e| ChainError::Io(e.to_string()))?;
                        eprintln!(
                            "muten-overlay: recovered torn audit tail in {} (resuming at seq {count})",
                            path.display()
                        );
                        (head, count)
                    }
                    None => return Err(e),
                },
            }
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

/// Collect each event's stored `hash` (as leaf bytes) from a log, after
/// verifying the chain's integrity. The Merkle tree is built over these
/// per-event link hashes, so the root commits to the exact ordered set of
/// events the chain already authenticates. Returns the chain's
/// [`verify_chain`] error if the log does not verify.
pub fn log_leaves(text: &str) -> Result<Vec<Vec<u8>>, ChainError> {
    // Integrity gate first: a Merkle root over a tampered log would be
    // meaningless. This also guarantees every line parses below.
    verify_chain(text)?;
    let mut leaves = Vec::new();
    for raw in text.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| ChainError::InvalidJson(0, e.to_string()))?;
        if let Some(h) = v.get("hash").and_then(|x| x.as_str()) {
            leaves.push(h.as_bytes().to_vec());
        }
    }
    Ok(leaves)
}

/// The RFC 6962 Merkle root over a verified log — a single 32-byte
/// commitment to the whole ordered event set, suitable for publishing or
/// signing out-of-band as an external anchor (see [`crate::merkle`]).
/// Fails with the chain error if the log does not verify.
pub fn merkle_root_of_log(text: &str) -> Result<String, ChainError> {
    Ok(crate::merkle::merkle_root(&log_leaves(text)?))
}

/// An inclusion proof that the event at `seq` is committed by the Merkle
/// root of this log, for compact third-party verification against an
/// anchored root. `None` if `seq` is out of range; chain error if the log
/// does not verify.
pub fn inclusion_proof_for_seq(text: &str, seq: usize) -> Result<Option<Vec<String>>, ChainError> {
    Ok(crate::merkle::inclusion_proof(&log_leaves(text)?, seq))
}

/// RFC 9162 §2.1.4 consistency proof over a verified log.
///
/// Returns the O(log n) sibling hashes proving that the first `first`
/// events in `text` form the same Merkle tree as the full log.  The
/// proof allows any holder of both Merkle roots (e.g. from two
/// published anchors at different points in time) to verify that the
/// newer log is an append-only extension of the older one — no new
/// events were inserted or re-ordered.
///
/// Returns `None` when `first > event_count` (out of range).  An empty
/// proof is returned (and is valid) when `first == 0` (empty prefix)
/// or `first == event_count` (identical tree).  Chain error if the log
/// does not verify.
pub fn consistency_proof_for_range(
    text: &str,
    first: usize,
) -> Result<Option<Vec<String>>, ChainError> {
    let leaves = log_leaves(text)?;
    if first > leaves.len() {
        return Ok(None);
    }
    Ok(Some(crate::merkle::consistency_proof(first, &leaves)))
}

/// Per-signal occurrence counts across a verified audit log.
///
/// Aggregated from the `detail.signals` array of `overlay_blocked` and
/// `overlay_suspicious` events.  Useful for threshold tuning and FP-rate
/// estimation: operators can rank signals by `blocks + suspicious` to see
/// which signals fire most often, and by `blocks / (blocks + suspicious)`
/// to estimate how often a signal alone led to a dismissal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignalStats {
    /// Times this signal appeared in an `overlay_blocked` event.
    pub blocks: u64,
    /// Times this signal appeared in an `overlay_suspicious` event.
    pub suspicious: u64,
}

impl SignalStats {
    /// Total appearances (blocks + suspicious).
    #[must_use]
    pub fn total(&self) -> u64 {
        self.blocks + self.suspicious
    }
}

/// Per-signal firing statistics across a **verified** audit log.
///
/// Parses `overlay_blocked` and `overlay_suspicious` events from `text`
/// and aggregates the `detail.signals` array into a map keyed by signal
/// name.  The log is verified for chain integrity before any parsing;
/// returns a chain error if the log does not verify.
///
/// Use this to:
/// - Rank signals by frequency (`total()`) to identify which drive most
///   alerts and tune blocklist sensitivity.
/// - Compare `blocks` vs `suspicious` ratios to spot signals that mostly
///   contribute to review-queue noise vs confirmed dismissals.
/// - Track how firing rates shift over time (run periodically on a
///   rolling audit-log window).
pub fn signal_firing_stats(
    text: &str,
) -> Result<std::collections::HashMap<String, SignalStats>, ChainError> {
    verify_chain(text)?;
    let mut stats: std::collections::HashMap<String, SignalStats> =
        std::collections::HashMap::new();
    for (i, raw) in text.lines().enumerate() {
        if raw.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| ChainError::InvalidJson(i + 1, e.to_string()))?;
        let kind = v.get("kind").and_then(|k| k.as_str()).unwrap_or_default();
        let is_block = kind == "overlay_blocked";
        let is_suspicious = kind == "overlay_suspicious";
        if !is_block && !is_suspicious {
            continue;
        }
        if let Some(signals) = v
            .get("detail")
            .and_then(|d| d.get("signals"))
            .and_then(|s| s.as_array())
        {
            for sig in signals {
                if let Some(name) = sig.as_str() {
                    let entry = stats.entry(name.to_string()).or_default();
                    if is_block {
                        entry.blocks += 1;
                    } else {
                        entry.suspicious += 1;
                    }
                }
            }
        }
    }
    Ok(stats)
}

/// An error that can occur while opening or verifying the audit chain.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainError {
    /// A line in the log is not valid JSON.
    #[error("invalid JSON on line {0}: {1}")]
    InvalidJson(usize, String),
    /// A required field is absent from a log line.
    #[error("missing field {0} on line {1}")]
    MissingField(&'static str, usize),
    /// The hash chain is broken at the given line.
    #[error("chain broken at line {line}: expected prev_hash {expected}, got {actual}")]
    Broken {
        /// 1-based line number where the break was detected.
        line: usize,
        /// The hash value expected at this position.
        expected: String,
        /// The hash value actually found.
        actual: String,
    },
    /// The seq field is out of order.
    #[error("seq out of order at line {line}: expected {expected}, got {actual}")]
    SeqGap {
        /// 1-based line number where the gap was detected.
        line: usize,
        /// Expected seq value.
        expected: u64,
        /// Actual seq value found.
        actual: u64,
    },
    /// An IO error occurred while opening or writing the log file.
    #[error("io: {0}")]
    Io(String),
}

/// If `text` ends in a torn (incomplete) final line — the signature of a
/// crash mid-append: content with **no trailing newline** — return the
/// intact prefix (up to and including the last newline) plus its verified
/// `(count, head)`. Returns `None` if the file ends cleanly (so any break
/// is real tampering of a complete line) or if the surviving prefix does
/// not itself verify (so the break is not merely in the torn tail). Pure;
/// does no I/O.
fn recover_torn_tail(text: &str) -> Option<(String, u64, String)> {
    if text.ends_with('\n') {
        // The last line was fully written (newline present) → not a torn
        // write; the failure is genuine tampering. Do not recover.
        return None;
    }
    // Drop everything after the last newline (the partial line). With no
    // newline at all, the whole file is one torn line → empty prefix.
    let prefix = match text.rfind('\n') {
        Some(nl) => text[..=nl].to_string(),
        None => String::new(),
    };
    let (count, head) = verify_chain(&prefix).ok()?;
    Some((prefix, count, head))
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

    #[test]
    fn recovers_from_torn_final_line() {
        // A crash mid-`emit` leaves a partial last line with no newline.
        // Re-open must recover (drop the torn tail) and keep appending.
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("audit.log");
        {
            let sink = ChainedFileSink::open(&p).unwrap();
            sink.emit(&ev("a", "w1"));
            sink.emit(&ev("b", "w2"));
        }
        // Simulate a torn append: a partial JSON fragment, no trailing \n.
        let mut text = std::fs::read_to_string(&p).unwrap();
        text.push_str("{\"seq\":2,\"prev_hash\":\"deadbeef\",\"kind\":\"ov");
        std::fs::write(&p, &text).unwrap();

        let sink = ChainedFileSink::open(&p).expect("torn tail should be recoverable");
        // The partial line was truncated; we resume at seq 2.
        sink.emit(&ev("c", "w3"));
        let final_text = std::fs::read_to_string(&p).unwrap();
        let (count, head) = verify_chain(&final_text).unwrap();
        assert_eq!(count, 3, "should have w1,w2,w3 after recovery");
        assert_eq!(head, sink.head());
    }

    #[test]
    fn recovers_single_torn_line_to_empty() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("audit.log");
        // A lone torn first line (crash before the very first newline).
        std::fs::write(&p, "{\"seq\":0,\"prev_ha").unwrap();
        let sink = ChainedFileSink::open(&p).expect("lone torn line recovers to empty");
        sink.emit(&ev("a", "w1"));
        let (count, _) = verify_chain(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn torn_tail_over_tampered_prefix_still_refuses() {
        // A torn tail does NOT excuse tampering of an earlier complete
        // line: the surviving prefix must itself verify, or we refuse.
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("audit.log");
        {
            let sink = ChainedFileSink::open(&p).unwrap();
            sink.emit(&ev("a", "w1"));
            sink.emit(&ev("b", "w2"));
        }
        let mut text = std::fs::read_to_string(&p).unwrap();
        // Tamper a complete prior line AND append a torn tail.
        text = text.replacen("\"x\":\"w1\"", "\"x\":\"evil\"", 1);
        text.push_str("{\"seq\":2,\"prev_ha");
        std::fs::write(&p, &text).unwrap();
        assert!(
            ChainedFileSink::open(&p).is_err(),
            "tampered prefix must still refuse even with a torn tail"
        );
    }

    // ── C6-4: canonical JSON ─────────────────────────────────────

    #[test]
    fn canonical_json_sorts_object_keys() {
        // Keys in reverse alphabetical order must serialize alphabetically.
        let v = serde_json::json!({"z": 3, "a": 1, "m": [{"b": 2, "a": 1}]});
        let out = std::str::from_utf8(&canonical_json(&v))
            .unwrap()
            .to_string();
        assert_eq!(out, r#"{"a":1,"m":[{"a":1,"b":2}],"z":3}"#);
    }

    #[test]
    fn link_hash_is_stable_regardless_of_key_insertion_order() {
        // Even if serde_json's map ordering changed, canonical_json enforces
        // the same sorted serialization so the hash is always identical.
        let d1 = serde_json::json!({"z": 9, "a": 1});
        let d2 = serde_json::json!({"a": 1, "z": 9});
        assert_eq!(
            link_hash("prev", 1_000, "kind", "w1", &d1, 0),
            link_hash("prev", 1_000, "kind", "w1", &d2, 0),
        );
    }

    // ── Merkle anchoring (C6-2/3) ────────────────────────────────

    #[test]
    fn merkle_root_commits_to_every_event() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("audit.log");
        let sink = ChainedFileSink::open(&p).unwrap();
        for id in ["w1", "w2", "w3", "w4", "w5"] {
            sink.emit(&ev("overlay_blocked", id));
        }
        let text = std::fs::read_to_string(&p).unwrap();
        let root = merkle_root_of_log(&text).unwrap();
        assert_eq!(root.len(), 64); // hex SHA-256
        let leaves = log_leaves(&text).unwrap();
        assert_eq!(leaves.len(), 5);
        // Every event has a verifiable inclusion proof against the root.
        for (seq, leaf) in leaves.iter().enumerate() {
            let proof = inclusion_proof_for_seq(&text, seq).unwrap().unwrap();
            assert!(crate::merkle::verify_inclusion(leaf, seq, 5, &proof, &root));
        }
    }

    #[test]
    fn merkle_root_changes_if_an_event_is_altered() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("audit.log");
        let sink = ChainedFileSink::open(&p).unwrap();
        sink.emit(&ev("overlay_blocked", "w1"));
        sink.emit(&ev("overlay_blocked", "w2"));
        let text = std::fs::read_to_string(&p).unwrap();
        let root = merkle_root_of_log(&text).unwrap();

        // A tampered log fails the integrity gate (no root computed) ...
        let tampered = text.replacen("\"x\":\"w2\"", "\"x\":\"evil\"", 1);
        assert!(merkle_root_of_log(&tampered).is_err());

        // ... and an independently re-built log with a different event
        // yields a different root.
        let dir2 = TempDir::new().unwrap();
        let p2 = dir2.path().join("audit.log");
        let sink2 = ChainedFileSink::open(&p2).unwrap();
        sink2.emit(&ev("overlay_blocked", "w1"));
        sink2.emit(&ev("overlay_blocked", "DIFFERENT"));
        let text2 = std::fs::read_to_string(&p2).unwrap();
        assert_ne!(root, merkle_root_of_log(&text2).unwrap());
    }

    #[test]
    fn merkle_root_of_empty_log_is_defined() {
        // An empty (but valid) log has the RFC empty-tree root.
        let root = merkle_root_of_log("").unwrap();
        assert_eq!(
            root,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(inclusion_proof_for_seq("", 0).unwrap().is_none());
    }

    // ── B7/B8: signal firing stats ────────────────────────────────

    fn ev_with_signals(kind: &'static str, id: &str, signals: &[&str]) -> AuditEvent {
        AuditEvent {
            timestamp_ms: 1_000,
            kind,
            window_id: id.into(),
            detail: serde_json::json!({
                "x": id,
                "signals": signals,
            }),
        }
    }

    #[test]
    fn signal_firing_stats_counts_block_and_suspicious() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("audit.log");
        let sink = ChainedFileSink::open(&p).unwrap();
        // Two events share "fullscreen"; one block also has "phone_number".
        sink.emit(&ev_with_signals(
            "overlay_blocked",
            "w1",
            &["fullscreen", "phone_number"],
        ));
        sink.emit(&ev_with_signals(
            "overlay_suspicious",
            "w2",
            &["fullscreen"],
        ));
        sink.emit(&ev_with_signals("overlay_blocked", "w3", &["fullscreen"]));
        let text = std::fs::read_to_string(&p).unwrap();
        let stats = signal_firing_stats(&text).unwrap();
        let fs = &stats["fullscreen"];
        assert_eq!(fs.blocks, 2);
        assert_eq!(fs.suspicious, 1);
        assert_eq!(fs.total(), 3);
        let pn = &stats["phone_number"];
        assert_eq!(pn.blocks, 1);
        assert_eq!(pn.suspicious, 0);
        // Non-detection events (scareware, sweep_error) don't contribute.
        assert!(!stats.contains_key("x"));
    }

    #[test]
    fn signal_firing_stats_empty_log() {
        let stats = signal_firing_stats("").unwrap();
        assert!(stats.is_empty());
    }

    #[test]
    fn signal_firing_stats_tampered_log_errors() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("audit.log");
        let sink = ChainedFileSink::open(&p).unwrap();
        sink.emit(&ev("overlay_blocked", "w1"));
        let text = std::fs::read_to_string(&p).unwrap();
        let tampered = text.replacen("\"x\":\"w1\"", "\"x\":\"evil\"", 1);
        assert!(signal_firing_stats(&tampered).is_err());
    }
}
