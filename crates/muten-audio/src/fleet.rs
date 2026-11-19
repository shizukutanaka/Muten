//! Fleet policy status: the read side of central distribution.
//!
//! The intake ([`crate::distribute`]) records every applied policy in
//! the machine's audit log as `policy_updated`, with the source and
//! the SHA-256 of the applied bytes, and every failed pull as
//! `policy_fetch_failed` / `policy_error`. This module aggregates
//! those records across machines: an administrator collects the
//! `audit.log` files (or excerpts of them) from the fleet — one file
//! per machine, named so the machine is recognisable, e.g.
//! `pc-042.log` — and [`analyze_log`] reduces each one to the last
//! policy it applied, where it came from, when, and the most recent
//! failure. Compared against the master policy's SHA-256, a machine
//! that is behind (or has never taken a distributed policy) stands
//! out immediately.
//!
//! Identification is deliberately limited to what already exists:
//! the log format carries no machine identifier, so a machine is
//! labelled by the file name the administrator gave its collected
//! log. Nothing here collects, phones home, or watches anything —
//! it reads files it is handed, once, and reports.
//!
//! Lines that cannot be read, and lines that are JSON but not a
//! recognisable audit event (a future format, a hand-edited file),
//! are **counted and reported**, never silently dropped: a fleet
//! report that quietly skipped a machine's bad lines would be lying
//! by omission.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::audit::{line_hash, verify_chain, AuditError, EventKind};
use crate::Error;

/// A policy application, as recorded by a `policy_updated` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedPolicy {
    pub ts_unix: i64,
    /// Source label from the event (credentials are stripped by the
    /// intake before recording — see `distribute::sanitize_source_label`).
    pub source: String,
    /// SHA-256 (hex) of the applied policy bytes.
    pub sha256: String,
}

/// A failed policy pull, as recorded by a `policy_fetch_failed` or
/// `policy_error` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFailure {
    pub ts_unix: i64,
    pub kind: EventKind,
    /// The recorded error text (may be empty if the event carried none).
    pub error: String,
}

impl PolicyFailure {
    /// The event kind as it appears in the log (`policy_fetch_failed`, …).
    pub fn kind_name(&self) -> String {
        serde_json::to_value(self.kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "policy_error".to_string())
    }
}

/// The agent's newest lifecycle record: an `agent_started`, or an
/// `agent_stopped` (written when the watchdog exits on an error).
///
/// A start without a later stop is *not* proof the agent is still
/// running — closing its window or powering off writes nothing — but
/// a recorded stop is proof that it is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentLifecycle {
    pub ts_unix: i64,
    pub stopped: bool,
    /// The recorded error text of a stop (empty for a start).
    pub error: String,
}

/// How a log's hash chain held up under inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainCheck {
    /// The full chain verifies from `GENESIS` (see [`verify_chain`]).
    Intact { events: usize },
    /// The text does not start at the chain head (an excerpt, e.g.
    /// the tail forwarded by a scheduled task), but every entry's
    /// hash recomputes and every link matches its predecessor within
    /// the text — nothing inside the excerpt was edited. This says
    /// nothing about entries before the excerpt.
    Excerpt { events: usize },
    /// An entry was edited, a link does not match, or a line cannot
    /// be parsed at all — the chain cannot vouch for this log.
    Broken { line: usize, reason: String },
}

/// One machine's reduced status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineStatus {
    /// The machine's label (the collected log's file stem).
    pub label: String,
    /// Recognisable audit events read from the log.
    pub events: usize,
    /// Lines that were not JSON at all.
    pub unreadable_lines: usize,
    /// Lines that were JSON but not a recognisable audit event
    /// (wrong shape, unknown kind, or a malformed event payload).
    pub unknown_lines: usize,
    pub chain: ChainCheck,
    /// The newest `policy_updated` event, if the log records any.
    pub last_applied: Option<AppliedPolicy>,
    /// The newest distribution failure, if the log records any.
    pub last_failure: Option<PolicyFailure>,
    /// The newest agent start/stop, if the log records any.
    pub last_agent: Option<AgentLifecycle>,
}

/// A machine's standing against the expected (master) policy hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStatus {
    /// The last applied policy is the expected one.
    Current,
    /// The last applied policy is a different one.
    Stale,
    /// The log records no policy application at all.
    NoRecord,
    /// No expected hash was given, so no comparison was made.
    NotChecked,
}

impl MachineStatus {
    pub fn sync_status(&self, expected_sha256: Option<&str>) -> SyncStatus {
        let Some(expected) = expected_sha256 else {
            return SyncStatus::NotChecked;
        };
        match &self.last_applied {
            None => SyncStatus::NoRecord,
            Some(applied) if applied.sha256.eq_ignore_ascii_case(expected) => SyncStatus::Current,
            Some(_) => SyncStatus::Stale,
        }
    }

    /// The log's last lifecycle record says the agent stopped, so
    /// this machine is not enforcing whatever policy it last applied.
    pub fn agent_stopped(&self) -> bool {
        self.last_agent.as_ref().is_some_and(|a| a.stopped)
    }

    /// Lines that were skipped, with their counts — always reported.
    pub fn skipped_lines(&self) -> usize {
        self.unreadable_lines + self.unknown_lines
    }
}

/// One structurally parsed chained line, before kind-specific checks.
struct ParsedLine {
    line_no: usize,
    ts_unix: i64,
    kind: EventKind,
    detail: serde_json::Value,
    prev: String,
    hash: String,
}

enum LineOutcome {
    Event(ParsedLine),
    Unreadable,
    Unknown,
}

/// Parse one non-empty line leniently: JSON first, then the chained
/// line's shape, then the event kind. Anything that fails a step is
/// classified, not dropped.
fn parse_line(line_no: usize, raw: &str) -> LineOutcome {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return LineOutcome::Unreadable;
    };
    let Some(obj) = value.as_object() else {
        return LineOutcome::Unknown;
    };
    let (Some(ts_unix), Some(kind_raw), Some(prev), Some(hash)) = (
        obj.get("ts_unix").and_then(serde_json::Value::as_i64),
        obj.get("kind"),
        obj.get("prev").and_then(serde_json::Value::as_str),
        obj.get("hash").and_then(serde_json::Value::as_str),
    ) else {
        return LineOutcome::Unknown;
    };
    let Ok(kind) = serde_json::from_value::<EventKind>(kind_raw.clone()) else {
        return LineOutcome::Unknown;
    };
    LineOutcome::Event(ParsedLine {
        line_no,
        ts_unix,
        kind,
        detail: obj
            .get("detail")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        prev: prev.to_string(),
        hash: hash.to_string(),
    })
}

/// Check the internal consistency of an excerpt: every entry's hash
/// must recompute from its contents, and every entry after the first
/// must link to its predecessor *within the text*. The first entry's
/// `prev` is taken as given — that is what makes it an excerpt check
/// rather than a full-chain verification.
fn check_excerpt(parsed: &[ParsedLine], first_bad_line: Option<usize>) -> ChainCheck {
    if let Some(line) = first_bad_line {
        return ChainCheck::Broken {
            line,
            reason: "unparseable line: the chain cannot be checked past it".into(),
        };
    }
    let mut prev_hash: Option<&str> = None;
    for line in parsed {
        let expect = line_hash(&line.prev, line.ts_unix, line.kind, &line.detail);
        if expect != line.hash {
            return ChainCheck::Broken {
                line: line.line_no,
                reason: "hash mismatch (entry was edited)".into(),
            };
        }
        if let Some(prev) = prev_hash {
            if line.prev != prev {
                return ChainCheck::Broken {
                    line: line.line_no,
                    reason: "prev hash does not match the previous line".into(),
                };
            }
        }
        prev_hash = Some(&line.hash);
    }
    ChainCheck::Excerpt {
        events: parsed.len(),
    }
}

/// Reduce one machine's audit-log text to its fleet status.
///
/// `label` is the machine's name for the report — the intake format
/// records no machine identity, so the caller supplies the label it
/// collected the log under (see [`machine_label`]).
pub fn analyze_log(label: &str, text: &str) -> MachineStatus {
    let mut events = 0usize;
    let mut unreadable_lines = 0usize;
    let mut unknown_lines = 0usize;
    let mut first_bad_line: Option<usize> = None;
    let mut parsed: Vec<ParsedLine> = Vec::new();
    let mut last_applied: Option<AppliedPolicy> = None;
    let mut last_failure: Option<PolicyFailure> = None;
    let mut last_agent: Option<AgentLifecycle> = None;

    for (i, raw) in text.lines().enumerate() {
        if raw.trim().is_empty() {
            continue;
        }
        let line_no = i + 1;
        let line = match parse_line(line_no, raw) {
            LineOutcome::Event(line) => line,
            LineOutcome::Unreadable => {
                unreadable_lines += 1;
                first_bad_line.get_or_insert(line_no);
                continue;
            }
            LineOutcome::Unknown => {
                unknown_lines += 1;
                first_bad_line.get_or_insert(line_no);
                continue;
            }
        };
        match line.kind {
            EventKind::PolicyUpdated => {
                let (Some(source), Some(sha256)) = (
                    line.detail.get("source").and_then(|v| v.as_str()),
                    line.detail.get("sha256").and_then(|v| v.as_str()),
                ) else {
                    // A policy_updated without the fields the intake
                    // always records is not a recognisable application.
                    unknown_lines += 1;
                    first_bad_line.get_or_insert(line_no);
                    continue;
                };
                let applied = AppliedPolicy {
                    ts_unix: line.ts_unix,
                    source: source.to_string(),
                    sha256: sha256.to_string(),
                };
                if last_applied
                    .as_ref()
                    .map_or(true, |prev| applied.ts_unix >= prev.ts_unix)
                {
                    last_applied = Some(applied);
                }
            }
            EventKind::PolicyFetchFailed | EventKind::PolicyError => {
                let failure = PolicyFailure {
                    ts_unix: line.ts_unix,
                    kind: line.kind,
                    error: line
                        .detail
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                };
                if last_failure
                    .as_ref()
                    .map_or(true, |prev| failure.ts_unix >= prev.ts_unix)
                {
                    last_failure = Some(failure);
                }
            }
            EventKind::AgentStarted | EventKind::AgentStopped => {
                let stopped = line.kind == EventKind::AgentStopped;
                let lifecycle = AgentLifecycle {
                    ts_unix: line.ts_unix,
                    stopped,
                    error: if stopped {
                        line.detail
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string()
                    } else {
                        String::new()
                    },
                };
                if last_agent
                    .as_ref()
                    .map_or(true, |prev| lifecycle.ts_unix >= prev.ts_unix)
                {
                    last_agent = Some(lifecycle);
                }
            }
            _ => {}
        }
        events += 1;
        parsed.push(line);
    }

    // Full-chain verification first (the strong statement); if the
    // text is an excerpt, fall back to internal consistency.
    let chain = match verify_chain(text) {
        Ok(status) => ChainCheck::Intact {
            events: status.events,
        },
        Err(AuditError::Broken { .. }) => {
            // verify_chain stops at the first problem; an excerpt
            // whose head is missing and a genuinely broken link look
            // alike from here, so let the excerpt check decide (it
            // recomputes every hash itself).
            check_excerpt(&parsed, first_bad_line)
        }
        Err(e) => ChainCheck::Broken {
            line: 0,
            reason: e.to_string(),
        },
    };

    MachineStatus {
        label: label.to_string(),
        events,
        unreadable_lines,
        unknown_lines,
        chain,
        last_applied,
        last_failure,
        last_agent,
    }
}

/// The label a collected log is reported under: its file name
/// without the extension (`pc-042.log` → `pc-042`).
pub fn machine_label(path: &Path) -> String {
    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
        if !stem.is_empty() {
            return stem.to_string();
        }
    }
    path.display().to_string()
}

/// Expand the CLI's log inputs into the concrete files to read:
/// a directory contributes its `*.log` files (sorted by name), a
/// file contributes itself. A missing path, or a directory with no
/// logs in it, is an error — never a silently empty report.
pub fn collect_log_paths(inputs: &[PathBuf]) -> Result<Vec<PathBuf>, Error> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut push = |p: PathBuf, out: &mut Vec<PathBuf>| {
        if seen.insert(p.clone()) {
            out.push(p);
        }
    };
    for input in inputs {
        if input.is_dir() {
            let mut logs: Vec<PathBuf> = Vec::new();
            for entry in std::fs::read_dir(input)? {
                let path = entry?.path();
                if path.is_file()
                    && path
                        .extension()
                        .is_some_and(|e| e.eq_ignore_ascii_case("log"))
                {
                    logs.push(path);
                }
            }
            logs.sort();
            if logs.is_empty() {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no .log files in {}", input.display()),
                )));
            }
            for log in logs {
                push(log, &mut out);
            }
        } else if input.is_file() {
            push(input.clone(), &mut out);
        } else {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("log path not found: {}", input.display()),
            )));
        }
    }
    Ok(out)
}

/// Format a Unix timestamp as `YYYY-MM-DD HH:MM:SS` in UTC — the one
/// frame every machine's log shares. Pure arithmetic (the civil
/// conversion is Howard Hinnant's algorithm); no timezone database,
/// matching this crate's approach in [`crate::time`].
pub fn format_unix_utc(ts_unix: i64) -> String {
    let days = ts_unix.div_euclid(86_400);
    let secs = ts_unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The display form of a policy hash: the first 12 hex characters,
/// enough to tell two policies apart at a glance in a table.
pub fn short_hash(sha256: &str) -> &str {
    let end = sha256.len().min(12);
    &sha256[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditLog, Event};

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn applied(ts: i64, sha: &str) -> Event {
        Event {
            ts_unix: ts,
            kind: EventKind::PolicyUpdated,
            detail: serde_json::json!({
                "source": r"\\fileserver\muten\policy.json",
                "sha256": sha,
                "enforce": true,
                "allow_unmute": true,
                "max_unmute_minutes": 30,
                "schedule_windows": 1,
                "pin_set": true,
            }),
        }
    }

    fn failed(ts: i64, kind: EventKind, error: &str) -> Event {
        Event {
            ts_unix: ts,
            kind,
            detail: serde_json::json!({
                "what": "policy_source",
                "source": r"\\fileserver\muten\policy.json",
                "error": error,
            }),
        }
    }

    fn log_text(events: &[Event]) -> String {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        {
            let mut log = AuditLog::open(&path).unwrap();
            for ev in events {
                log.append(ev).unwrap();
            }
        }
        std::fs::read_to_string(&path).unwrap()
    }

    #[test]
    fn last_applied_is_the_newest_policy_updated() {
        let text = log_text(&[
            applied(1_700_000_000, SHA_A),
            Event {
                ts_unix: 1_700_000_100,
                kind: EventKind::Muted,
                detail: serde_json::json!({"reason": "startup"}),
            },
            applied(1_700_000_200, SHA_B),
        ]);
        let st = analyze_log("pc-1", &text);
        let last = st.last_applied.as_ref().unwrap();
        assert_eq!(last.sha256, SHA_B);
        assert_eq!(last.ts_unix, 1_700_000_200);
        assert_eq!(last.source, r"\\fileserver\muten\policy.json");
        assert_eq!(st.events, 3);
        assert_eq!(st.chain, ChainCheck::Intact { events: 3 });
        assert_eq!(st.sync_status(Some(SHA_B)), SyncStatus::Current);
        assert_eq!(st.sync_status(Some(SHA_A)), SyncStatus::Stale);
        assert_eq!(st.sync_status(None), SyncStatus::NotChecked);
    }

    fn lifecycle(ts: i64, kind: EventKind) -> Event {
        Event {
            ts_unix: ts,
            kind,
            detail: if kind == EventKind::AgentStopped {
                serde_json::json!({"reason": "error", "error": "audio backend error: x"})
            } else {
                serde_json::json!({"version": "0.1.0"})
            },
        }
    }

    #[test]
    fn last_agent_is_the_newest_start_or_stop() {
        let text = log_text(&[
            lifecycle(10, EventKind::AgentStarted),
            applied(20, SHA_A),
            lifecycle(30, EventKind::AgentStopped),
        ]);
        let m = analyze_log("pc", &text);
        assert!(m.agent_stopped());
        let a = m.last_agent.unwrap();
        assert_eq!(a.ts_unix, 30);
        assert_eq!(a.error, "audio backend error: x");

        // A restart after the stop clears it.
        let text = log_text(&[
            lifecycle(10, EventKind::AgentStarted),
            lifecycle(30, EventKind::AgentStopped),
            lifecycle(40, EventKind::AgentStarted),
        ]);
        let m = analyze_log("pc", &text);
        assert!(!m.agent_stopped());
        assert_eq!(m.last_agent.unwrap().ts_unix, 40);

        // No lifecycle record at all: unknown, not stopped.
        let m = analyze_log("pc", &log_text(&[applied(20, SHA_A)]));
        assert!(m.last_agent.is_none());
        assert!(!m.agent_stopped());
    }

    #[test]
    fn no_policy_updated_means_no_record() {
        let text = log_text(&[Event {
            ts_unix: 1_700_000_000,
            kind: EventKind::AgentStarted,
            detail: serde_json::json!({}),
        }]);
        let st = analyze_log("pc-2", &text);
        assert!(st.last_applied.is_none());
        assert_eq!(st.sync_status(Some(SHA_A)), SyncStatus::NoRecord);
    }

    #[test]
    fn last_failure_is_the_newest_failure_event() {
        let text = log_text(&[
            applied(1_700_000_000, SHA_A),
            failed(
                1_700_000_100,
                EventKind::PolicyFetchFailed,
                "share unreachable",
            ),
            applied(1_700_000_200, SHA_B),
            failed(1_700_000_300, EventKind::PolicyError, "unknown field"),
        ]);
        let st = analyze_log("pc-3", &text);
        let failure = st.last_failure.as_ref().unwrap();
        assert_eq!(failure.ts_unix, 1_700_000_300);
        assert_eq!(failure.kind, EventKind::PolicyError);
        assert_eq!(failure.kind_name(), "policy_error");
        assert_eq!(failure.error, "unknown field");
        // A successful application after a failure does not erase it:
        // the newest failure is still the newest failure.
        let text2 = log_text(&[
            failed(1_700_000_100, EventKind::PolicyFetchFailed, "down"),
            applied(1_700_000_200, SHA_A),
        ]);
        let st2 = analyze_log("pc-3b", &text2);
        assert_eq!(st2.last_failure.as_ref().unwrap().error, "down");
    }

    #[test]
    fn unreadable_and_unknown_lines_are_counted_not_dropped() {
        let mut text = log_text(&[applied(1_700_000_000, SHA_A)]);
        text.push_str("{not json at all\n");
        // Valid JSON, valid chained shape, but a kind from the future.
        text.push_str(
            "{\"ts_unix\":1700000100,\"kind\":\"policy_teleported\",\"detail\":{},\"prev\":\"x\",\"hash\":\"y\"}\n",
        );
        // Valid JSON, but not a chained line at all.
        text.push_str("{\"hello\":\"world\"}\n");
        let st = analyze_log("pc-4", &text);
        assert_eq!(st.unreadable_lines, 1);
        assert_eq!(st.unknown_lines, 2);
        assert_eq!(st.skipped_lines(), 3);
        // The good event is still read.
        assert_eq!(st.last_applied.as_ref().unwrap().sha256, SHA_A);
        // …but the chain can no longer vouch for the file.
        assert!(
            matches!(st.chain, ChainCheck::Broken { .. }),
            "{:?}",
            st.chain
        );
    }

    #[test]
    fn policy_updated_without_sha256_is_unknown_format() {
        // Hand-crafted line: right shape and kind, but the payload is
        // missing the fields the intake always records.
        let text = "{\"ts_unix\":1700000000,\"kind\":\"policy_updated\",\"detail\":{\"source\":\"x\"},\"prev\":\"GENESIS\",\"hash\":\"00\"}\n";
        let st = analyze_log("pc-5", text);
        assert_eq!(st.unknown_lines, 1);
        assert_eq!(st.events, 0);
        assert!(st.last_applied.is_none());
    }

    #[test]
    fn excerpt_is_consistent_but_not_intact() {
        let text = log_text(&[
            applied(1_700_000_000, SHA_A),
            applied(1_700_000_100, SHA_B),
            failed(1_700_000_200, EventKind::PolicyFetchFailed, "down"),
        ]);
        // Drop the first line: the remaining text no longer anchors
        // at GENESIS, but its internal links still check out.
        let excerpt = text.lines().skip(1).collect::<Vec<_>>().join("\n");
        let st = analyze_log("pc-6", &excerpt);
        assert_eq!(st.chain, ChainCheck::Excerpt { events: 2 });
        assert_eq!(st.last_applied.as_ref().unwrap().sha256, SHA_B);
        assert!(st.last_failure.is_some());
    }

    #[test]
    fn edited_entry_is_broken_not_excerpt() {
        let text = log_text(&[applied(1_700_000_000, SHA_A), applied(1_700_000_100, SHA_B)]);
        let tampered = text.replace("\"enforce\":true", "\"enforce\":false");
        let st = analyze_log("pc-7", &tampered);
        assert!(
            matches!(st.chain, ChainCheck::Broken { line: 1, .. }),
            "{:?}",
            st.chain
        );
    }

    #[test]
    fn empty_log_is_intact_with_no_record() {
        let st = analyze_log("pc-8", "");
        assert_eq!(st.events, 0);
        assert_eq!(st.chain, ChainCheck::Intact { events: 0 });
        assert_eq!(st.sync_status(Some(SHA_A)), SyncStatus::NoRecord);
    }

    #[test]
    fn format_unix_utc_known_values() {
        assert_eq!(format_unix_utc(0), "1970-01-01 00:00:00");
        assert_eq!(format_unix_utc(-1), "1969-12-31 23:59:59");
        // 2026-11-16T00:00:00Z (a Monday).
        assert_eq!(format_unix_utc(1_794_787_200), "2026-11-16 00:00:00");
        assert_eq!(
            format_unix_utc(1_794_787_200 + 8 * 3600 + 12 * 60 + 3),
            "2026-11-16 08:12:03"
        );
        // Leap day: 2024-02-29T12:00:00Z.
        assert_eq!(format_unix_utc(1_709_208_000), "2024-02-29 12:00:00");
    }

    #[test]
    fn machine_label_uses_the_file_stem() {
        assert_eq!(machine_label(Path::new("/collected/pc-042.log")), "pc-042");
        assert_eq!(machine_label(Path::new("audit.log")), "audit");
        assert_eq!(machine_label(Path::new("front-desk")), "front-desk");
    }

    #[test]
    fn collect_log_paths_expands_directories_sorted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b.log"), "").unwrap();
        std::fs::write(dir.path().join("a.log"), "").unwrap();
        std::fs::write(dir.path().join("notes.txt"), "").unwrap();
        let paths = collect_log_paths(&[dir.path().to_path_buf()]).unwrap();
        let names: Vec<String> = paths.iter().map(|p| machine_label(p)).collect();
        assert_eq!(names, ["a", "b"]);

        // A single file passes through, and duplicates collapse.
        let one = dir.path().join("a.log");
        let paths = collect_log_paths(&[one.clone(), one]).unwrap();
        assert_eq!(paths.len(), 1);

        // Missing paths and log-less directories are errors.
        assert!(collect_log_paths(&[dir.path().join("nope.log")]).is_err());
        let empty = tempfile::tempdir().unwrap();
        assert!(collect_log_paths(&[empty.path().to_path_buf()]).is_err());
    }

    #[test]
    fn short_hash_truncates_for_display() {
        assert_eq!(short_hash(SHA_A), "aaaaaaaaaaaa");
        assert_eq!(short_hash("abc"), "abc");
    }
}
