//! The overlay monitor: the daemon-side loop that ties everything
//! together. Each tick it asks the [`OverlayController`] for the
//! windows on screen, classifies them, dismisses confirmed scams,
//! folds scareware repeat-detection in, and emits one audit event per
//! notable outcome.
//!
//! ## Self-contained audit sink
//!
//! In the full muten workspace these events flow into `muten-events`
//! and the `muten-audit-chain` SHA-256 chain. To keep this crate
//! independently buildable and testable, the monitor depends only on
//! a tiny [`AuditSink`] trait. The daemon wires the real chained sink;
//! tests use [`MemorySink`]. This is the same "depend on a trait, not
//! a concrete IO type" rule the rest of muten follows.
//!
//! ## What gets audited
//!
//! - `OverlayBlocked` — a window scored Block and we asked the
//!   controller to dismiss it (with whether it actually went away).
//! - `OverlaySuspicious` — a window scored Suspicious; recorded for IT
//!   review, never dismissed.
//! - `ScarewareDetected` — the repeat-tracker + process check flagged
//!   installed rogue AV.
//! - `OverlaySweepError` — the controller failed (transient WM hiccup);
//!   the loop logs and continues rather than crashing.
//!
//! `Allow` outcomes are intentionally *not* audited: a quiet log is a
//! useful log, and recording every benign window would bury the
//! signal.

use crate::{
    assess, classify, signature, Decision, OverlayController, RepeatTracker, Ruleset,
    ScarewareDecision,
};
use serde::Serialize;

/// One audit record the monitor emits. `kind` is a stable snake_case
/// string so a downstream SIEM mapping (and the real hash-chain sink)
/// can key off it without matching on the enum's memory layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    /// Logical event time in milliseconds (the sweep's `now_ms`). Using
    /// the injected clock — not `SystemTime::now()` buried in the sink —
    /// keeps the whole pipeline deterministic and testable, and lets the
    /// daemon supply wall-clock time in production. Required for
    /// incident-timeline reconstruction (see IMPROVEMENT_ROADMAP C6-7).
    pub timestamp_ms: u64,
    /// Event type identifier (e.g. `"overlay_blocked"`, `"scareware_detected"`).
    pub kind: &'static str,
    /// Controller's window handle, or `"n/a"` when there's no specific window.
    pub window_id: String,
    /// Event-specific payload (title, score, signals, …) as a JSON object.
    pub detail: serde_json::Value,
}

/// Where audit events go. The daemon implements this over the real
/// chained JSONL sink; tests use [`MemorySink`].
pub trait AuditSink {
    /// Record one audit event. Implementations MUST NOT block or panic.
    fn emit(&self, ev: &AuditEvent);
}

/// In-memory sink for tests and dry runs.
#[derive(Default)]
pub struct MemorySink {
    events: std::sync::Mutex<Vec<AuditEvent>>,
}

impl MemorySink {
    /// Create an empty in-memory sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Snapshot all events recorded so far, in emission order.
    #[must_use]
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().unwrap().clone()
    }
    /// Count events with a given `kind` string.
    #[must_use]
    pub fn count_of(&self, kind: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.kind == kind)
            .count()
    }
}

impl AuditSink for MemorySink {
    fn emit(&self, ev: &AuditEvent) {
        self.events.lock().unwrap().push(ev.clone());
    }
}

/// Drives overlay enforcement over time. Holds the repeat-tracker
/// state across sweeps so scareware floods are detected.
pub struct Monitor {
    rules: Ruleset,
    tracker: RepeatTracker,
    /// Signatures ([`signature`]) seen in the *immediately prior* sweep,
    /// so [`Self::sweep`] can tell a genuine new appearance (the window
    /// was gone last sweep, now it's back — a real re-pop) from mere
    /// continued presence (the same static window, still on screen).
    /// Replaced wholesale each sweep, so its size is bounded by however
    /// many windows are on screen at once — no unbounded growth over a
    /// long-running daemon.
    present_last_sweep: std::collections::HashSet<crate::scareware::Signature>,
    /// First sweep timestamp at which each window id was observed, for
    /// inferring `age_ms` when the helper reports `0` ("unknown" — see
    /// [`crate::OverlayWindow::age_ms`]'s documented contract). Real OS
    /// helpers on all four platforms currently always report `age_ms:
    /// 0`, which means the `very_new` (+10) signal and the
    /// `sudden_fullscreen_takeover` composite (both gated on `age_ms > 0
    /// && age_ms < 1000`) never fire on a real host (audit DR-2). Pruned
    /// each sweep to just the currently-present ids, so memory is
    /// bounded by on-screen window count, not uptime.
    first_seen_ms: std::collections::HashMap<crate::WindowId, u64>,
    /// `true` once at least one sweep has completed. Used to identify the
    /// daemon's very first sweep, whose windows seed
    /// `untrusted_from_startup` below.
    has_swept_before: bool,
    /// Window ids present during the daemon's very *first* sweep. Such a
    /// window might have been open for hours before the daemon started —
    /// we have no way to know — so its inferred age must never be trusted
    /// (which would make it look `very_new` for one brief window right
    /// after daemon startup, a false positive) for as long as it stays
    /// continuously present. The moment a startup-cohort window is ever
    /// absent from a sweep, it's dropped from this set (see the pruning
    /// at the end of [`Self::sweep`]); a later reappearance is a genuine,
    /// freshly-observed appearance and gets a trustworthy inferred age
    /// like any other window.
    untrusted_from_startup: std::collections::HashSet<crate::WindowId>,
}

impl Monitor {
    /// Create a monitor with the default 2-minute repeat-flood window.
    #[must_use]
    pub fn new(rules: Ruleset) -> Self {
        Self {
            rules,
            tracker: RepeatTracker::default(),
            present_last_sweep: std::collections::HashSet::new(),
            first_seen_ms: std::collections::HashMap::new(),
            has_swept_before: false,
            untrusted_from_startup: std::collections::HashSet::new(),
        }
    }

    /// Construct with a custom repeat window.
    #[must_use]
    pub fn with_tracker(rules: Ruleset, tracker: RepeatTracker) -> Self {
        Self {
            rules,
            tracker,
            present_last_sweep: std::collections::HashSet::new(),
            first_seen_ms: std::collections::HashMap::new(),
            has_swept_before: false,
            untrusted_from_startup: std::collections::HashSet::new(),
        }
    }

    /// Run a single sweep at logical time `now_ms`. Enumerates,
    /// classifies, dismisses Block windows, folds in scareware
    /// detection, and emits audit events. Returns a [`SweepOutcome`]
    /// with the dismissed-window count and the detection count
    /// (Block + Suspicious events that fired).
    ///
    /// Process attribution for the rogue-AV check prefers the
    /// [`EnumeratedWindow::process`] field the helper reported with the
    /// window itself (atomic with the enumeration snapshot); `process_of`
    /// maps a window id to the owning process name as a *fallback* for
    /// controllers/hosts that attribute processes out-of-band. Return
    /// `None` when unknown.
    pub fn sweep<F>(
        &mut self,
        controller: &dyn OverlayController,
        sink: &dyn AuditSink,
        now_ms: u64,
        process_of: F,
    ) -> SweepOutcome
    where
        F: Fn(&str) -> Option<String>,
    {
        let windows = match controller.enumerate() {
            Ok(w) => w,
            Err(e) => {
                sink.emit(&AuditEvent {
                    timestamp_ms: now_ms,
                    kind: "overlay_sweep_error",
                    window_id: String::new(),
                    detail: serde_json::json!({ "error": e.to_string() }),
                });
                return SweepOutcome::default();
            }
        };

        let mut dismissed_count = 0u32;
        let mut detection_count = 0u32;
        let mut present_this_sweep = std::collections::HashSet::with_capacity(windows.len());
        let mut ids_this_sweep = std::collections::HashSet::with_capacity(windows.len());
        // Skip inference entirely on the daemon's very first sweep — see
        // `has_swept_before`'s doc comment for why.
        let was_first_sweep = !self.has_swept_before;
        for ew in &windows {
            ids_this_sweep.insert(ew.id.clone());

            // Record first-seen time unconditionally (including on the
            // very first sweep) so a window's age can be inferred once it
            // becomes trustworthy to do so (see `untrusted_from_startup`).
            let first_seen = *self.first_seen_ms.entry(ew.id.clone()).or_insert(now_ms);
            if was_first_sweep {
                self.untrusted_from_startup.insert(ew.id.clone());
            }
            let trusted = !self.untrusted_from_startup.contains(&ew.id);

            // Infer age_ms when the helper couldn't determine it (reports
            // 0 = "unknown") and the inference is trustworthy. A window
            // whose id we haven't seen before is a genuinely new
            // appearance since the daemon started watching, so `now_ms -
            // first_seen_ms` is a real age; a startup-cohort window's true
            // age is unknowable until it's been seen absent at least once.
            let effective_window = if ew.window.age_ms == 0 && trusted {
                let inferred = now_ms.saturating_sub(first_seen);
                if inferred == ew.window.age_ms {
                    None // still 0 this sweep (just-inserted) — no override needed
                } else {
                    Some(crate::OverlayWindow {
                        age_ms: inferred,
                        ..ew.window.clone()
                    })
                }
            } else {
                None
            };
            let window_for_classify = effective_window.as_ref().unwrap_or(&ew.window);
            let verdict = classify(window_for_classify, &self.rules);

            // Scareware: a rogue-AV *process* match fires regardless of
            // origin, but the repeated-*flood* signal must only count
            // genuine NEW appearances — a window that re-pops after being
            // gone (real rogue-AV flood behavior), not a window that is
            // merely still on screen from the previous sweep. Without this
            // distinction, ANY long-lived window (a real one left open for
            // multiple sweeps) would cross REPEAT_THRESHOLD after a few
            // sweeps and fire scareware_detected forever — this was a
            // real, reproduced false positive (docs/FEATURE_AUDIT_2026H2.md
            // DR-11): `signature()` is content-only (title|host), so the
            // same static window yields the same signature every sweep,
            // and every real OS helper reports `Origin::Unknown` (never
            // `UserInitiated`), so the pre-existing UserInitiated carve-out
            // never actually applied on a real host.
            //
            // `present_last_sweep` is the previous sweep's signature set;
            // a signature already in it means "still here," not "just
            // appeared," so we only probe (`count`) rather than record.
            // The `UserInitiated` carve-out is preserved as an additional,
            // independent reason to probe-only (e.g. a user's own window
            // that just so happens to share a signature with a scam
            // template on its very first sweep).
            let sig = signature(&ew.window);
            let seen_last_sweep = self.present_last_sweep.contains(&sig);
            let repeats = if ew.window.origin == crate::Origin::UserInitiated || seen_last_sweep {
                // Probe the existing count without adding to it, so a
                // genuine unsolicited flood already in progress isn't
                // masked by an interleaved user window with the same
                // (unlikely) signature.
                self.tracker.count(&sig, now_ms)
            } else {
                self.tracker.record(&sig, now_ms)
            };
            present_this_sweep.insert(sig.clone());
            let proc = ew.process.clone().or_else(|| process_of(&ew.id));
            let sw = assess(repeats, proc.as_deref(), &self.rules);
            if sw.decision == ScarewareDecision::Scareware {
                let sw_categories: Vec<&'static str> =
                    crate::categories::categories_of(&sw.signals)
                        .iter()
                        .map(|c| c.as_str())
                        .collect();
                sink.emit(&AuditEvent {
                    timestamp_ms: now_ms,
                    kind: "scareware_detected",
                    window_id: ew.id.clone(),
                    detail: serde_json::json!({
                        "repeat_count": sw.repeat_count,
                        "signals": sw.signals,
                        "categories": sw_categories,
                        "matched_process": sw.matched_process,
                        "signature": sig,
                    }),
                });
            }

            // Dark-pattern strategy categories for the audit log.
            let categories: Vec<&'static str> =
                verdict.categories.iter().map(|c| c.as_str()).collect();

            match verdict.decision {
                Decision::Block => {
                    detection_count += 1;
                    let dismissed = controller.dismiss(&ew.id).unwrap_or(false);
                    if dismissed {
                        dismissed_count += 1;
                    }
                    sink.emit(&AuditEvent {
                        timestamp_ms: now_ms,
                        kind: "overlay_blocked",
                        window_id: ew.id.clone(),
                        detail: serde_json::json!({
                            "score": verdict.score,
                            "signals": verdict.signals,
                            "categories": categories,
                            "matched_rule": verdict.matched_rule,
                            "dismissed": dismissed,
                        }),
                    });
                }
                Decision::Suspicious => {
                    detection_count += 1;
                    sink.emit(&AuditEvent {
                        timestamp_ms: now_ms,
                        kind: "overlay_suspicious",
                        window_id: ew.id.clone(),
                        detail: serde_json::json!({
                            "score": verdict.score,
                            "signals": verdict.signals,
                            "categories": categories,
                        }),
                    });
                }
                Decision::Allow => { /* quiet log: benign windows not audited */ }
            }
        }

        // Keep tracker memory bounded over long uptimes.
        self.tracker.prune(now_ms);
        // Replace wholesale: only this sweep's presence matters for
        // classifying *next* sweep's appearances as new-vs-continuing.
        self.present_last_sweep = present_this_sweep;
        // Drop first-seen timestamps for ids no longer present — bounds
        // memory, and correctly restarts age inference from zero if the
        // OS ever reuses the same id for an unrelated later window.
        self.first_seen_ms
            .retain(|id, _| ids_this_sweep.contains(id));
        // A startup-cohort window absent this sweep loses its "untrusted"
        // status permanently — if it reappears later, that's a genuine
        // fresh appearance and its inferred age becomes trustworthy.
        self.untrusted_from_startup
            .retain(|id| ids_this_sweep.contains(id));
        self.has_swept_before = true;
        SweepOutcome {
            dismissed: dismissed_count,
            detections: detection_count,
        }
    }

    /// Run periodic sweeps until `cfg.max_sweeps` is reached (or
    /// forever if `None`). Logical time and process attribution are
    /// injected so tests run without real sleeps or a real desktop.
    ///
    /// Returns the total number of windows dismissed across all sweeps.
    /// The `should_stop` closure lets the daemon request a graceful
    /// exit between sweeps without a signal handler (keeps the crate
    /// `forbid(unsafe_code)`, same trick as the audio daemon's
    /// file-based stop flag).
    pub fn run<C, P, S>(
        &mut self,
        controller: &dyn OverlayController,
        sink: &dyn AuditSink,
        cfg: &RunConfig,
        clock_ms: C,
        process_of: P,
        should_stop: S,
    ) -> u64
    where
        C: Fn() -> u64,
        P: Fn(&str) -> Option<String> + Copy,
        S: Fn() -> bool,
    {
        let mut total_dismissed = 0u64;
        let mut sweeps = 0u64;
        loop {
            if should_stop() {
                break;
            }
            if let Some(max) = cfg.max_sweeps {
                if sweeps >= max {
                    break;
                }
            }
            let now = clock_ms();
            let outcome = self.sweep(controller, sink, now, process_of);
            total_dismissed += u64::from(outcome.dismissed);
            sweeps += 1;
            // Skip the sleep on the final bounded iteration so tests
            // (and clean shutdowns) don't wait needlessly.
            let last = cfg.max_sweeps.map(|m| sweeps >= m).unwrap_or(false);
            if !last {
                // Adaptive interval: shorten sleep after a detection sweep so
                // the monitor reacts faster when malware is actively re-spawning.
                let sleep_ms = if outcome.detections > 0 {
                    cfg.alert_interval_ms.unwrap_or(cfg.interval_ms)
                } else {
                    cfg.interval_ms
                };
                if sleep_ms > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
                }
            }
        }
        total_dismissed
    }
}

/// Per-sweep outcome: dismissed-window count + detection count.
///
/// Returned by [`Monitor::sweep`] so callers can tell whether any
/// Block or Suspicious verdict fired — useful for adaptive sleep logic
/// and for wiring sweep results into dashboards without re-parsing the
/// audit log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepOutcome {
    /// Number of windows the controller successfully dismissed this sweep.
    pub dismissed: u32,
    /// Number of Block + Suspicious verdicts that fired this sweep
    /// (includes windows the controller failed to dismiss).  Useful
    /// for determining whether to shorten the next sleep interval.
    pub detections: u32,
}

/// Knobs for [`Monitor::run`]. Bundled into a struct so the loop call
/// stays readable (and under clippy's argument-count limit).
#[derive(Debug, Clone, Copy)]
pub struct RunConfig {
    /// Gap between sweeps in milliseconds. 0 = no sleep (tests).
    pub interval_ms: u64,
    /// Shortened sleep interval when the previous sweep had ≥1 detection
    /// (Block or Suspicious). `None` disables adaptive shortening.
    /// Typical value: `interval_ms / 5` or a fixed 200 ms.  The normal
    /// `interval_ms` resumes once a clean (zero-detection) sweep completes.
    pub alert_interval_ms: Option<u64>,
    /// Stop after this many sweeps; `None` = run until `should_stop`.
    pub max_sweeps: Option<u64>,
}

impl Default for RunConfig {
    fn default() -> Self {
        // 1-second sweeps, unbounded — sensible production default.
        Self {
            interval_ms: 1_000,
            alert_interval_ms: None,
            max_sweeps: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EnumeratedWindow, NullController, Origin, OverlayWindow};

    fn scam() -> OverlayWindow {
        OverlayWindow {
            title: "your computer is infected - call support".into(),
            url: Some("http://win-prize-now.example/x".into()),
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 200,
        }
    }

    fn benign() -> OverlayWindow {
        OverlayWindow {
            title: "report.pdf".into(),
            url: None,
            coverage_percent: 30,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        }
    }

    fn no_proc(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn sweep_blocks_and_audits_scam() {
        let rules = Ruleset::from_lines(&["host: win-prize-now.example"]);
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            process: None,
            id: "scam".into(),
            window: scam(),
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(rules);
        let outcome = mon.sweep(&ctrl, &sink, 1_000, no_proc);
        assert_eq!(outcome.dismissed, 1);
        assert_eq!(outcome.detections, 1);
        assert_eq!(sink.count_of("overlay_blocked"), 1);
        assert_eq!(ctrl.dismissed(), vec!["scam".to_string()]);
    }

    #[test]
    fn sweep_does_not_audit_benign() {
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            process: None,
            id: "ok".into(),
            window: benign(),
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        let outcome = mon.sweep(&ctrl, &sink, 1_000, no_proc);
        assert_eq!(outcome.dismissed, 0);
        assert_eq!(outcome.detections, 0);
        assert!(
            sink.events().is_empty(),
            "benign windows must not be audited"
        );
    }

    #[test]
    fn repeated_scam_triggers_scareware_event() {
        // Genuine re-pop flood: the window appears, disappears, appears
        // again — not merely "the same static window left open" (that
        // presence-only case is the DR-11 false positive this monitor
        // must NOT flag; see present_last_sweep in `sweep`). Real rogue-AV
        // floods pop the alert, and it comes back after being dismissed
        // or briefly closed, which is what this models.
        let rules = Ruleset::default();
        let window = EnumeratedWindow {
            process: None,
            id: "flood".into(),
            window: OverlayWindow {
                // Suspicious-but-not-block so we isolate the scareware path.
                title: "special offer".into(),
                url: None,
                coverage_percent: 0,
                topmost: false,
                has_close_button: false,
                blocks_input: false,
                origin: Origin::Unsolicited,
                age_ms: 1_000,
            },
        };
        let ctrl_present = NullController::with_windows(vec![window]);
        let ctrl_gone = NullController::new();
        let sink = MemorySink::new();
        let mut mon = Monitor::new(rules);
        // appear, gone, appear, gone, appear — 3 genuine appearances.
        mon.sweep(&ctrl_present, &sink, 1_000, no_proc);
        mon.sweep(&ctrl_gone, &sink, 1_500, no_proc);
        mon.sweep(&ctrl_present, &sink, 2_000, no_proc);
        mon.sweep(&ctrl_gone, &sink, 2_500, no_proc);
        mon.sweep(&ctrl_present, &sink, 3_000, no_proc);
        assert!(
            sink.count_of("scareware_detected") >= 1,
            "3 genuine re-pop appearances should trigger scareware_detected; events={:?}",
            sink.events()
        );
    }

    #[test]
    fn rogue_av_process_triggers_scareware_first_sweep() {
        let rules = Ruleset::from_lines(&["process: pc protector plus"]);
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            process: None,
            id: "win42".into(),
            window: benign(), // even a benign-looking window
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(rules);
        mon.sweep(&ctrl, &sink, 1_000, |_id| {
            Some("PCProtectorPlus.exe".into())
        });
        assert_eq!(sink.count_of("scareware_detected"), 1);
    }

    /// The production path (DR-1): the helper reports the owning process
    /// IN the enumerate payload (`EnumeratedWindow.process`), and the
    /// daemon passes only the `None` fallback callback — the embedded
    /// value alone must drive `rogue_av_process` / `scareware_detected`.
    #[test]
    fn embedded_process_field_triggers_scareware_without_callback() {
        let rules = Ruleset::from_lines(&["process: pc protector plus"]);
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            process: Some("PCProtectorPlus.exe".into()),
            id: "win42".into(),
            window: benign(),
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(rules);
        mon.sweep(&ctrl, &sink, 1_000, no_proc); // daemon-mode fallback: always None
        assert_eq!(
            sink.count_of("scareware_detected"),
            1,
            "the helper-embedded process name alone must trigger the rogue-AV path"
        );
        let ev = &sink.events()[0];
        assert_eq!(ev.detail["matched_process"], "pc protector plus");
        assert!(ev.detail["signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "rogue_av_process"));
    }

    /// When both are present, the embedded (enumeration-atomic) value wins
    /// over the out-of-band callback — pinned so a future refactor doesn't
    /// silently invert the precedence.
    #[test]
    fn embedded_process_takes_precedence_over_callback() {
        // The embedded name matches a rule; the callback returns a
        // non-matching name. If precedence inverted, no event would fire.
        let rules = Ruleset::from_lines(&["process: pc protector plus"]);
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            process: Some("PCProtectorPlus.exe".into()),
            id: "win42".into(),
            window: benign(),
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(rules);
        mon.sweep(&ctrl, &sink, 1_000, |_id| Some("innocent-editor".into()));
        assert_eq!(sink.count_of("scareware_detected"), 1);
    }

    #[test]
    fn user_initiated_window_not_flagged_as_flood() {
        // A user-opened video kept on screen across many sweeps must
        // NOT trip the repeated_flood signal — a false positive seen in
        // the CLI smoke test. Rogue-AV floods are by definition
        // unsolicited; user-initiated repeats are benign.
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            process: None,
            id: "video".into(),
            window: OverlayWindow {
                title: "holiday.mp4 - vlc".into(),
                url: None,
                coverage_percent: 100,
                topmost: true,
                has_close_button: true,
                blocks_input: false,
                origin: Origin::UserInitiated,
                age_ms: 8_000,
            },
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        for ms in [1_000, 2_000, 3_000, 4_000, 5_000] {
            mon.sweep(&ctrl, &sink, ms, no_proc);
        }
        assert_eq!(
            sink.count_of("scareware_detected"),
            0,
            "user-initiated window must never be a flood; events={:?}",
            sink.events()
        );
    }

    #[test]
    fn unsolicited_repeats_still_flood() {
        // The fix must not break detection of genuine floods: appear,
        // gone, appear, gone, appear — real re-pop behavior, not mere
        // continued presence (see present_last_sweep in `sweep`).
        let window = EnumeratedWindow {
            process: None,
            id: "flood".into(),
            window: OverlayWindow {
                title: "critical error".into(),
                url: None,
                coverage_percent: 50,
                topmost: true,
                has_close_button: false,
                blocks_input: false,
                origin: Origin::Unsolicited,
                age_ms: 500,
            },
        };
        let ctrl_present = NullController::with_windows(vec![window]);
        let ctrl_gone = NullController::new();
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        for ms in [1_000, 1_500, 2_000, 2_500, 3_000] {
            let ctrl: &dyn OverlayController = if ms % 1_000 == 0 {
                &ctrl_present
            } else {
                &ctrl_gone
            };
            mon.sweep(ctrl, &sink, ms, no_proc);
        }
        assert!(sink.count_of("scareware_detected") >= 1);
    }

    /// Direct regression test for DR-11: a long-lived, perfectly benign
    /// window that never disappears must NOT accumulate repeat-flood
    /// hits just for existing across sweeps. Before the fix, this fired
    /// scareware_detected from the 3rd sweep onward, forever.
    #[test]
    fn long_lived_benign_window_does_not_trigger_repeated_flood() {
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            process: None,
            id: "steady".into(),
            window: OverlayWindow {
                title: "my ordinary app".into(),
                url: None,
                coverage_percent: 20,
                topmost: false,
                has_close_button: true,
                blocks_input: false,
                // Every real OS helper reports Unknown, never
                // UserInitiated — this is deliberately NOT UserInitiated
                // so the test exercises the presence-tracking fix itself,
                // not the pre-existing (real-host-inapplicable) carve-out.
                origin: Origin::Unknown,
                age_ms: 0,
            },
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        for ms in [1_000, 2_000, 3_000, 4_000, 5_000] {
            mon.sweep(&ctrl, &sink, ms, no_proc);
        }
        assert_eq!(
            sink.count_of("scareware_detected"),
            0,
            "a static, ever-present benign window must never be flagged as a repeat flood; events={:?}",
            sink.events()
        );
    }

    /// Companion to the above: a window that genuinely re-pops (appears,
    /// disappears, appears again) across a sequence including gaps must
    /// still be detected — proving the fix distinguishes presence from
    /// appearance rather than just suppressing the signal outright.
    #[test]
    fn genuine_repop_flood_still_detected_across_gaps() {
        let window = EnumeratedWindow {
            process: None,
            id: "repop".into(),
            window: OverlayWindow {
                title: "you have won a prize".into(),
                url: None,
                coverage_percent: 90,
                topmost: true,
                has_close_button: false,
                blocks_input: true,
                origin: Origin::Unknown,
                age_ms: 0,
            },
        };
        let ctrl_present = NullController::with_windows(vec![window]);
        let ctrl_gone = NullController::new();
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        // present, gone, present, gone, present: 3 genuine appearances.
        mon.sweep(&ctrl_present, &sink, 1_000, no_proc);
        mon.sweep(&ctrl_gone, &sink, 2_000, no_proc);
        mon.sweep(&ctrl_present, &sink, 3_000, no_proc);
        mon.sweep(&ctrl_gone, &sink, 4_000, no_proc);
        mon.sweep(&ctrl_present, &sink, 5_000, no_proc);
        assert!(
            sink.count_of("scareware_detected") >= 1,
            "a genuinely re-popping window must still be detected as a flood; events={:?}",
            sink.events()
        );
    }

    #[test]
    fn user_initiated_window_with_rogue_process_still_flagged() {
        // Origin gates the *flood* signal, not the *process* signal.
        let rules = Ruleset::from_lines(&["process: advanced mac cleaner"]);
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            process: None,
            id: "w".into(),
            window: OverlayWindow {
                origin: Origin::UserInitiated,
                ..benign()
            },
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(rules);
        mon.sweep(&ctrl, &sink, 1_000, |_| Some("AdvancedMacCleaner".into()));
        assert_eq!(sink.count_of("scareware_detected"), 1);
    }

    /// A window scoring exactly `SUSPICIOUS_THRESHOLD - W_VERY_NEW` (i.e.
    /// `Decision::Allow` without `very_new`, `Decision::Suspicious` with
    /// it) so the `very_new` signal's effect on the decision is directly
    /// observable through the audit sink (`Allow` windows are never
    /// audited, so we can't inspect their signals directly).
    fn borderline_window(age_ms: u64) -> OverlayWindow {
        OverlayWindow {
            title: "quarterly report viewer".into(),
            url: None,
            coverage_percent: 0,
            topmost: true, // +15
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unsolicited, // +25 => 40, below the 50 threshold
            age_ms,
        }
    }

    /// DR-2 (age_ms inference): a window present since the daemon's very
    /// first sweep might have been open for hours before the daemon
    /// started, so its true age is unknowable. Even though it never
    /// disappears across many closely-spaced sweeps (which, for a
    /// genuinely new window, would make the inferred age small enough to
    /// trip `very_new`), it must never be trusted enough to get an
    /// inferred age at all — else a benign long-running app would
    /// spuriously look `very_new` right after the daemon starts.
    #[test]
    fn startup_cohort_window_never_gets_inferred_age_while_continuously_present() {
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            process: None,
            id: "steady".into(),
            window: borderline_window(0), // helper reports "unknown"
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        // Closely spaced sweeps: if this window's age were (wrongly)
        // inferred, every one after the first would compute an age well
        // under 1000ms and trip `very_new`.
        for ms in [1_000, 1_200, 1_400, 1_600, 1_800, 2_000] {
            mon.sweep(&ctrl, &sink, ms, no_proc);
        }
        assert_eq!(
            sink.count_of("overlay_suspicious"),
            0,
            "a window present since the daemon's first sweep must never be treated as very_new; events={:?}",
            sink.events()
        );
    }

    /// Companion: a window that genuinely first appears *after* the
    /// daemon has already completed at least one sweep gets a
    /// trustworthy inferred age, and `very_new` correctly fires while
    /// that inferred age is still under 1s.
    #[test]
    fn window_appearing_after_first_sweep_gets_trusted_inferred_age() {
        let ctrl_empty = NullController::new();
        let ctrl_present = NullController::with_windows(vec![EnumeratedWindow {
            process: None,
            id: "fresh".into(),
            window: borderline_window(0),
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        mon.sweep(&ctrl_empty, &sink, 1_000, no_proc); // sweep 1: nothing present
        mon.sweep(&ctrl_present, &sink, 2_000, no_proc); // sweep 2: genuinely new appearance, inferred age 0
        assert_eq!(
            sink.count_of("overlay_suspicious"),
            0,
            "a freshly-appeared window's first sweep must not yet be very_new (inferred age 0)"
        );
        mon.sweep(&ctrl_present, &sink, 2_500, no_proc); // sweep 3: inferred age 500ms < 1000ms
        assert_eq!(
            sink.count_of("overlay_suspicious"),
            1,
            "a window seen for the first time mid-run should get a trustworthy inferred age and trip very_new while under 1s old; events={:?}",
            sink.events()
        );
    }

    /// A startup-cohort window that is ever absent for even one sweep
    /// loses its "untrusted" status permanently: a later reappearance is
    /// legitimately fresh information (the OS could easily have reused
    /// the id for an unrelated window), so it should be treated exactly
    /// like any other genuinely-new appearance from that point on.
    #[test]
    fn startup_cohort_window_becomes_trusted_again_after_disappearing_and_reappearing() {
        let ctrl_empty = NullController::new();
        let ctrl_present = NullController::with_windows(vec![EnumeratedWindow {
            process: None,
            id: "steady".into(),
            window: borderline_window(0),
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        mon.sweep(&ctrl_present, &sink, 1_000, no_proc); // sweep 1: startup cohort, untrusted
        mon.sweep(&ctrl_empty, &sink, 1_500, no_proc); // sweep 2: gone — untrusted status cleared
        mon.sweep(&ctrl_present, &sink, 2_000, no_proc); // sweep 3: reappears, treated as new (inferred age 0)
        assert_eq!(
            sink.count_of("overlay_suspicious"),
            0,
            "the reappearance sweep itself must not yet be very_new (inferred age 0)"
        );
        mon.sweep(&ctrl_present, &sink, 2_500, no_proc); // sweep 4: inferred age 500ms < 1000ms — now trusted
        assert_eq!(
            sink.count_of("overlay_suspicious"),
            1,
            "after disappearing once, the window's reappearance should be trusted and trip very_new; events={:?}",
            sink.events()
        );
    }

    #[test]
    fn enumerate_error_emits_sweep_error_and_does_not_panic() {
        struct Failing;
        impl OverlayController for Failing {
            fn name(&self) -> &'static str {
                "failing"
            }
            fn available(&self) -> bool {
                true
            }
            fn enumerate(&self) -> Result<Vec<EnumeratedWindow>, crate::ControllerError> {
                Err(crate::ControllerError::Enumerate("boom".into()))
            }
            fn dismiss(&self, _: &crate::WindowId) -> Result<bool, crate::ControllerError> {
                Ok(false)
            }
        }
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        let outcome = mon.sweep(&Failing, &sink, 1_000, no_proc);
        assert_eq!(outcome.dismissed, 0);
        assert_eq!(outcome.detections, 0);
        assert_eq!(sink.count_of("overlay_sweep_error"), 1);
    }

    #[test]
    fn suspicious_window_audited_not_dismissed() {
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            process: None,
            id: "s".into(),
            window: OverlayWindow {
                title: "newsletter".into(),
                url: None,
                coverage_percent: 0,
                topmost: false,
                has_close_button: false, // +25
                blocks_input: false,
                origin: Origin::Unsolicited, // +25 => 50 = Suspicious
                age_ms: 5_000,
            },
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        let outcome = mon.sweep(&ctrl, &sink, 1_000, no_proc);
        assert_eq!(outcome.dismissed, 0);
        assert_eq!(outcome.detections, 1); // suspicious is a detection
        assert_eq!(sink.count_of("overlay_suspicious"), 1);
        assert!(ctrl.dismissed().is_empty());
    }

    #[test]
    fn run_bounded_sweeps_executes_exactly_max() {
        let rules = Ruleset::from_lines(&["host: win-prize-now.example"]);
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            process: None,
            id: "scam".into(),
            window: scam(),
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(rules);
        // Logical clock advancing 1s per call.
        let t = std::cell::Cell::new(0u64);
        let clock = || {
            let v = t.get();
            t.set(v + 1_000);
            v
        };
        let total = mon.run(
            &ctrl,
            &sink,
            &RunConfig {
                interval_ms: 0,
                max_sweeps: Some(3),
                ..Default::default()
            },
            clock,
            no_proc,
            || false,
        );
        // Scam blocked each sweep → 3 dismiss attempts.
        assert_eq!(total, 3);
        assert_eq!(sink.count_of("overlay_blocked"), 3);
    }

    #[test]
    fn run_stops_when_flag_set() {
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            process: None,
            id: "ok".into(),
            window: benign(),
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        // should_stop returns true immediately → zero sweeps.
        let total = mon.run(
            &ctrl,
            &sink,
            &RunConfig {
                interval_ms: 0,
                max_sweeps: None,
                ..Default::default()
            },
            || 0,
            no_proc,
            || true,
        );
        assert_eq!(total, 0);
        assert!(sink.events().is_empty());
    }

    #[test]
    fn run_with_chained_sink_produces_verifiable_log() {
        use crate::{verify_chain, ChainedFileSink};
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("overlay-audit.log");
        let rules = Ruleset::from_lines(&["host: win-prize-now.example"]);
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            process: None,
            id: "scam".into(),
            window: scam(),
        }]);
        let sink = ChainedFileSink::open(&p).unwrap();
        let mut mon = Monitor::new(rules);
        let t = std::cell::Cell::new(0u64);
        let clock = || {
            let v = t.get();
            t.set(v + 1_000);
            v
        };
        mon.run(
            &ctrl,
            &sink,
            &RunConfig {
                interval_ms: 0,
                max_sweeps: Some(2),
                ..Default::default()
            },
            clock,
            no_proc,
            || false,
        );
        let text = std::fs::read_to_string(&p).unwrap();
        let (count, head) = verify_chain(&text).unwrap();
        assert!(count >= 2, "expected >=2 chained events, got {count}");
        assert_eq!(head, sink.head());
    }

    // ── L3: SweepOutcome + adaptive interval ──────────────────────

    #[test]
    fn sweep_outcome_detections_counts_block_and_suspicious() {
        // One Block window + one Suspicious window → detections == 2.
        let ctrl = NullController::with_windows(vec![
            EnumeratedWindow {
                process: None,
                id: "block".into(),
                window: scam(), // fully triggers block
            },
            EnumeratedWindow {
                process: None,
                id: "sus".into(),
                window: OverlayWindow {
                    title: "offer".into(),
                    has_close_button: false,     // +25
                    origin: Origin::Unsolicited, // +25 = 50 → suspicious
                    ..Default::default()
                },
            },
        ]);
        let sink = MemorySink::new();
        let rules = Ruleset::from_lines(&["host: win-prize-now.example"]);
        let mut mon = Monitor::new(rules);
        let outcome = mon.sweep(&ctrl, &sink, 1_000, no_proc);
        assert_eq!(
            outcome.detections, 2,
            "one block + one suspicious = 2 detections"
        );
        assert_eq!(outcome.dismissed, 1, "only the block window is dismissed");
    }

    #[test]
    fn sweep_outcome_zero_detections_for_benign_sweep() {
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            process: None,
            id: "ok".into(),
            window: benign(),
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        let outcome = mon.sweep(&ctrl, &sink, 1_000, no_proc);
        assert_eq!(outcome, SweepOutcome::default());
    }

    #[test]
    fn run_with_alert_interval_field_accepted() {
        // Verify that RunConfig with alert_interval_ms set builds and
        // runs without panic. The actual sleep is 0 in tests so we
        // can't observe the shortened interval, but we validate the
        // config is accepted and the run terminates normally.
        let rules = Ruleset::from_lines(&["host: win-prize-now.example"]);
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            process: None,
            id: "scam".into(),
            window: scam(),
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(rules);
        let total = mon.run(
            &ctrl,
            &sink,
            &RunConfig {
                interval_ms: 0,
                alert_interval_ms: Some(0), // also 0 in test
                max_sweeps: Some(2),
            },
            || 1_000,
            no_proc,
            || false,
        );
        assert_eq!(total, 2);
    }
}
