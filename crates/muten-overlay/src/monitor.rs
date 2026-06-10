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
}

impl Monitor {
    /// Create a monitor with the default 2-minute repeat-flood window.
    #[must_use]
    pub fn new(rules: Ruleset) -> Self {
        Self {
            rules,
            tracker: RepeatTracker::default(),
        }
    }

    /// Construct with a custom repeat window.
    #[must_use]
    pub fn with_tracker(rules: Ruleset, tracker: RepeatTracker) -> Self {
        Self { rules, tracker }
    }

    /// Run a single sweep at logical time `now_ms`. Enumerates,
    /// classifies, dismisses Block windows, folds in scareware
    /// detection, and emits audit events. Returns a [`SweepOutcome`]
    /// with the dismissed-window count and the detection count
    /// (Block + Suspicious events that fired).
    ///
    /// `process_of` maps a window id to the owning process name, if
    /// the controller/host can attribute one (used for the rogue-AV
    /// process check). Return `None` when unknown.
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
        for ew in &windows {
            let verdict = classify(&ew.window, &self.rules);

            // Scareware: a rogue-AV *process* match fires regardless of
            // origin, but the repeated-*flood* signal must only count
            // UNSOLICITED appearances. A user-initiated window kept on
            // screen across sweeps (e.g. a video) is not a flood — that
            // was a real false positive. We therefore only record an
            // appearance toward the repeat tracker when the window is
            // not user-initiated.
            let sig = signature(&ew.window);
            let repeats = if ew.window.origin == crate::Origin::UserInitiated {
                // Probe the existing count without adding to it, so a
                // genuine unsolicited flood already in progress isn't
                // masked by an interleaved user window with the same
                // (unlikely) signature.
                self.tracker.count(&sig, now_ms)
            } else {
                self.tracker.record(&sig, now_ms)
            };
            let proc = process_of(&ew.id);
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
        // Same window every sweep → repeat tracker crosses threshold.
        let rules = Ruleset::default();
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
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
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(rules);
        // Three sweeps of the same signature within the window.
        mon.sweep(&ctrl, &sink, 1_000, no_proc);
        mon.sweep(&ctrl, &sink, 2_000, no_proc);
        mon.sweep(&ctrl, &sink, 3_000, no_proc);
        assert!(
            sink.count_of("scareware_detected") >= 1,
            "3 identical appearances should trigger scareware_detected; events={:?}",
            sink.events()
        );
    }

    #[test]
    fn rogue_av_process_triggers_scareware_first_sweep() {
        let rules = Ruleset::from_lines(&["process: pc protector plus"]);
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
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

    #[test]
    fn user_initiated_window_not_flagged_as_flood() {
        // A user-opened video kept on screen across many sweeps must
        // NOT trip the repeated_flood signal — a false positive seen in
        // the CLI smoke test. Rogue-AV floods are by definition
        // unsolicited; user-initiated repeats are benign.
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
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
        // The fix must not break detection of genuine floods.
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
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
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        for ms in [1_000, 2_000, 3_000] {
            mon.sweep(&ctrl, &sink, ms, no_proc);
        }
        assert!(sink.count_of("scareware_detected") >= 1);
    }

    #[test]
    fn user_initiated_window_with_rogue_process_still_flagged() {
        // Origin gates the *flood* signal, not the *process* signal.
        let rules = Ruleset::from_lines(&["process: advanced mac cleaner"]);
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
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
                id: "block".into(),
                window: scam(), // fully triggers block
            },
            EnumeratedWindow {
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
