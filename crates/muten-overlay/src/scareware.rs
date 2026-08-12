//! Scareware / rogue-antivirus detection.
//!
//! A one-off scam overlay is handled by [`crate::classify`]. Rogue
//! security software ("fake antivirus") behaves differently: once
//! installed it *persists* and **floods the desktop with the same
//! fake-threat pop-up over and over**, demanding payment to "fix"
//! infections that don't exist. Two tells distinguish it from a
//! single web overlay:
//!
//! 1. **Repetition** — the same alert signature reappears many times
//!    in a short window. A legitimate app does not re-pop an identical
//!    modal every few seconds.
//! 2. **An installed process** — unlike a web page, rogue AV runs as
//!    a local process (often masquerading as "PC Protector Plus",
//!    "Advanced Mac Cleaner", a registry cleaner, etc.) and re-launches
//!    via Run-key / scheduled-task persistence.
//!
//! This module models both signals as **pure logic**: the daemon's
//! OS-specific collector feeds in observations (overlay appearances,
//! the owning process name) and the detector decides. No OS calls, no
//! network, `forbid(unsafe_code)` — same contract as the rest of the
//! crate.
//!
//! ## Scope (CLAUDE.md I9: least privilege, read-only first)
//!
//! muten **detects and audits** scareware; it does not kill processes,
//! edit the registry, or delete files. Removal is an EDR / antivirus
//! responsibility and would require privileges and `unsafe` we refuse
//! to take. The value muten adds is *early, explainable, offline
//! detection* on managed fleets — surfacing "PC-07 has shown the same
//! fake-virus pop-up 9 times in 2 minutes and is running
//! `pcprotectorplus.exe`" into the audit log / SIEM so IT acts before
//! the user pays.

use crate::rules::Ruleset;
use serde::Serialize;
use std::collections::HashMap;

/// A stable fingerprint of an overlay appearance. The OS collector
/// derives this from the window — typically a normalized title plus
/// the source host — so that "the same pop-up" maps to "the same key"
/// across appearances. We don't define the hashing here; the caller
/// supplies whatever stable string identifies one campaign.
pub type Signature = String;

/// Verdict from the scareware detector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScarewareVerdict {
    /// The scareware classification (Benign or Scareware).
    pub decision: ScarewareDecision,
    /// Why we decided. Listed for the audit log.
    pub signals: Vec<&'static str>,
    /// How many times this signature appeared in the window.
    pub repeat_count: u32,
    /// Matched rogue-AV process pattern, if any.
    pub matched_process: Option<String>,
}

/// The scareware detector's classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScarewareDecision {
    /// Nothing notable.
    Benign,
    /// Looks like scareware — audit and surface to IT, do not act
    /// destructively.
    Scareware,
}

/// How many identical appearances within the window before we call it
/// a flood. Three of the exact same modal in the window is already
/// abnormal for legitimate software.
pub const REPEAT_THRESHOLD: u32 = 3;

/// Sliding window for repeat counting, milliseconds (default 2 min).
pub const DEFAULT_WINDOW_MS: u64 = 120_000;

/// Tracks repeated overlay appearances within a sliding time window to
/// detect the "flood" behavior of installed rogue AV.
///
/// The daemon holds one of these and calls [`record`](Self::record)
/// each time the OS collector reports an overlay, passing the current
/// time. Appearances older than the window are pruned, so memory is
/// bounded by the number of *distinct* signatures seen recently.
#[derive(Debug, Clone)]
pub struct RepeatTracker {
    window_ms: u64,
    /// signature -> timestamps (ms) of recent appearances.
    seen: HashMap<Signature, Vec<u64>>,
}

impl RepeatTracker {
    /// Create a tracker with a custom sliding-window duration in milliseconds.
    #[must_use]
    pub fn new(window_ms: u64) -> Self {
        Self {
            window_ms,
            seen: HashMap::new(),
        }
    }

    /// Record one appearance of `sig` at time `now_ms`; returns the
    /// number of appearances now within the window (including this
    /// one). Prunes expired entries for this signature.
    pub fn record(&mut self, sig: &str, now_ms: u64) -> u32 {
        let window_ms = self.window_ms;
        let entry = self.seen.entry(sig.to_string()).or_default();
        entry.retain(|&t| Self::in_window(t, now_ms, window_ms));
        entry.push(now_ms);
        entry.len() as u32
    }

    /// Current count for a signature without recording a new hit.
    #[must_use]
    pub fn count(&self, sig: &str, now_ms: u64) -> u32 {
        let window_ms = self.window_ms;
        self.seen
            .get(sig)
            .map(|v| {
                v.iter()
                    .filter(|&&t| Self::in_window(t, now_ms, window_ms))
                    .count() as u32
            })
            .unwrap_or(0)
    }

    /// Drop all tracking state for signatures with no recent activity,
    /// keeping memory bounded over long uptimes. Call periodically.
    pub fn prune(&mut self, now_ms: u64) {
        let window_ms = self.window_ms;
        for v in self.seen.values_mut() {
            v.retain(|&t| Self::in_window(t, now_ms, window_ms));
        }
        self.seen.retain(|_, v| !v.is_empty());
    }

    /// True if timestamp `t` falls within the **closed** sliding window ending
    /// at `now_ms`: `now_ms - window_ms <= t <= now_ms`.
    ///
    /// The **upper** bound is the clock-regression guard. The injected clock is
    /// wall-clock in production and can step *backward* (NTP correction, manual
    /// set, VM snapshot restore, host migration). With only a lower bound, an
    /// entry recorded before a backward jump becomes "future-dated"
    /// (`t > now_ms`) and would linger in the window — inflating repeat counts
    /// (risking a false scareware-flood detection) and escaping `prune`. Under a
    /// monotonic clock every recorded `t <= now_ms`, so the upper bound is a
    /// no-op and behavior is unchanged; it only takes effect to discard stale
    /// future-dated entries after a regression. `saturating_sub` keeps the lower
    /// bound from underflowing early in process life (`now_ms < window_ms`).
    fn in_window(t: u64, now_ms: u64, window_ms: u64) -> bool {
        let cutoff = now_ms.saturating_sub(window_ms);
        cutoff <= t && t <= now_ms
    }
}

impl Default for RepeatTracker {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW_MS)
    }
}

/// Decide whether the current situation is scareware.
///
/// Inputs:
/// - `repeat_count`: appearances of this overlay signature in the
///   window (from [`RepeatTracker::record`]).
/// - `process_name`: the owning process, if the collector attributed
///   one (an installed rogue AV will have one; a transient web overlay
///   typically won't, or will be the browser).
/// - `rules`: the blocklist, consulted for known rogue-AV process
///   names.
///
/// A known rogue-AV **process** match alone is enough (the software is
/// already installed). Otherwise, a **repeat flood** at or above
/// [`REPEAT_THRESHOLD`] is the signal.
#[must_use]
pub fn assess(repeat_count: u32, process_name: Option<&str>, rules: &Ruleset) -> ScarewareVerdict {
    let mut signals: Vec<&'static str> = Vec::new();

    let matched_process = process_name.and_then(|p| rules.match_process(p));

    if matched_process.is_some() {
        signals.push("rogue_av_process");
    }
    if repeat_count >= REPEAT_THRESHOLD {
        signals.push("repeated_flood");
    }

    let decision = if matched_process.is_some() || repeat_count >= REPEAT_THRESHOLD {
        ScarewareDecision::Scareware
    } else {
        ScarewareDecision::Benign
    };

    ScarewareVerdict {
        decision,
        signals,
        repeat_count,
        matched_process,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rogue_rules() -> Ruleset {
        Ruleset::from_lines(&[
            "process: pc protector plus",
            "process: advanced mac cleaner",
            "process: registrysmart",
            "process: systemcare antivirus",
        ])
    }

    #[test]
    fn single_appearance_is_benign() {
        let mut t = RepeatTracker::new(DEFAULT_WINDOW_MS);
        let n = t.record("fake-virus-alert", 1_000);
        assert_eq!(n, 1);
        let v = assess(n, None, &Ruleset::default());
        assert_eq!(v.decision, ScarewareDecision::Benign);
    }

    /// Flood-threshold boundary guard (Socratic round 9). `assess` flags a
    /// flood at `repeat_count >= REPEAT_THRESHOLD`. The existing tests cover
    /// count 1 (Benign) and count 3 (= threshold, Scareware) but skip the
    /// decisive lower edge, count 2 — the last *benign* count. Lowering
    /// `REPEAT_THRESHOLD` to 2, or changing the comparison to
    /// `>= REPEAT_THRESHOLD - 1`, would still pass those tests while turning a
    /// legitimate app that merely pops up twice into a false "flood" — a
    /// false positive on the scareware path, which the FP-averse design must
    /// avoid. This pins both edges relative to the constant so it stays
    /// correct if the threshold is retuned.
    #[test]
    fn flood_threshold_boundary_one_below_is_benign() {
        // One below the threshold → not yet a flood (FP guard).
        let v = assess(REPEAT_THRESHOLD - 1, None, &Ruleset::default());
        assert_eq!(v.decision, ScarewareDecision::Benign);
        assert!(!v.signals.contains(&"repeated_flood"));
        // Exactly at the threshold → flood.
        let v = assess(REPEAT_THRESHOLD, None, &Ruleset::default());
        assert_eq!(v.decision, ScarewareDecision::Scareware);
        assert!(v.signals.contains(&"repeated_flood"));
    }

    #[test]
    fn repeated_flood_is_scareware() {
        let mut t = RepeatTracker::new(DEFAULT_WINDOW_MS);
        let mut n = 0;
        for ms in [1_000, 5_000, 9_000] {
            n = t.record("fake-virus-alert", ms);
        }
        assert_eq!(n, 3);
        let v = assess(n, None, &Ruleset::default());
        assert_eq!(v.decision, ScarewareDecision::Scareware);
        assert!(v.signals.contains(&"repeated_flood"));
    }

    #[test]
    fn appearances_outside_window_dont_count() {
        let mut t = RepeatTracker::new(10_000); // 10s window
        t.record("sig", 1_000);
        t.record("sig", 2_000);
        // This one is way past the window from the first two.
        let n = t.record("sig", 100_000);
        assert_eq!(n, 1, "old appearances should have been pruned");
    }

    /// Sliding-window boundary guard (Socratic round 10). Pruning keeps
    /// entries with `t >= cutoff` where `cutoff = now - window_ms`, so an
    /// appearance *exactly* `window_ms` old is still inside the window, and
    /// one tick older falls out. The existing test only checks an event far
    /// outside the window, so flipping `>= cutoff` to `> cutoff` (shrinking
    /// the window by one tick — enough to miss a flood whose appearances are
    /// spaced exactly `window_ms` apart) would pass it. This pins both sides
    /// of the exact edge via the non-mutating `count`.
    #[test]
    fn sliding_window_boundary_is_inclusive_of_exactly_window_ms() {
        let window_ms = 10_000;
        let mut t = RepeatTracker::new(window_ms);
        t.record("sig", 1_000);
        // now == event_time + window_ms → cutoff == event_time → still counted.
        assert_eq!(
            t.count("sig", 1_000 + window_ms),
            1,
            "an appearance exactly window_ms old must remain in the window"
        );
        // One tick later → cutoff passes the event → pruned from the count.
        assert_eq!(
            t.count("sig", 1_000 + window_ms + 1),
            0,
            "an appearance just over window_ms old must fall out of the window"
        );
    }

    #[test]
    fn distinct_signatures_counted_separately() {
        let mut t = RepeatTracker::new(DEFAULT_WINDOW_MS);
        t.record("alert-a", 1_000);
        t.record("alert-a", 2_000);
        let nb = t.record("alert-b", 3_000);
        assert_eq!(nb, 1);
        assert_eq!(t.count("alert-a", 3_000), 2);
    }

    /// Clock-regression robustness (Socratic round 11). The injected clock is
    /// wall-clock in production and can step *backward* (NTP correction, manual
    /// set, VM snapshot restore). The window is closed on both sides, so an
    /// entry recorded before a backward jump (now "future-dated", `t > now_ms`)
    /// must NOT be counted — otherwise stale entries linger and could push a
    /// benign repeat over the flood threshold (false scareware detection) or
    /// escape pruning. Under a monotonic clock this is a no-op (every recorded
    /// `t <= now_ms`).
    #[test]
    fn future_dated_entry_excluded_after_clock_regression() {
        let window_ms = 120_000;
        let mut t = RepeatTracker::new(window_ms);
        // Record at a high time, then the clock steps back by an hour.
        t.record("sig", 3_600_000);
        // count at the regressed (earlier) time: the future-dated entry
        // (t = 3_600_000 > now = 1_000) must be excluded.
        assert_eq!(
            t.count("sig", 1_000),
            0,
            "a future-dated entry (recorded before a backward clock jump) must \
             not be counted in the window"
        );
    }

    #[test]
    fn clock_regression_does_not_inflate_flood_count() {
        // A single pre-jump appearance + a few post-jump appearances at the
        // regressed clock must count only the in-window post-jump ones, so the
        // stale future entry can't help cross the flood threshold.
        let window_ms = 120_000;
        let mut t = RepeatTracker::new(window_ms);
        t.record("flood", 10_000_000); // pre-jump, far in the "future" after reset
                                       // Clock resets near zero; two genuine appearances arrive.
        t.record("flood", 1_000);
        let n = t.record("flood", 2_000);
        assert_eq!(
            n, 2,
            "only the two in-window post-regression appearances count; the \
             future-dated entry is discarded"
        );
    }

    #[test]
    fn prune_drops_future_dated_entries() {
        // prune must also discard future-dated entries after a regression, so
        // memory cannot grow unboundedly across repeated clock steps.
        let window_ms = 120_000;
        let mut t = RepeatTracker::new(window_ms);
        t.record("sig", 5_000_000);
        t.prune(1_000); // regressed clock
        assert_eq!(
            t.count("sig", 1_000),
            0,
            "future-dated entry must be pruned"
        );
    }

    #[test]
    fn rogue_av_process_alone_is_scareware() {
        // Even a single appearance is scareware if the owning process
        // is a known rogue AV — the software is already installed.
        let v = assess(1, Some("PCProtectorPlus.exe"), &rogue_rules());
        assert_eq!(v.decision, ScarewareDecision::Scareware);
        assert!(v.signals.contains(&"rogue_av_process"));
        assert_eq!(v.matched_process.as_deref(), Some("pc protector plus"));
    }

    #[test]
    fn legit_process_not_flagged() {
        let v = assess(1, Some("chrome.exe"), &rogue_rules());
        assert_eq!(v.decision, ScarewareDecision::Benign);
        assert!(v.matched_process.is_none());
    }

    #[test]
    fn both_signals_fire_together() {
        let mut t = RepeatTracker::new(DEFAULT_WINDOW_MS);
        let mut n = 0;
        for ms in [1_000, 2_000, 3_000, 4_000] {
            n = t.record("registrysmart-alert", ms);
        }
        let v = assess(n, Some("RegistrySmart.exe"), &rogue_rules());
        assert_eq!(v.decision, ScarewareDecision::Scareware);
        assert!(v.signals.contains(&"rogue_av_process"));
        assert!(v.signals.contains(&"repeated_flood"));
        assert_eq!(v.repeat_count, 4);
    }

    #[test]
    fn prune_drops_stale_signatures() {
        let mut t = RepeatTracker::new(10_000);
        t.record("old", 1_000);
        t.record("recent", 50_000);
        t.prune(55_000);
        assert_eq!(t.count("old", 55_000), 0);
        assert_eq!(t.count("recent", 55_000), 1);
    }

    #[test]
    fn count_does_not_mutate() {
        let mut t = RepeatTracker::new(DEFAULT_WINDOW_MS);
        t.record("sig", 1_000);
        assert_eq!(t.count("sig", 2_000), 1);
        assert_eq!(t.count("sig", 2_000), 1); // stable, no increment
    }
}
