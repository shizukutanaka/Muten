//! Property-based tests for the scareware detector.
//!
//! The repeat tracker is the load-bearing piece: it must count
//! appearances within a sliding window correctly no matter the
//! ordering or spacing of timestamps, and it must never panic.

use muten_overlay::scareware::{assess, RepeatTracker, ScarewareDecision, REPEAT_THRESHOLD};
use muten_overlay::Ruleset;
use proptest::prelude::*;

proptest! {
    /// record() never panics and always returns a count >= 1 (the
    /// just-recorded appearance is always within the window).
    #[test]
    fn record_returns_at_least_one(
        window in 1u64..1_000_000,
        sig in "[a-z]{1,12}",
        now in 0u64..u64::MAX / 2,
    ) {
        let mut t = RepeatTracker::new(window);
        let n = t.record(&sig, now);
        prop_assert!(n >= 1);
    }

    /// Recording the same signature `k` times all within the window
    /// yields a final count of exactly `k`.
    #[test]
    fn k_records_in_window_count_k(k in 1u32..50) {
        let window = 1_000_000u64;
        let mut t = RepeatTracker::new(window);
        let mut last = 0;
        for i in 0..k {
            // All timestamps within the window (step << window).
            last = t.record("sig", u64::from(i) * 10);
        }
        prop_assert_eq!(last, k);
    }

    /// A signature recorded then probed far beyond the window reads 0.
    #[test]
    fn expired_signature_counts_zero(
        window in 1u64..100_000,
        base in 0u64..1_000_000,
    ) {
        let mut t = RepeatTracker::new(window);
        t.record("sig", base);
        // Probe strictly more than `window` later.
        let later = base + window + 1;
        prop_assert_eq!(t.count("sig", later), 0);
    }

    /// count() is idempotent: probing twice at the same instant gives
    /// the same answer and doesn't mutate state.
    #[test]
    fn count_is_idempotent(
        sig in "[a-z]{1,8}",
        times in prop::collection::vec(0u64..10_000, 0..20),
        probe in 0u64..20_000,
    ) {
        let mut t = RepeatTracker::new(1_000_000);
        for &ts in &times {
            t.record(&sig, ts);
        }
        let a = t.count(&sig, probe);
        let b = t.count(&sig, probe);
        prop_assert_eq!(a, b);
    }

    /// assess() is monotone in repeat_count: once at/above threshold,
    /// it stays Scareware as the count grows.
    #[test]
    fn assess_monotone_in_repeat_count(extra in 0u32..100) {
        let n = REPEAT_THRESHOLD + extra;
        let v = assess(n, None, &Ruleset::default());
        prop_assert_eq!(v.decision, ScarewareDecision::Scareware);
    }

    /// Below threshold with no rogue process is always Benign.
    #[test]
    fn below_threshold_no_process_is_benign(n in 0u32..REPEAT_THRESHOLD) {
        let v = assess(n, None, &Ruleset::default());
        prop_assert_eq!(v.decision, ScarewareDecision::Benign);
    }

    /// A known rogue-AV process is always Scareware regardless of the
    /// repeat count (even a single appearance).
    #[test]
    fn rogue_process_always_scareware(n in 0u32..100) {
        let rules = Ruleset::from_lines(&["process: pc protector plus"]);
        let v = assess(n, Some("PCProtectorPlus.exe"), &rules);
        prop_assert_eq!(v.decision, ScarewareDecision::Scareware);
    }

    /// prune() never panics and never increases any count.
    #[test]
    fn prune_never_increases_counts(
        times in prop::collection::vec(0u64..100_000, 0..30),
        prune_at in 0u64..200_000,
    ) {
        let mut t = RepeatTracker::new(50_000);
        for &ts in &times {
            t.record("sig", ts);
        }
        let before = t.count("sig", prune_at);
        t.prune(prune_at);
        let after = t.count("sig", prune_at);
        prop_assert_eq!(before, after, "prune must not change the windowed count");
    }
}
