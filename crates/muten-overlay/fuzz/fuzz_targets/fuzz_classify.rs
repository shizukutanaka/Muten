//! Fuzz the full `classify()` pipeline over arbitrary `OverlayWindow` inputs.
//!
//! The fuzzer generates arbitrary byte sequences; we treat them as JSON for
//! `OverlayWindow` deserialization.  If deserialization fails we exit early —
//! the parser's safety is covered by `fuzz_window_json`.  The interesting case
//! is when deserialization succeeds: `classify()` must never panic, the decision
//! must be consistent with the score, and `explain()` must be non-empty.
//!
//! Run with:
//! ```sh
//! cargo +nightly fuzz run fuzz_classify -- -max_len=2048
//! ```
#![no_main]
use libfuzzer_sys::fuzz_target;
use muten_overlay::{classify, Decision, OverlayWindow, Ruleset, BLOCK_THRESHOLD, SUSPICIOUS_THRESHOLD};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(window) = serde_json::from_str::<OverlayWindow>(s) else {
        return;
    };
    let rs = Ruleset::default();
    let v = classify(&window, &rs);
    // Score is always non-negative (clamped).
    assert!(v.score >= 0, "score must be non-negative: {}", v.score);
    // Decision is consistent with score.
    match v.decision {
        Decision::Block => assert!(v.score >= BLOCK_THRESHOLD),
        Decision::Suspicious => {
            assert!(v.score >= SUSPICIOUS_THRESHOLD);
            assert!(v.score < BLOCK_THRESHOLD);
        }
        Decision::Allow => assert!(v.score < SUSPICIOUS_THRESHOLD),
    }
    // explain() is always non-empty and ends with a period.
    let why = v.explain();
    assert!(!why.is_empty());
    assert!(why.ends_with('.'), "explain() must end with '.': {why:?}");
    // score_breakdown covers all fired signals.
    let bd = v.score_breakdown();
    for sig in &v.signals {
        assert!(
            bd.iter().any(|(name, _)| name == sig),
            "signal {sig} missing from score_breakdown"
        );
    }
});
