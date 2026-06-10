//! Property-based tests for the monitor sweep loop.
//!
//! Invariants that must hold for *any* set of observed windows:
//! 1. A sweep never panics.
//! 2. The dismissed count never exceeds the number of windows.
//! 3. Only `Block`-class windows are ever dismissed (we never dismiss
//!    a window the controller reports but the classifier allowed).
//! 4. User-initiated windows never contribute to the repeated-flood
//!    signal, no matter how many times they reappear.

use muten_overlay::{
    EnumeratedWindow, MemorySink, Monitor, NullController, Origin, OverlayWindow, Ruleset,
};
use proptest::prelude::*;

fn origin_strategy() -> impl Strategy<Value = Origin> {
    prop_oneof![
        Just(Origin::Unknown),
        Just(Origin::UserInitiated),
        Just(Origin::Unsolicited),
    ]
}

prop_compose! {
    fn window_strategy()(
        title in "[ -~]{0,40}",
        coverage in 0u8..=100,
        topmost in any::<bool>(),
        has_close in any::<bool>(),
        blocks_input in any::<bool>(),
        origin in origin_strategy(),
        age_ms in 0u64..100_000,
    ) -> OverlayWindow {
        OverlayWindow {
            title,
            url: None,
            coverage_percent: coverage,
            topmost,
            has_close_button: has_close,
            blocks_input,
            origin,
            age_ms,
        }
    }
}

prop_compose! {
    fn enumerated_strategy()(
        windows in prop::collection::vec(window_strategy(), 0..12),
    ) -> Vec<EnumeratedWindow> {
        windows
            .into_iter()
            .enumerate()
            .map(|(i, w)| EnumeratedWindow { id: format!("w{i}"), window: w })
            .collect()
    }
}

proptest! {
    /// A sweep never panics and dismisses at most as many windows as
    /// were enumerated.
    #[test]
    fn sweep_never_panics_and_dismiss_bounded(windows in enumerated_strategy()) {
        let n = windows.len() as u32;
        let ctrl = NullController::with_windows(windows);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        let outcome = mon.sweep(&ctrl, &sink, 1_000, |_| None);
        prop_assert!(outcome.dismissed <= n);
        // The controller recorded exactly `dismissed`-or-fewer ids
        // (NullController always returns Ok(true), so equal here).
        prop_assert_eq!(ctrl.dismissed().len() as u32, outcome.dismissed);
    }

    /// Every dismissed window's id appears in the controller's dismiss
    /// log; nothing is dismissed that wasn't enumerated.
    #[test]
    fn only_enumerated_windows_dismissed(windows in enumerated_strategy()) {
        let ids: std::collections::HashSet<String> =
            windows.iter().map(|w| w.id.clone()).collect();
        let ctrl = NullController::with_windows(windows);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        mon.sweep(&ctrl, &sink, 1_000, |_| None);
        for id in ctrl.dismissed() {
            prop_assert!(ids.contains(&id), "dismissed an unknown id: {id}");
        }
    }

    /// A user-initiated window repeated arbitrarily many times never
    /// produces a scareware_detected event (with an empty process map).
    #[test]
    fn user_initiated_never_floods(
        title in "[a-z ]{1,20}",
        sweeps in 3u32..15,
    ) {
        let w = OverlayWindow {
            title,
            url: None,
            coverage_percent: 50,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            id: "u".into(),
            window: w,
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        for i in 0..sweeps {
            mon.sweep(&ctrl, &sink, u64::from(i) * 1_000, |_| None);
        }
        prop_assert_eq!(sink.count_of("scareware_detected"), 0);
    }

    /// An unsolicited window repeated >= 3 times within the window
    /// always eventually produces at least one scareware_detected.
    #[test]
    fn unsolicited_repeats_always_flood(reps in 3u32..10) {
        let w = OverlayWindow {
            title: "alert".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 1_000,
        };
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            id: "f".into(),
            window: w,
        }]);
        let sink = MemorySink::new();
        let mut mon = Monitor::new(Ruleset::default());
        for i in 0..reps {
            mon.sweep(&ctrl, &sink, u64::from(i) * 1_000, |_| None);
        }
        prop_assert!(sink.count_of("scareware_detected") >= 1);
    }
}
