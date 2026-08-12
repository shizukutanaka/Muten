//! Fuzz the `OverlayWindow` JSON deserializer directly.
//!
//! Even when the input isn't valid JSON for OverlayWindow, `serde_json` and
//! the derived `Deserialize` impl must never panic.  When deserialization
//! succeeds, the window must survive a full `classify()` round.
//!
//! Run with:
//! ```sh
//! cargo +nightly fuzz run fuzz_window_json -- -max_len=2048
//! ```
#![no_main]
use libfuzzer_sys::fuzz_target;
use muten_overlay::{classify, OverlayWindow, Ruleset};

fuzz_target!(|data: &[u8]| {
    // serde_json::from_slice never panics.
    if let Ok(window) = serde_json::from_slice::<OverlayWindow>(data) {
        // A successfully-deserialized window must survive classify().
        let _ = classify(&window, &Ruleset::default());
    }
});
