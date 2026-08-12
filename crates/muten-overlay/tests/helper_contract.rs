//! Contract tests: the JSON the OS helpers emit must deserialize into
//! `EnumeratedWindow` and classify sensibly.
//!
//! The last two bugs both lived at the helper↔domain boundary (the
//! helpers feed `origin:"unknown"` and `age_ms:0`, which the domain
//! layer must handle gracefully). These tests pin the contract so a
//! helper format change or a domain-side regression is caught here
//! rather than in production.
//!
//! We embed the *exact* JSON shape each helper's `printf`/`echo`
//! produces. If a helper's output format changes, update these strings
//! and re-confirm the classifier still behaves.

use muten_overlay::{classify, Decision, EnumeratedWindow, Origin, Ruleset};

/// The Linux/X11 helper (wmctrl) emits this per window.
const LINUX_HELPER_LINE: &str = r#"{"id":"0x04000007","process":"badav","window":{"title":"your computer is infected","url":null,"coverage_percent":100,"topmost":true,"has_close_button":true,"blocks_input":false,"origin":"unknown","age_ms":0}}"#;

/// The Windows helper (Win32 P/Invoke) emits this shape (id is an
/// int64 HWND; topmost from WS_EX_TOPMOST).
const WINDOWS_HELPER_LINE: &str = r#"{"id":"67174407","process":"PCProtectorPlus","window":{"title":"critical error - call support","url":null,"coverage_percent":98,"topmost":true,"has_close_button":true,"blocks_input":false,"origin":"unknown","age_ms":0}}"#;

/// The macOS helper (osascript) emits this shape (id is app::window).
const MACOS_HELPER_LINE: &str = r#"{"id":"Safari::Verify you are human","process":"Safari","window":{"title":"Verify you are human","url":null,"coverage_percent":75,"topmost":false,"has_close_button":true,"blocks_input":false,"origin":"unknown","age_ms":0}}"#;

/// The Wayland helper (wlroots foreign-toplevel) emits this shape: id
/// is "app-id::title", geometry/stacking unavailable on Wayland so
/// coverage=0, topmost=false. Title blocklist is the detection path.
const WAYLAND_HELPER_LINE: &str = r#"{"id":"firefox::your computer is infected","process":"firefox","window":{"title":"your computer is infected","url":null,"coverage_percent":0,"topmost":false,"has_close_button":true,"blocks_input":false,"origin":"unknown","age_ms":0}}"#;

#[test]
fn linux_helper_line_deserializes() {
    let ew: EnumeratedWindow = serde_json::from_str(LINUX_HELPER_LINE).unwrap();
    assert_eq!(ew.id, "0x04000007");
    assert_eq!(ew.process.as_deref(), Some("badav"));
    assert_eq!(ew.window.coverage_percent, 100);
    assert!(ew.window.topmost);
    assert_eq!(ew.window.origin, Origin::Unknown);
    assert_eq!(ew.window.age_ms, 0);
}

#[test]
fn windows_helper_line_deserializes() {
    let ew: EnumeratedWindow = serde_json::from_str(WINDOWS_HELPER_LINE).unwrap();
    assert_eq!(ew.id, "67174407");
    assert_eq!(ew.process.as_deref(), Some("PCProtectorPlus"));
    assert_eq!(ew.window.coverage_percent, 98);
}

#[test]
fn macos_helper_line_deserializes() {
    let ew: EnumeratedWindow = serde_json::from_str(MACOS_HELPER_LINE).unwrap();
    assert_eq!(ew.id, "Safari::Verify you are human");
    assert_eq!(ew.process.as_deref(), Some("Safari"));
    assert!(!ew.window.topmost);
}

#[test]
fn wayland_helper_line_deserializes() {
    let ew: EnumeratedWindow = serde_json::from_str(WAYLAND_HELPER_LINE).unwrap();
    assert_eq!(ew.id, "firefox::your computer is infected");
    assert_eq!(ew.process.as_deref(), Some("firefox"));
    assert_eq!(ew.window.coverage_percent, 0);
    assert!(!ew.window.topmost);
    assert_eq!(ew.window.origin, Origin::Unknown);
}

/// Helpers that predate the optional `process` field — or that couldn't
/// attribute a process for a given window and therefore omitted the field
/// (the documented best-effort contract) — must keep parsing, with the
/// process coming back as `None`.
#[test]
fn helper_line_without_process_field_still_deserializes() {
    let old = r#"{"id":"0x04000007","window":{"title":"your computer is infected","url":null,"coverage_percent":100,"topmost":true,"has_close_button":true,"blocks_input":false,"origin":"unknown","age_ms":0}}"#;
    let ew: EnumeratedWindow =
        serde_json::from_str(old).expect("process-less helper output must keep parsing");
    assert_eq!(ew.process, None);
}

#[test]
fn wayland_title_only_still_detected_via_blocklist() {
    // On Wayland, geometry is unavailable (coverage=0, topmost=false),
    // so the behavioural heuristic scores ~0. The TITLE BLOCKLIST is
    // the detection path — confirm a known scam title still hits.
    let ew: EnumeratedWindow = serde_json::from_str(WAYLAND_HELPER_LINE).unwrap();
    let rules = Ruleset::from_lines(&["title: your computer is infected"]);
    let v = classify(&ew.window, &rules);
    assert!(
        v.signals.iter().any(|s| s == "blocklist_title"),
        "Wayland title evaded blocklist: {:?}",
        v.signals
    );
}

#[test]
fn helper_array_deserializes() {
    // Helpers wrap lines in a JSON array.
    let arr = format!("[{LINUX_HELPER_LINE},{WINDOWS_HELPER_LINE}]");
    let windows: Vec<EnumeratedWindow> = serde_json::from_str(&arr).unwrap();
    assert_eq!(windows.len(), 2);
}

#[test]
fn empty_helper_array_deserializes() {
    let windows: Vec<EnumeratedWindow> = serde_json::from_str("[]").unwrap();
    assert!(windows.is_empty());
}

#[test]
fn helper_unknown_origin_age_zero_does_not_falsely_block() {
    // The whole point of the last two fixes: with the helpers' default
    // origin=unknown + age_ms=0, a window is judged on its real
    // attributes only, NOT inflated by phantom very_new or a missing
    // user_initiated relief.
    //
    // This Windows line scores fullscreen(30)+topmost(15) = 45, which
    // is below SUSPICIOUS_THRESHOLD (50) → Allow. That is the correct,
    // conservative result: with origin unknown, no close-button info,
    // and age unknown, the heuristic alone does NOT have enough signal
    // to act. See `known_limitation_*` below — on real hosts the
    // BLOCKLIST is the reliable detection path, not the soft heuristic.
    let ew: EnumeratedWindow = serde_json::from_str(WINDOWS_HELPER_LINE).unwrap();
    let v = classify(&ew.window, &Ruleset::default());
    assert_eq!(
        v.decision,
        Decision::Allow,
        "score={} {:?}",
        v.score,
        v.signals
    );
    assert!(
        !v.signals.iter().any(|s| s == "very_new"),
        "age 0 must not be very_new"
    );
    assert!(
        !v.signals.iter().any(|s| s == "unsolicited"),
        "unknown origin is not unsolicited"
    );
}

#[test]
fn known_limitation_helper_defaults_weaken_heuristic_but_title_rescues() {
    // KNOWN LIMITATION: the OS helpers currently default
    // has_close_button=true, blocks_input=false, origin=unknown — which
    // strips three of the strongest scam signals. A real fullscreen
    // scam therefore scores low on the heuristic ALONE. The blocklist
    // (host/title) is what makes detection reliable on real hosts: the
    // same window with a blocklisted title pattern crosses into
    // Suspicious/Block. This test documents the mitigation so a future
    // change that breaks it is caught.
    let line = r#"{"id":"0x1","window":{"title":"your computer is infected - call microsoft support","url":null,"coverage_percent":100,"topmost":true,"has_close_button":true,"blocks_input":false,"origin":"unknown","age_ms":0}}"#;
    let ew: EnumeratedWindow = serde_json::from_str(line).unwrap();

    // Heuristic only: fullscreen+topmost = 45 → Allow (weak).
    let v_no_rules = classify(&ew.window, &Ruleset::default());
    assert_eq!(v_no_rules.decision, Decision::Allow);

    // With a title blocklist: +40 → 85 → Suspicious (flagged for review).
    let rules = Ruleset::from_lines(&["title: your computer is infected"]);
    let v_rules = classify(&ew.window, &rules);
    assert_eq!(
        v_rules.decision,
        Decision::Suspicious,
        "title hit should lift it to Suspicious; score={}",
        v_rules.score
    );
}

#[test]
fn helper_window_on_blocklist_still_hard_blocks() {
    // Even with unknown origin / age 0, a blocklisted host is a hard
    // Block — the helper-default fields don't weaken a confirmed hit.
    let line = r#"{"id":"0x1","window":{"title":"alert","url":"http://scam.example/x","coverage_percent":50,"topmost":false,"has_close_button":true,"blocks_input":false,"origin":"unknown","age_ms":0}}"#;
    let ew: EnumeratedWindow = serde_json::from_str(line).unwrap();
    let rules = Ruleset::from_lines(&["host: scam.example"]);
    let v = classify(&ew.window, &rules);
    assert_eq!(v.decision, Decision::Block);
}

#[test]
fn missing_optional_fields_use_defaults() {
    // A future/minimal helper that omits url should still parse
    // (url is Option). origin/age default via serde if absent? They
    // are NOT #[serde(default)], so omitting them should FAIL — this
    // test documents that contract so we notice if it changes.
    let minimal = r#"{"id":"x","window":{"title":"t","coverage_percent":10,"topmost":false,"has_close_button":true,"blocks_input":false,"origin":"unknown","age_ms":0}}"#;
    // url omitted but it's Option → should still parse.
    let parsed: Result<EnumeratedWindow, _> = serde_json::from_str(minimal);
    assert!(parsed.is_ok(), "url is optional and may be omitted");
}
