//! Regression tests for the shipped example blocklist.
//!
//! `examples/overlay-blocklist.txt` is a product asset: on real hosts
//! where the behavioural heuristic is weak (origin/modality unknown),
//! the blocklist is muten's reliable detection path. These tests load
//! the real file and assert that current high-volume scam families are
//! covered, so an edit that accidentally drops a category is caught.
//!
//! Threat grounding: FBI IC3 2025 (government-impersonation complaints
//! ~doubled to 32,500, top-5 fraud), Microsoft Edge security team
//! reports (fake blue screens / control panels / law-enforcement
//! lock-screens), FTC TSS guidance, 2026 ClickFix/FakeCAPTCHA surge.

use muten_overlay::{classify, Decision, OverlayWindow, Ruleset};

fn load_example_blocklist() -> Ruleset {
    // Tests run with CWD = crate dir; the file lives at the repo's
    // examples/ (two levels up from crates/muten-overlay).
    let candidates = [
        "../../examples/overlay-blocklist.txt",
        "examples/overlay-blocklist.txt",
    ];
    for path in candidates {
        if let Ok(text) = std::fs::read_to_string(path) {
            return Ruleset::parse(&text);
        }
    }
    panic!("could not locate examples/overlay-blocklist.txt from CWD");
}

/// A fullscreen, unsolicited overlay whose title contains `title`.
fn alert_with_title(title: &str) -> OverlayWindow {
    OverlayWindow {
        title: title.to_string(),
        url: None,
        coverage_percent: 100,
        topmost: true,
        has_close_button: false,
        blocks_input: true,
        origin: muten_overlay::Origin::Unsolicited,
        age_ms: 0,
    }
}

#[test]
fn blocklist_parses_with_substantial_coverage() {
    let rs = load_example_blocklist();
    assert!(rs.title_count() >= 85, "titles: {}", rs.title_count());
    assert!(
        rs.process_count() >= 10,
        "processes: {}",
        rs.process_count()
    );
}

#[test]
fn covers_classic_tech_support_scam() {
    let rs = load_example_blocklist();
    let v = classify(&alert_with_title("your computer is infected"), &rs);
    assert!(v.signals.contains(&"blocklist_title"));
}

#[test]
fn covers_law_enforcement_impersonation() {
    // FBI IC3 2025: fastest-growing, ~$797M lost.
    let rs = load_example_blocklist();
    for title in [
        "This device has been locked for security",
        "Illegal activity has been detected on this device",
        "Federal Bureau of Investigation: pay the fine to unlock",
    ] {
        let v = classify(&alert_with_title(title), &rs);
        assert!(
            v.signals.contains(&"blocklist_title"),
            "not covered: {title:?}"
        );
    }
}

#[test]
fn covers_fake_blue_screen() {
    let rs = load_example_blocklist();
    for title in [
        "Your PC ran into a problem and needs to restart",
        "STOP CODE: CRITICAL PROCESS DIED",
        "Do not restart your computer",
    ] {
        let v = classify(&alert_with_title(title), &rs);
        assert!(
            v.signals.contains(&"blocklist_title"),
            "not covered: {title:?}"
        );
    }
}

#[test]
fn covers_clickfix_fakecaptcha() {
    // 2026's dominant initial-access vector.
    let rs = load_example_blocklist();
    for title in ["Verify you are human", "Press Win+R then Ctrl+V"] {
        let v = classify(&alert_with_title(title), &rs);
        assert!(
            v.signals.contains(&"blocklist_title"),
            "not covered: {title:?}"
        );
    }
}

#[test]
fn covers_japanese_support_scam() {
    // muten is a Japan-market product; サポート詐欺 is the dominant
    // local variant (IPA / Trend Micro / 消費者庁). These exact phrases
    // appear on real fake-warning screens.
    let rs = load_example_blocklist();
    for title in [
        "警告：ウイルスに感染しています",
        "トロイの木馬スパイウェアに感染したPC",
        "今すぐサポートセンターに電話してください",
        "お使いのコンピュータは危険な状態です",
        "すべてのファイルが削除されます",
    ] {
        let v = classify(&alert_with_title(title), &rs);
        assert!(
            v.signals.contains(&"blocklist_title"),
            "Japanese scam not covered: {title:?}"
        );
    }
}

#[test]
fn japanese_support_scam_reaches_block() {
    // End to end: a fullscreen Japanese TSS screen → Block.
    let rs = load_example_blocklist();
    let v = classify(
        &alert_with_title("ウイルスに感染しています。今すぐ電話してください 0120-000-000"),
        &rs,
    );
    assert_eq!(
        v.decision,
        Decision::Block,
        "score={} {:?}",
        v.score,
        v.signals
    );
}

#[test]
fn japanese_matching_is_case_and_width_robust() {
    // Japanese has no case, but a mix with Latin/fullwidth shouldn't
    // break matching. "Windows" in the title plus the JP phrase.
    let rs = load_example_blocklist();
    let v = classify(
        &alert_with_title("Windows 警告: ウイルスに感染しました"),
        &rs,
    );
    assert!(v.signals.contains(&"blocklist_title"));
}

#[test]
fn law_enforcement_scam_reaches_block() {
    // End to end: a fullscreen FBI-impersonation lock screen should be
    // Block, not merely Suspicious.
    let rs = load_example_blocklist();
    let v = classify(
        &alert_with_title("This device has been locked for security - illegal content detected"),
        &rs,
    );
    assert_eq!(
        v.decision,
        Decision::Block,
        "score={} {:?}",
        v.score,
        v.signals
    );
}

#[test]
fn homoglyph_law_enforcement_title_still_caught() {
    // Combine this session's blocklist additions with the prior
    // confusable-folding defense: a Cyrillic-spoofed FBI lock screen
    // must still match.
    let rs = load_example_blocklist();
    // "illegal" with Cyrillic і twice → "іllegal" ... use Cyrillic 'е'
    // in "detected" and 'а' in "illegal activity".
    let title = "illеgal аctivity has been detected"; // Cyrillic е, а
    let v = classify(&alert_with_title(title), &rs);
    assert!(
        v.signals.contains(&"blocklist_title"),
        "homoglyph law-enforcement title evaded: {:?}",
        v.signals
    );
}
