//! End-to-end scoring scenarios — heuristic-only (no blocklist).
//!
//! These tests verify that representative samples from each major scam
//! threat family score at or above threshold using only the built-in
//! heuristic signals, without any operator blocklist.  They serve as:
//!
//! 1. **Regression guards** — a signal removal or weight change that
//!    drops a known scam below Suspicious will fail here.
//! 2. **Documentation** — each test names the threat family and the
//!    signals expected to fire.
//! 3. **FP guards** — the user-initiated / closable variants at the end
//!    confirm the false-positive firewall is intact.
//!
//! Threat groundings: FBI IC3 2025, THREAT_INTEL_2026.md, Symantec
//! Reveton/Winlock, Huntress GlitchFix (Jan 2026), Malwarebytes rogue-AV.

use muten_overlay::{classify, Decision, Origin, OverlayWindow, Ruleset};
use muten_overlay::{BLOCK_THRESHOLD, SUSPICIOUS_THRESHOLD};

fn alert_window(title: &str) -> OverlayWindow {
    OverlayWindow {
        title: title.to_string(),
        url: None,
        coverage_percent: 99,
        topmost: true,
        has_close_button: false,
        blocks_input: true,
        origin: Origin::Unsolicited,
        age_ms: 500,
    }
}

fn closable_window(title: &str) -> OverlayWindow {
    OverlayWindow {
        title: title.to_string(),
        url: None,
        coverage_percent: 30,
        topmost: false,
        has_close_button: true,
        blocks_input: false,
        origin: Origin::UserInitiated,
        age_ms: 10_000,
    }
}

// ── Classic TSS phone-number overlays ────────────────────────────────────

#[test]
fn classic_tss_phone_in_title_reaches_block() {
    let v = classify(
        &alert_window("WARNING: Your computer is infected! Call 1-800-555-0100"),
        &Ruleset::default(),
    );
    assert_eq!(
        v.decision,
        Decision::Block,
        "classic TSS phone overlay must Block; score={} signals={:?}",
        v.score,
        v.signals
    );
    assert!(v.signals.iter().any(|s| s == "phone_number"));
}

#[test]
fn classic_tss_without_phone_is_suspicious() {
    // Full-screen unsolicited overlay with no phone → geometry signals only → Suspicious.
    let v = classify(
        &alert_window("WARNING: Your computer is infected!"),
        &Ruleset::default(),
    );
    assert!(
        v.score >= SUSPICIOUS_THRESHOLD,
        "unsolicited full-screen modal must reach Suspicious; score={}",
        v.score
    );
}

// ── ClickFix / GlitchFix (E2/E9) ─────────────────────────────────────────

#[test]
fn clickfix_instruction_fires_on_alert_shaped_window() {
    let v = classify(
        &alert_window("Verify you are human — press Win+R then paste the command"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "clickfix_instruction"),
        "clickfix must fire; got {:?}",
        v.signals
    );
    assert!(v.score >= SUSPICIOUS_THRESHOLD);
}

#[test]
fn glitchfix_browser_error_fires() {
    let v = classify(
        &alert_window("Your browser stopped working — font required to continue"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "clickfix_instruction"),
        "GlitchFix must fire clickfix_instruction; got {:?}",
        v.signals
    );
}

// ── Cloud blob-storage abuse (E10) ────────────────────────────────────────

#[test]
fn azure_blob_alert_overlay_is_suspicious() {
    let w = OverlayWindow {
        title: "Critical Error".into(),
        url: Some("https://scamtenant.blob.core.windows.net/page/alert.html".into()),
        coverage_percent: 99,
        topmost: true,
        has_close_button: false,
        blocks_input: false,
        origin: Origin::Unsolicited,
        age_ms: 200,
    };
    let v = classify(&w, &Ruleset::default());
    assert!(
        v.signals.iter().any(|s| s == "cloud_storage_abuse"),
        "Azure Blob TSS must fire cloud_storage_abuse; got {:?}",
        v.signals
    );
    assert!(v.score >= SUSPICIOUS_THRESHOLD);
}

// ── Forced-retention cue (E13) ────────────────────────────────────────────

#[test]
fn forced_retention_with_geometry_reaches_suspicious() {
    let v = classify(
        &alert_window("Do not close this window — Microsoft is scanning your PC"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "forced_retention_cue"),
        "forced_retention_cue must fire; got {:?}",
        v.signals
    );
    assert!(v.score >= SUSPICIOUS_THRESHOLD);
}

// ── Credential harvest (E14) ──────────────────────────────────────────────

#[test]
fn credential_harvest_with_geometry_reaches_suspicious() {
    let v = classify(
        &alert_window("Your account has been suspended — verify your account to restore access"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "credential_harvest_cue"),
        "credential_harvest_cue must fire; got {:?}",
        v.signals
    );
    assert!(v.score >= SUSPICIOUS_THRESHOLD);
}

// ── Fake-scanner / rogue-AV (E15) ────────────────────────────────────────

#[test]
fn fake_scanner_overlay_reaches_suspicious() {
    let v = classify(
        &alert_window("Scanning for threats... 4 viruses found — do not close"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "fake_scanner_cue"),
        "fake_scanner_cue must fire; got {:?}",
        v.signals
    );
    assert!(v.score >= SUSPICIOUS_THRESHOLD);
}

#[test]
fn fake_scanner_plus_phone_reaches_block() {
    let v = classify(
        &alert_window("3 threats detected — call 1-800-555-0100 immediately"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "fake_scanner_cue"),
        "fake_scanner_cue must fire; got {:?}",
        v.signals
    );
    assert!(
        v.signals.iter().any(|s| s == "phone_number"),
        "phone_number must fire; got {:?}",
        v.signals
    );
    assert_eq!(
        v.decision,
        Decision::Block,
        "fake-scanner + phone must Block; score={} signals={:?}",
        v.score,
        v.signals
    );
}

// ── Subscription lure (E16) ───────────────────────────────────────────────

#[test]
fn subscription_lure_reaches_suspicious() {
    let v = classify(
        &alert_window("Your Norton subscription has expired — renew now to stay protected"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "subscription_lure"),
        "subscription_lure must fire; got {:?}",
        v.signals
    );
    assert!(v.score >= SUSPICIOUS_THRESHOLD);
}

// ── Authority / LEA impersonation (E17) ──────────────────────────────────

#[test]
fn authority_lure_reaches_suspicious() {
    let v = classify(
        &alert_window("FBI Warning: Your computer has been locked for illegal activity"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "authority_lure"),
        "authority_lure must fire; got {:?}",
        v.signals
    );
    assert!(v.score >= SUSPICIOUS_THRESHOLD);
}

#[test]
fn authority_lure_with_phone_reaches_block() {
    let v = classify(
        &alert_window("Cybercrime division warning: device blocked — call 1-800-555-0100"),
        &Ruleset::default(),
    );
    assert!(v.signals.iter().any(|s| s == "authority_lure"));
    assert!(v.signals.iter().any(|s| s == "phone_number"));
    assert_eq!(
        v.decision,
        Decision::Block,
        "authority_lure + phone must Block; score={} signals={:?}",
        v.score,
        v.signals
    );
}

// ── Multi-signal composite scenarios ─────────────────────────────────────

#[test]
fn full_tss_composite_reaches_block() {
    // Full-screen, no close, modal, unsolicited, new, phone number.
    // Geometry alone (30+15+25+20+25+10 = 125) reaches Block.
    let v = classify(
        &alert_window("Your PC is infected call 1-800-555-0100"),
        &Ruleset::default(),
    );
    assert_eq!(v.decision, Decision::Block, "score={}", v.score);
    assert!(v.score >= BLOCK_THRESHOLD);
}

#[test]
fn authority_plus_fake_scanner_amplifies_score() {
    // Combining two text signals on top of geometry.
    let v = classify(
        &alert_window("FBI Warning: 4 threats found on your computer — system is locked"),
        &Ruleset::default(),
    );
    assert!(v.signals.iter().any(|s| s == "authority_lure"));
    assert!(v.signals.iter().any(|s| s == "fake_scanner_cue"));
    assert_eq!(v.decision, Decision::Block);
}

// ── False-positive firewall ───────────────────────────────────────────────

#[test]
fn user_initiated_closable_window_is_allow() {
    // Same scary title but user opened it and can close it.
    let v = classify(
        &closable_window("Your computer is infected — call support"),
        &Ruleset::default(),
    );
    assert_eq!(
        v.decision,
        Decision::Allow,
        "user-initiated closable window must Allow; score={} signals={:?}",
        v.score,
        v.signals
    );
}

#[test]
fn legitimate_security_app_does_not_fire_fake_scanner() {
    // User opened a real AV scan result; closable, user-initiated.
    let v = classify(
        &closable_window("Scan complete: 0 threats found — your PC is clean"),
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "fake_scanner_cue"),
        "fake_scanner_cue must not fire for user-initiated AV result; got {:?}",
        v.signals
    );
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn news_article_authority_does_not_fire() {
    // Browser tab showing news article: "FBI Warning: New Phishing Attack".
    let v = classify(
        &closable_window("FBI warning new phishing campaign targets bank customers"),
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "authority_lure"),
        "authority_lure must not fire for news article; got {:?}",
        v.signals
    );
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn legitimate_renewal_reminder_does_not_fire() {
    // User navigated to a subscription renewal page.
    let v = classify(
        &closable_window("Your subscription has expired — renew now"),
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "subscription_lure"),
        "subscription_lure must not fire for user-initiated renewal page; got {:?}",
        v.signals
    );
}

// ── Homoglyph / leet evasion resistance ──────────────────────────────────

#[test]
fn homoglyph_phone_number_still_fires() {
    // Cyrillic chars in the title don't defeat phone detection.
    let v = classify(
        &alert_window("уоur computer іs infected call 1-800-555-0100"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "phone_number")
            || v.signals.iter().any(|s| s == "mixed_script"),
        "homoglyph title must fire phone_number or mixed_script; got {:?}",
        v.signals
    );
    assert!(v.score >= SUSPICIOUS_THRESHOLD);
}

#[test]
fn leet_fake_scanner_still_fires() {
    // "v1rus" → "virus", "thr34ts" → "threats" after normalize_for_match.
    let v = classify(
        &alert_window("sc4nning for v1rus3s — 3 thr34ts detected"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "fake_scanner_cue"),
        "leet-coded fake_scanner_cue must still fire; got {:?}",
        v.signals
    );
}

#[test]
fn crypto_wallet_alarm_reaches_suspicious() {
    // Wallet-alarm pattern: wallet word + compromise token, alert-shaped.
    // Groundings: FBI IC3 2025 crypto investment fraud #1 ($4.57B losses).
    let v = classify(
        &alert_window("your wallet has been compromised click here to secure"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "crypto_drain_lure"),
        "expected crypto_drain_lure; got {:?}",
        v.signals
    );
    assert!(v.score >= SUSPICIOUS_THRESHOLD);
}

#[test]
fn seed_phrase_harvest_reaches_suspicious() {
    // seed_harvest pattern: seed phrase + required → in an alert-shaped window.
    let v = classify(
        &alert_window("seed phrase verification required to restore your wallet"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "crypto_drain_lure"),
        "expected crypto_drain_lure for seed-phrase lure; got {:?}",
        v.signals
    );
    assert!(v.score >= SUSPICIOUS_THRESHOLD);
}

#[test]
fn crypto_news_article_does_not_fire() {
    // FP guard: a news article about a crypto hack in a user-opened, closable tab.
    let v = classify(
        &closable_window("coinbase wallet hacked 200m compromised security researchers"),
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "crypto_drain_lure"),
        "crypto_drain_lure must not fire for user-initiated closable tab; got {:?}",
        v.signals
    );
}

#[test]
fn prize_lure_reaches_suspicious() {
    // Prize + claim action in an alert-shaped window.
    // Grounding: FTC 2024 imposter & prize scams #2 category by reports.
    let v = classify(
        &alert_window("congratulations you have won a prize claim it before it expires"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "prize_lure"),
        "expected prize_lure; got {:?}",
        v.signals
    );
    assert!(v.score >= SUSPICIOUS_THRESHOLD);
}

#[test]
fn legitimate_loyalty_notification_does_not_fire_prize_lure() {
    // FP guard: loyalty-program reward notification in user-opened, closable tab.
    let v = classify(
        &closable_window("you have earned 500 reward points eligible for a free reward claim"),
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "prize_lure"),
        "prize_lure must not fire for user-initiated closable window; got {:?}",
        v.signals
    );
}

#[test]
fn download_trap_reaches_suspicious() {
    // Fake plugin gate in an alert-shaped window.
    // Groundings: Microsoft Edge security team (2025 fake-update malware);
    // FBI IC3 2024 malware-delivery overlays.
    let v = classify(
        &alert_window("flash player update required to view this content"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "download_trap_lure"),
        "expected download_trap_lure; got {:?}",
        v.signals
    );
    assert!(v.score >= SUSPICIOUS_THRESHOLD);
}

#[test]
fn legitimate_extension_install_does_not_fire_download_trap() {
    // FP guard: user-opened, closable browser extension install prompt.
    let v = classify(
        &closable_window("install extension to enable developer tools"),
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "download_trap_lure"),
        "download_trap_lure must not fire for user-initiated closable prompt; got {:?}",
        v.signals
    );
}

#[test]
fn crypto_drain_plus_phone_reaches_block() {
    // crypto_drain_lure + phone_number: two independent signals both fire →
    // combined score should exceed Block threshold.
    // Grounding: FBI IC3 2025 — crypto scam overlays often include a
    // "call support" phone number alongside the wallet alarm.
    let v = classify(
        &alert_window("your wallet has been compromised call 1-800-555-0100 to secure your funds"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "crypto_drain_lure"),
        "expected crypto_drain_lure; got {:?}",
        v.signals
    );
    assert!(
        v.signals.iter().any(|s| s == "phone_number"),
        "expected phone_number; got {:?}",
        v.signals
    );
    assert!(
        v.score >= BLOCK_THRESHOLD,
        "crypto_drain_lure + phone_number must reach Block; score = {}",
        v.score
    );
}

#[test]
fn prize_lure_plus_phone_reaches_block() {
    // prize_lure + phone_number: classic sweepstakes scam with call-in lure.
    let v = classify(
        &alert_window("congratulations you have won a prize call 1-800-555-0100 to claim now"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "prize_lure"),
        "expected prize_lure; got {:?}",
        v.signals
    );
    assert!(
        v.signals.iter().any(|s| s == "phone_number"),
        "expected phone_number; got {:?}",
        v.signals
    );
    assert!(
        v.score >= BLOCK_THRESHOLD,
        "prize_lure + phone_number must reach Block; score = {}",
        v.score
    );
}

#[test]
fn authority_lure_plus_crypto_drain_amplifies_score() {
    // Ransomware-bluff variant: LEA impersonation + wallet drain in one overlay.
    let v = classify(
        &alert_window("cybercrime unit warning your wallet has been flagged for illegal activity"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "authority_lure"),
        "expected authority_lure; got {:?}",
        v.signals
    );
    assert!(
        v.signals.iter().any(|s| s == "crypto_drain_lure"),
        "expected crypto_drain_lure; got {:?}",
        v.signals
    );
    assert!(
        v.score >= BLOCK_THRESHOLD,
        "authority_lure + crypto_drain_lure must reach Block; score = {}",
        v.score
    );
}

// ── E22: qr_code_lure ─────────────────────────────────────────────────────

#[test]
fn qr_code_lure_reaches_suspicious() {
    let v = classify(
        &alert_window("scan qr code to verify your identity"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "qr_code_lure"),
        "expected qr_code_lure; got {:?}",
        v.signals
    );
    assert!(
        v.score >= SUSPICIOUS_THRESHOLD,
        "qr_code_lure must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn legitimate_qr_display_does_not_fire_qr_code_lure() {
    // E-ticket / boarding-pass QR: user-initiated, closable, low coverage.
    let v = classify(
        &muten_overlay::OverlayWindow {
            title: "show your qr code at the gate".into(),
            url: None,
            coverage_percent: 20,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        },
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "qr_code_lure"),
        "qr_code_lure must not fire on user-initiated QR display; got {:?}",
        v.signals
    );
}

#[test]
fn qr_code_lure_plus_phone_reaches_block() {
    // Quishing overlay with phone: "scan QR or call 1-800-555-0100 to verify".
    let v = classify(
        &alert_window("scan qr code to verify your account or call 1-800-555-0100"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "qr_code_lure"),
        "expected qr_code_lure; got {:?}",
        v.signals
    );
    assert!(
        v.signals.iter().any(|s| s == "phone_number"),
        "expected phone_number; got {:?}",
        v.signals
    );
    assert!(
        v.score >= BLOCK_THRESHOLD,
        "qr_code_lure + phone_number must reach Block; score = {}",
        v.score
    );
}

// ── E23: ip_alarm_lure ────────────────────────────────────────────────────

#[test]
fn ip_alarm_lure_reaches_suspicious() {
    let v = classify(
        &alert_window("your ip address has been hacked contact support"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "ip_alarm_lure"),
        "expected ip_alarm_lure; got {:?}",
        v.signals
    );
    assert!(
        v.score >= SUSPICIOUS_THRESHOLD,
        "ip_alarm_lure must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn ip_info_page_does_not_fire_ip_alarm_lure() {
    // Legitimate "what is my IP" page: user-initiated, closable, no alarm word.
    let v = classify(
        &muten_overlay::OverlayWindow {
            title: "your ip address is 203.0.113.45".into(),
            url: None,
            coverage_percent: 15,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 3_000,
        },
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "ip_alarm_lure"),
        "ip_alarm_lure must not fire on user-initiated IP info page; got {:?}",
        v.signals
    );
}

#[test]
fn ip_alarm_lure_plus_phone_reaches_block() {
    let v = classify(
        &alert_window("your ip address has been flagged call 1-800-555-0100 immediately"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "ip_alarm_lure"),
        "expected ip_alarm_lure; got {:?}",
        v.signals
    );
    assert!(
        v.signals.iter().any(|s| s == "phone_number"),
        "expected phone_number; got {:?}",
        v.signals
    );
    assert!(
        v.score >= BLOCK_THRESHOLD,
        "ip_alarm_lure + phone_number must reach Block; score = {}",
        v.score
    );
}

// ── Geometry-only bounded-composite regression guards ─────────────────────

#[test]
fn sudden_fullscreen_takeover_alone_stays_suspicious_not_block() {
    // An unsolicited, brand-new, full-screen, always-on-top window with NO
    // content/provenance tell (no title, no URL, no phone number) must NOT
    // reach Block — the geometry shape is bounded to preserve observe-first.
    let v = classify(
        &muten_overlay::OverlayWindow {
            title: "".into(),
            url: None,
            coverage_percent: 99,
            topmost: true,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 50, // very_new: appeared 50 ms ago
        },
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "sudden_fullscreen_takeover"),
        "expected sudden_fullscreen_takeover; got {:?}",
        v.signals
    );
    assert!(
        v.score < BLOCK_THRESHOLD,
        "geometry-only sudden_fullscreen_takeover must stay below Block; score = {}",
        v.score
    );
}

#[test]
fn sudden_fullscreen_takeover_plus_phone_reaches_block() {
    // The same shape WITH a phone number — a content tell — pushes past Block.
    let v = classify(
        &muten_overlay::OverlayWindow {
            title: "call 1-800-555-0100 for support".into(),
            url: None,
            coverage_percent: 99,
            topmost: true,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 50,
        },
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "sudden_fullscreen_takeover"),
        "expected sudden_fullscreen_takeover; got {:?}",
        v.signals
    );
    assert!(
        v.signals.iter().any(|s| s == "phone_number"),
        "expected phone_number; got {:?}",
        v.signals
    );
    assert!(
        v.score >= BLOCK_THRESHOLD,
        "sudden_fullscreen_takeover + phone_number must reach Block; score = {}",
        v.score
    );
}

// ── E24: package_fee_lure ─────────────────────────────────────────────────

#[test]
fn package_fee_lure_reaches_suspicious() {
    let v = classify(
        &alert_window("your package is on hold customs fee required to release"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "package_fee_lure"),
        "expected package_fee_lure; got {:?}",
        v.signals
    );
    assert!(
        v.score >= SUSPICIOUS_THRESHOLD,
        "package_fee_lure must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn legitimate_order_notification_does_not_fire_package_fee_lure() {
    let v = classify(
        &muten_overlay::OverlayWindow {
            title: "your order has been shipped and is on its way".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        },
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "package_fee_lure"),
        "package_fee_lure must not fire on user-initiated order notification; got {:?}",
        v.signals
    );
}

#[test]
fn package_fee_lure_plus_phone_reaches_block() {
    let v = classify(
        &alert_window("your shipment is on hold call 1-800-555-0100 to pay customs fee"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "package_fee_lure"),
        "expected package_fee_lure; got {:?}",
        v.signals
    );
    assert!(
        v.signals.iter().any(|s| s == "phone_number"),
        "expected phone_number; got {:?}",
        v.signals
    );
    assert!(
        v.score >= BLOCK_THRESHOLD,
        "package_fee_lure + phone_number must reach Block; score = {}",
        v.score
    );
}

// ── E25: sextortion_lure ──────────────────────────────────────────────────

#[test]
fn sextortion_lure_reaches_suspicious() {
    let v = classify(
        &alert_window("we have recorded you send bitcoin to prevent release to your contacts"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "sextortion_lure"),
        "expected sextortion_lure; got {:?}",
        v.signals
    );
    assert!(
        v.score >= SUSPICIOUS_THRESHOLD,
        "sextortion_lure must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn webcam_permission_dialog_does_not_fire_sextortion_lure() {
    let v = classify(
        &muten_overlay::OverlayWindow {
            title: "allow your camera for this video call".into(),
            url: None,
            coverage_percent: 25,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 2_000,
        },
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "sextortion_lure"),
        "sextortion_lure must not fire for user-initiated webcam dialog; got {:?}",
        v.signals
    );
}

#[test]
fn sextortion_lure_reaches_block_with_unsolicited_fullscreen() {
    // Alert-shaped unsolicited sextortion overlay should reach Block via
    // score accumulation (sextortion_lure + fullscreen + topmost + unsolicited).
    let v = classify(
        &alert_window(
            "your webcam was accessed send btc payment to prevent this from going to your contacts",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "sextortion_lure"),
        "expected sextortion_lure; got {:?}",
        v.signals
    );
    assert!(
        v.score >= BLOCK_THRESHOLD,
        "alert-shaped sextortion_lure must reach Block; score = {}",
        v.score
    );
}

// ── E26: gift_card_demand ─────────────────────────────────────────────────

#[test]
fn gift_card_demand_reaches_suspicious() {
    let v = classify(
        &alert_window("please purchase gift cards and send codes to unlock your computer"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "gift_card_demand"),
        "expected gift_card_demand; got {:?}",
        v.signals
    );
    assert!(
        v.score >= SUSPICIOUS_THRESHOLD,
        "gift_card_demand must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn legitimate_gift_card_store_does_not_fire_gift_card_demand() {
    let v = classify(
        &muten_overlay::OverlayWindow {
            title: "check your amazon gift card balance".into(),
            url: None,
            coverage_percent: 25,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 2_000,
        },
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "gift_card_demand"),
        "gift_card_demand must not fire for user-initiated gift-card page; got {:?}",
        v.signals
    );
}

#[test]
fn gift_card_demand_plus_phone_reaches_block() {
    let v = classify(
        &alert_window(
            "go to the nearest store buy gift cards call 1-800-555-0199 send codes to fix virus",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "gift_card_demand"),
        "expected gift_card_demand; got {:?}",
        v.signals
    );
    assert!(
        v.signals.iter().any(|s| s == "phone_number"),
        "expected phone_number; got {:?}",
        v.signals
    );
    assert!(
        v.score >= BLOCK_THRESHOLD,
        "gift_card_demand + phone must reach Block; score = {}",
        v.score
    );
}
