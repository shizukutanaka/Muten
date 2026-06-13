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

#[test]
fn japanese_forced_retention_reaches_suspicious() {
    // The iconic JP サポート詐欺 retention overlay phrase.
    let v = classify(
        &alert_window("この画面を閉じないでください ウイルスを検出しました"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "forced_retention_cue"),
        "JP forced_retention_cue must fire; got {:?}",
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

#[test]
fn japanese_credential_harvest_reaches_suspicious() {
    // JP phishing overlay: account suspended + verify instruction.
    let v = classify(
        &alert_window("アカウントが停止されました 今すぐ本人確認を行ってください"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "credential_harvest_cue"),
        "JP credential_harvest_cue must fire; got {:?}",
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

#[test]
fn japanese_fake_scanner_reaches_suspicious() {
    // JP rogue-AV progress overlay: threat detection + repair framing.
    let v = classify(
        &alert_window("脅威が見つかりました システムを修復しています 電源を切らないで"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "fake_scanner_cue"),
        "JP fake_scanner_cue must fire; got {:?}",
        v.signals
    );
    assert!(v.score >= SUSPICIOUS_THRESHOLD);
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

#[test]
fn japanese_police_impersonation_reaches_suspicious() {
    // 警察庁 (NPA) impersonation overlay — IPA-documented サポート詐欺 /
    // 警察なりすまし詐欺 pattern targeting the JP market.
    let v = classify(
        &alert_window("警察庁からの警告 あなたのコンピュータはロックされました"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "authority_lure"),
        "JP authority_lure must fire; got {:?}",
        v.signals
    );
    assert!(v.score >= SUSPICIOUS_THRESHOLD);
}

#[test]
fn legitimate_japanese_police_notice_does_not_fire() {
    // Legitimate NPA traffic-safety notice, user-opened and closable — the
    // alert_shaped guard + benign wording must keep authority_lure silent.
    let v = classify(
        &closable_window("警察庁 交通安全週間のお知らせ"),
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "authority_lure"),
        "benign JP police notice must not fire authority_lure; got {:?}",
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

// ── E27: refund_scam_cue ──────────────────────────────────────────────────

#[test]
fn refund_scam_reaches_suspicious() {
    let v = classify(
        &alert_window("a refund of $499 is owed to you — call our agent to collect"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "refund_scam_cue"),
        "expected refund_scam_cue; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "refund_scam_cue must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn legitimate_refund_confirmation_does_not_fire_refund_scam() {
    // Ordinary e-commerce refund confirmation — user-initiated, closable, small.
    let v = classify(
        &closable_window("your refund of $29 has been processed — thank you for your purchase"),
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "refund_scam_cue"),
        "refund_scam_cue must not fire for legitimate refund confirmation; got {:?}",
        v.signals
    );
}

#[test]
fn jp_refund_scam_reaches_suspicious() {
    let v = classify(
        &alert_window("返金が完了しました。お手続きください。サポートに電話してください。"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "refund_scam_cue"),
        "expected refund_scam_cue for JP refund lure; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP refund_scam_cue must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn refund_scam_plus_phone_reaches_block() {
    let v = classify(
        &alert_window(
            "overpayment of $399 owed to you — call 1-800-555-0100 to collect your refund",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "refund_scam_cue"),
        "expected refund_scam_cue; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "refund_scam_cue + phone must reach Block; score = {}",
        v.score
    );
}

// ── E28: national_id_alarm ────────────────────────────────────────────────

#[test]
fn ssn_suspended_scam_reaches_suspicious() {
    let v = classify(
        &alert_window("your social security number has been suspended — call immediately"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "national_id_alarm"),
        "expected national_id_alarm; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "national_id_alarm must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn legitimate_ssa_benefits_page_does_not_fire() {
    let v = classify(
        &closable_window("social security benefits overview — my ssa account"),
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "national_id_alarm"),
        "national_id_alarm must not fire on legit SSA benefits page; got {:?}",
        v.signals
    );
}

#[test]
fn jp_my_number_scam_reaches_suspicious() {
    let v = classify(
        &alert_window("マイナンバーが不正使用されました。捜査中です。"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "national_id_alarm"),
        "expected national_id_alarm for JP マイナンバー scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP national_id_alarm must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn ssn_scam_plus_phone_reaches_block() {
    let v = classify(
        &alert_window("ssn used in criminal activity call 1-800-555-0100 to reactivate"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "national_id_alarm"),
        "expected national_id_alarm; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "national_id_alarm + phone must reach Block; score = {}",
        v.score
    );
}

// ── E29: bank_account_alarm ───────────────────────────────────────────────

#[test]
fn bank_account_frozen_reaches_suspicious() {
    let v = classify(
        &alert_window(
            "your bank account has been frozen — unauthorized transaction detected call now",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "bank_account_alarm"),
        "expected bank_account_alarm; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "bank_account_alarm must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn legitimate_bank_app_does_not_fire_bank_alarm() {
    let v = classify(
        &closable_window("your bank account overview — recent transactions"),
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "bank_account_alarm"),
        "bank_account_alarm must not fire on legit bank overview; got {:?}",
        v.signals
    );
}

#[test]
fn jp_bank_alarm_reaches_suspicious() {
    let v = classify(
        &alert_window("銀行口座に不正な取引が検出されました。口座が停止されました。"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "bank_account_alarm"),
        "expected bank_account_alarm for JP bank alarm; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP bank_account_alarm must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn bank_alarm_plus_phone_reaches_block() {
    let v = classify(
        &alert_window("credit card fraudulent charge detected call 1-800-555-0100 to dispute"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "bank_account_alarm"),
        "expected bank_account_alarm; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "bank_account_alarm + phone must reach Block; score = {}",
        v.score
    );
}

// ── E30: false_registration_billing ──────────────────────────────────────────

#[test]
fn false_reg_billing_reaches_suspicious() {
    let v = classify(
        &alert_window(
            "your registration is complete — pay within 72 hours or legal action will follow",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "false_registration_billing"),
        "expected false_registration_billing; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "false_registration_billing must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn legitimate_order_confirmation_does_not_fire_false_reg_billing() {
    // Legitimate e-commerce: closable, user-initiated, low coverage
    let v = classify(
        &OverlayWindow {
            title: "order confirmed — thanks for your purchase! your registration is complete"
                .into(),
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
        !v.signals.iter().any(|s| s == "false_registration_billing"),
        "false_registration_billing must not fire on closable order confirmation; got {:?}",
        v.signals
    );
}

#[test]
fn jp_false_reg_billing_reaches_suspicious() {
    let v = classify(
        &alert_window(
            "会員登録が完了しました。未払いの場合は法的措置を取ります。ご請求金額：¥29800",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "false_registration_billing"),
        "expected false_registration_billing for JP ワンクリック詐欺; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP false_registration_billing must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn false_reg_billing_plus_phone_reaches_block() {
    let v = classify(
        &alert_window(
            "membership confirmed — outstanding fee $199 — failure to pay — call 1-800-555-0100",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "false_registration_billing"),
        "expected false_registration_billing; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "false_registration_billing + phone must reach Block; score = {}",
        v.score
    );
}

// ── E31: fake_bsod_lure ───────────────────────────────────────────────────────

#[test]
fn fake_bsod_reaches_suspicious() {
    let v = classify(
        &alert_window(
            "stop code: memory_management — do not restart — call microsoft support 1-800-555-0100",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "fake_bsod_lure"),
        "expected fake_bsod_lure; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "fake_bsod_lure must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn legitimate_bsod_article_does_not_fire() {
    // IT blog: mentions blue screen but user-initiated and closable
    let v = classify(
        &OverlayWindow {
            title: "how to fix blue screen errors and stop codes in windows 10".into(),
            url: None,
            coverage_percent: 12,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 8_000,
        },
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "fake_bsod_lure"),
        "fake_bsod_lure must not fire on IT troubleshooting page; got {:?}",
        v.signals
    );
}

#[test]
fn jp_fake_bsod_reaches_suspicious() {
    let v = classify(
        &alert_window(
            "ブルースクリーンが発生しました。再起動しないでください。マイクロソフトサポートに電話してください。",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "fake_bsod_lure"),
        "expected fake_bsod_lure for JP BSOD scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP fake_bsod_lure must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn fake_bsod_plus_phone_reaches_block() {
    let v = classify(
        &alert_window(
            "windows has been blocked call microsoft certified technician 1-800-555-0100",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "fake_bsod_lure"),
        "expected fake_bsod_lure; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "fake_bsod_lure + phone must reach Block; score = {}",
        v.score
    );
}

// ── E32: advance_fee_lure ─────────────────────────────────────────────────────

#[test]
fn advance_fee_reaches_suspicious() {
    let v = classify(
        &alert_window(
            "you are a beneficiary of the estate of a deceased customer advance fee required to release the funds",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "advance_fee_lure"),
        "expected advance_fee_lure; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "advance_fee_lure must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn legitimate_estate_notice_does_not_fire_advance_fee() {
    // Legitimate estate attorney page: closable, user-initiated
    let v = classify(
        &OverlayWindow {
            title: "you are listed as a beneficiary of the estate — contact our office".into(),
            url: None,
            coverage_percent: 12,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 4_000,
        },
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "advance_fee_lure"),
        "advance_fee_lure must not fire on legitimate estate page; got {:?}",
        v.signals
    );
}

#[test]
fn jp_advance_fee_reaches_suspicious() {
    let v = classify(
        &alert_window("遺産の受益者に選ばれました。受け取るには手数料をお支払いください。"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "advance_fee_lure"),
        "expected advance_fee_lure for JP 419 scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP advance_fee_lure must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn advance_fee_plus_phone_reaches_block() {
    let v = classify(
        &alert_window(
            "unclaimed inheritance processing fee to unlock your funds call 1-800-555-0100",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "advance_fee_lure"),
        "expected advance_fee_lure; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "advance_fee_lure + phone must reach Block; score = {}",
        v.score
    );
}

// ── E33: tech_support_invoice_scam ───────────────────────────────────────────

#[test]
fn tech_invoice_scam_reaches_suspicious() {
    let v = classify(
        &alert_window(
            "you have been charged $499 norton subscription renewal call to cancel 1-800-555-0100",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "tech_support_invoice_scam"),
        "expected tech_support_invoice_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "tech_support_invoice_scam must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn legitimate_invoice_notification_does_not_fire() {
    // Legitimate billing email shown in a closable, user-initiated window
    let v = classify(
        &OverlayWindow {
            title: "billing confirmation — your subscription has been renewed — thank you".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 3_000,
        },
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "tech_support_invoice_scam"),
        "tech_support_invoice_scam must not fire on user-initiated invoice; got {:?}",
        v.signals
    );
}

#[test]
fn jp_tech_invoice_reaches_suspicious() {
    let v = classify(
        &alert_window("自動更新料金¥49800が課金されました。キャンセルするには電話してください。"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "tech_support_invoice_scam"),
        "expected tech_support_invoice_scam for JP billing scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP tech_support_invoice_scam must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn tech_invoice_plus_phone_reaches_block() {
    let v = classify(
        &alert_window(
            "a charge of $599 mcafee total protection — if you did not authorize call 1-800-555-0100",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "tech_support_invoice_scam"),
        "expected tech_support_invoice_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "tech_support_invoice_scam + phone must reach Block; score = {}",
        v.score
    );
}

// ── E34: utility_cutoff_threat ────────────────────────────────────────────────

#[test]
fn utility_cutoff_reaches_suspicious() {
    let v = classify(
        &alert_window(
            "final notice — your electricity service will be disconnected in 2 hours — avoid disconnection pay now",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "utility_cutoff_threat"),
        "expected utility_cutoff_threat; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "utility_cutoff_threat must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn legitimate_utility_portal_does_not_fire() {
    let v = classify(
        &OverlayWindow {
            title: "electricity account summary — current balance due — thank you".into(),
            url: None,
            coverage_percent: 12,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        },
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "utility_cutoff_threat"),
        "utility_cutoff_threat must not fire on legitimate utility portal; got {:?}",
        v.signals
    );
}

#[test]
fn jp_utility_cutoff_reaches_suspicious() {
    let v = classify(
        &alert_window(
            "電気の停止予告です。料金未払いのため供給停止となります。即時お支払いください。",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "utility_cutoff_threat"),
        "expected utility_cutoff_threat for JP utility scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP utility_cutoff_threat must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn utility_cutoff_plus_phone_reaches_block() {
    let v = classify(
        &alert_window(
            "gas service will be shut off today — pay to avoid disconnection — call 1-800-555-0100",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "utility_cutoff_threat"),
        "expected utility_cutoff_threat; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "utility_cutoff_threat + phone must reach Block; score = {}",
        v.score
    );
}

// ── E35: healthcare_scam ──────────────────────────────────────────────────────

#[test]
fn healthcare_scam_reaches_suspicious() {
    let v = classify(
        &alert_window(
            "your medicare benefits will expire — call to claim your free medical device",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "healthcare_scam"),
        "expected healthcare_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "healthcare_scam must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn legitimate_insurance_portal_does_not_fire_healthcare() {
    let v = classify(
        &OverlayWindow {
            title: "your medicare account — view benefits and claims summary".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 4_000,
        },
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "healthcare_scam"),
        "healthcare_scam must not fire on legitimate Medicare portal; got {:?}",
        v.signals
    );
}

#[test]
fn jp_healthcare_scam_reaches_suspicious() {
    let v = classify(
        &alert_window("健康保険の受給期限が近づいています。無料で受け取るにはお電話ください。"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "healthcare_scam"),
        "expected healthcare_scam for JP healthcare scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP healthcare_scam must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn healthcare_scam_plus_phone_reaches_block() {
    let v = classify(
        &alert_window(
            "medicare enrollment period ends soon you have been approved free of charge call 1-800-555-0100",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "healthcare_scam"),
        "expected healthcare_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "healthcare_scam + phone must reach Block; score = {}",
        v.score
    );
}

// ── E36: job_scam ─────────────────────────────────────────────────────────────

#[test]
fn job_scam_reaches_suspicious() {
    let v = classify(
        &alert_window(
            "work from home opportunity — easy money — registration fee required to start today",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "job_scam"),
        "expected job_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "job_scam must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn legitimate_job_listing_does_not_fire_job_scam() {
    let v = classify(
        &OverlayWindow {
            title: "work from home — remote work opportunity — apply now — no fee required".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 3_000,
        },
        &Ruleset::default(),
    );
    assert!(
        !v.signals.iter().any(|s| s == "job_scam"),
        "job_scam must not fire on legitimate job listing; got {:?}",
        v.signals
    );
}

#[test]
fn jp_job_scam_reaches_suspicious() {
    let v = classify(
        &alert_window("在宅ワークで高収入。副業募集中。登録料3000円が必要です。"),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "job_scam"),
        "expected job_scam for JP employment fraud; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP job_scam must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn job_scam_plus_phone_reaches_block() {
    let v = classify(
        &alert_window(
            "data entry job work from home — equipment deposit required — call 1-800-555-0100",
        ),
        &Ruleset::default(),
    );
    assert!(
        v.signals.iter().any(|s| s == "job_scam"),
        "expected job_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "job_scam + phone must reach Block; score = {}",
        v.score
    );
}

// ── E37: tax_authority_scam ──────────────────────────────────────────────────

#[test]
fn tax_authority_scam_fires_on_alert_shaped_window() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "irs notice: unpaid taxes — arrest warrant issued — call immediately".into(),
            url: None,
            coverage_percent: 95,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 150,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "tax_authority_scam"),
        "expected tax_authority_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 30,
        "tax_authority_scam must contribute at least W=30; score = {}",
        v.score
    );
}

#[test]
fn tax_authority_scam_fp_guard_no_alert_shape() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "irs notice: back taxes overdue — arrest warrant issued for suspect".into(),
            url: None,
            coverage_percent: 15,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 8_000,
        },
        &rules,
    );
    assert!(
        !v.signals.iter().any(|s| s == "tax_authority_scam"),
        "tax_authority_scam must not fire without alert_shape; got {:?}",
        v.signals
    );
}

#[test]
fn jp_tax_authority_scam_reaches_suspicious() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "国税庁通知：延滞税未払い。逮捕状が発行されました。即座にお支払いください。"
                .into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "tax_authority_scam"),
        "expected tax_authority_scam for JP IRS impostor; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP tax_authority_scam must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn tax_authority_scam_plus_phone_reaches_block() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "irs notice: tax debt — arrest warrant — call 1-800-555-0191 immediately".into(),
            url: None,
            coverage_percent: 95,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 150,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "tax_authority_scam"),
        "expected tax_authority_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "tax_authority_scam + phone must reach Block; score = {}",
        v.score
    );
}

// ── E38: social_media_account_alarm ─────────────────────────────────────────

#[test]
fn social_media_account_alarm_fires_on_alert_shaped_window() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "your facebook account has been hacked — verify to recover access immediately"
                .into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "social_media_account_alarm"),
        "expected social_media_account_alarm; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 25,
        "social_media_account_alarm must contribute at least W=25; score = {}",
        v.score
    );
}

#[test]
fn social_media_account_alarm_fp_guard_no_alert_shape() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "instagram account has been suspended — click to restore".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        },
        &rules,
    );
    assert!(
        !v.signals.iter().any(|s| s == "social_media_account_alarm"),
        "social_media_account_alarm must not fire without alert_shape; got {:?}",
        v.signals
    );
}

#[test]
fn jp_social_media_account_alarm_reaches_suspicious() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "ラインアカウントが乗っ取られました。アカウントを回復するにはこちらをクリック。"
                .into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "social_media_account_alarm"),
        "expected social_media_account_alarm for JP LINE hijacking; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP social_media_account_alarm must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn social_media_account_alarm_plus_phone_reaches_block() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "google account unusual login — someone accessed your account — call 1-800-555-0192 to regain access".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 150,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "social_media_account_alarm"),
        "expected social_media_account_alarm; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "social_media_account_alarm + phone must reach Block; score = {}",
        v.score
    );
}

// ── E39: immigration_visa_scam ───────────────────────────────────────────────

#[test]
fn immigration_visa_scam_fires_on_alert_shaped_window() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "immigration notice: your visa has been revoked — face deportation — pay renewal fee now".into(),
            url: None,
            coverage_percent: 92,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 180,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "immigration_visa_scam"),
        "expected immigration_visa_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 25,
        "immigration_visa_scam must contribute at least W=25; score = {}",
        v.score
    );
}

#[test]
fn immigration_visa_scam_fp_guard_no_alert_shape() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "your work permit has been cancelled — illegal overstay — renewal fee required"
                .into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        },
        &rules,
    );
    assert!(
        !v.signals.iter().any(|s| s == "immigration_visa_scam"),
        "immigration_visa_scam must not fire without alert_shape; got {:?}",
        v.signals
    );
}

#[test]
fn jp_immigration_visa_scam_reaches_suspicious() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title:
                "入国管理局：在留資格が取り消しになりました。強制送還を避けるには更新料が必要です。"
                    .into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "immigration_visa_scam"),
        "expected immigration_visa_scam for JP visa impostor; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP immigration_visa_scam must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn immigration_visa_scam_plus_phone_reaches_block() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "customs and border protection: your green card has expired — illegal overstay — call 1-800-555-0193 for renewal fee".into(),
            url: None,
            coverage_percent: 92,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 150,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "immigration_visa_scam"),
        "expected immigration_visa_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "immigration_visa_scam + phone must reach Block; score = {}",
        v.score
    );
}

// ── E40: government_grant_scam ───────────────────────────────────────────────

#[test]
fn government_grant_scam_fires_on_alert_shaped_window() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "federal grant approved — verify your identity to receive — application fee required".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "government_grant_scam"),
        "expected government_grant_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 25,
        "government_grant_scam must contribute at least W=25; score = {}",
        v.score
    );
}

#[test]
fn government_grant_scam_fp_guard_no_alert_shape() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "government grant — stimulus check — apply before the deadline — enrollment deadline".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 8_000,
        },
        &rules,
    );
    assert!(
        !v.signals.iter().any(|s| s == "government_grant_scam"),
        "government_grant_scam must not fire without alert_shape; got {:?}",
        v.signals
    );
}

#[test]
fn jp_government_grant_scam_reaches_suspicious() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "政府給付金のお知らせ：今すぐ申請すれば10万円受け取れます。手数料が必要です。"
                .into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "government_grant_scam"),
        "expected government_grant_scam for JP stimulus impostor; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP government_grant_scam must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn government_grant_scam_plus_phone_reaches_block() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "federal grant: $10,000 emergency relief fund — claim your grant — call 1-800-555-0194 — application fee required".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 150,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "government_grant_scam"),
        "expected government_grant_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "government_grant_scam + phone must reach Block; score = {}",
        v.score
    );
}

// ── E41: debt_relief_scam ────────────────────────────────────────────────────

#[test]
fn debt_relief_scam_fires_on_alert_shaped_window() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "debt relief program: eliminate your debt — guaranteed approval — no credit check required".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "debt_relief_scam"),
        "expected debt_relief_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 25,
        "debt_relief_scam must contribute at least W=25; score = {}",
        v.score
    );
}

#[test]
fn debt_relief_scam_fp_guard_no_alert_shape() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "debt consolidation — credit card debt — stop paying now — guaranteed approval"
                .into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        },
        &rules,
    );
    assert!(
        !v.signals.iter().any(|s| s == "debt_relief_scam"),
        "debt_relief_scam must not fire without alert_shape; got {:?}",
        v.signals
    );
}

#[test]
fn jp_debt_relief_scam_reaches_suspicious() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "借金の悩み解決。債務整理のご相談。確実に解決します。着手金が必要です。".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "debt_relief_scam"),
        "expected debt_relief_scam for JP debt impostor; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP debt_relief_scam must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn debt_relief_scam_plus_phone_reaches_block() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "credit card debt relief program — guaranteed approval — call 1-800-555-0195 — processing fee required".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 150,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "debt_relief_scam"),
        "expected debt_relief_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "debt_relief_scam + phone must reach Block; score = {}",
        v.score
    );
}

// ── E42: streaming_billing_scam ──────────────────────────────────────────────

#[test]
fn streaming_billing_scam_fires_on_alert_shaped_window() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "netflix: your payment failed — update your payment method immediately".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "streaming_billing_scam"),
        "expected streaming_billing_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 25,
        "streaming_billing_scam must contribute at least W=25; score = {}",
        v.score
    );
}

#[test]
fn streaming_billing_scam_fp_guard_no_alert_shape() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "spotify: payment declined — billing issue — update your payment".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        },
        &rules,
    );
    assert!(
        !v.signals.iter().any(|s| s == "streaming_billing_scam"),
        "streaming_billing_scam must not fire without alert_shape; got {:?}",
        v.signals
    );
}

#[test]
fn jp_streaming_billing_scam_reaches_suspicious() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title:
                "ネットフリックスよりお知らせ：お支払いが失敗しました。支払い情報の更新が必要です。"
                    .into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "streaming_billing_scam"),
        "expected streaming_billing_scam for JP Netflix impostor; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP streaming_billing_scam must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn streaming_billing_scam_plus_phone_reaches_block() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "amazon prime: payment failed — billing issue — call 1-800-555-0196 to update payment method".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 150,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "streaming_billing_scam"),
        "expected streaming_billing_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "streaming_billing_scam + phone must reach Block; score = {}",
        v.score
    );
}

// ── E43: traffic_fine_scam ───────────────────────────────────────────────────

#[test]
fn traffic_fine_scam_fires_on_alert_shaped_window() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "parking violation notice — overdue fine — pay within 24 hours — avoid license suspension".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "traffic_fine_scam"),
        "expected traffic_fine_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 25,
        "traffic_fine_scam must contribute at least W=25; score = {}",
        v.score
    );
}

#[test]
fn traffic_fine_scam_fp_guard_no_alert_shape() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "ezpass: unpaid toll balance — pay immediately — to avoid suspension".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        },
        &rules,
    );
    assert!(
        !v.signals.iter().any(|s| s == "traffic_fine_scam"),
        "traffic_fine_scam must not fire without alert_shape; got {:?}",
        v.signals
    );
}

#[test]
fn jp_traffic_fine_scam_reaches_suspicious() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "駐車違反のお知らせ：反則金未払い。すぐにお支払いください。未払いの場合は車両登録停止。"
                .into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "traffic_fine_scam"),
        "expected traffic_fine_scam for JP parking impostor; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 50,
        "JP traffic_fine_scam must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn traffic_fine_scam_plus_phone_reaches_block() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "fastrak: toll violation — pay immediately — call 1-800-555-0197 — penalty will increase".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 150,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "traffic_fine_scam"),
        "expected traffic_fine_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "traffic_fine_scam + phone must reach Block; score = {}",
        v.score
    );
}

// ── E44: pig_butchering_lure ──────────────────────────────────────

#[test]
fn pig_butchering_lure_fires_on_alert_shaped_window() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "join our vip group — exclusive trading platform guaranteed return".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "pig_butchering_lure"),
        "expected pig_butchering_lure; got {:?}",
        v.signals
    );
}

#[test]
fn pig_butchering_lure_fp_guard_no_alert_shape() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "join our vip group — exclusive trading platform guaranteed return".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        },
        &rules,
    );
    assert!(
        !v.signals.iter().any(|s| s == "pig_butchering_lure"),
        "pig_butchering_lure must not fire on user-initiated page; got {:?}",
        v.signals
    );
}

#[test]
fn jp_pig_butchering_reaches_suspicious() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "sns型投資詐欺: 一緒に稼ごう！不労所得で稼ぐ高利回り投資プラットフォーム".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        },
        &rules,
    );
    assert!(
        v.score >= 50,
        "JP pig_butchering_lure must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn pig_butchering_plus_phone_reaches_block() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "investment mentor: join my trading platform — guaranteed profit — call 1-800-555-0210".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "pig_butchering_lure"),
        "expected pig_butchering_lure; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "pig_butchering_lure + phone must reach Block; score = {}",
        v.score
    );
}

// ── E45: loan_fee_scam ────────────────────────────────────────────

#[test]
fn loan_fee_scam_fires_on_alert_shaped_window() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "pre-approved loan offer — pay processing fee to receive your loan".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "loan_fee_scam"),
        "expected loan_fee_scam; got {:?}",
        v.signals
    );
}

#[test]
fn loan_fee_scam_fp_guard_no_alert_shape() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "pre-approved loan offer — pay processing fee to receive your loan".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        },
        &rules,
    );
    assert!(
        !v.signals.iter().any(|s| s == "loan_fee_scam"),
        "loan_fee_scam must not fire on user-initiated page; got {:?}",
        v.signals
    );
}

#[test]
fn jp_loan_fee_scam_reaches_suspicious() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "審査不要ローン — 先払いが必要です。即日融資。保証金が必要".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        },
        &rules,
    );
    assert!(
        v.score >= 50,
        "JP loan_fee_scam must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn loan_fee_scam_plus_phone_reaches_block() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "instant loan approved — upfront fee required — call 1-800-555-0221 — to receive your loan".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "loan_fee_scam"),
        "expected loan_fee_scam; got {:?}",
        v.signals
    );
    assert!(
        v.score >= 100,
        "loan_fee_scam + phone must reach Block; score = {}",
        v.score
    );
}

// ── A9: data_uri_page ─────────────────────────────────────────────

#[test]
fn data_uri_page_fires_on_data_scheme_alert() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "microsoft security warning — call support".into(),
            url: Some("data:text/html,<html>fake alert</html>".into()),
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "data_uri_page"),
        "expected data_uri_page; got {:?}",
        v.signals
    );
}

#[test]
fn data_uri_page_fp_guard_no_alert_shape() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "hello world".into(),
            url: Some("data:text/html,hello".into()),
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        },
        &rules,
    );
    assert!(
        !v.signals.iter().any(|s| s == "data_uri_page"),
        "data_uri_page must not fire without alert shape; got {:?}",
        v.signals
    );
}

#[test]
fn file_scheme_page_fires_data_uri_signal() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "windows defender — critical threat detected".into(),
            url: Some("file:///C:/Users/Public/scam.html".into()),
            coverage_percent: 95,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 100,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "data_uri_page"),
        "expected data_uri_page for file:// URL; got {:?}",
        v.signals
    );
}

#[test]
fn data_uri_plus_phone_reaches_block() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "critical virus alert — call 1-800-555-0234 immediately".into(),
            url: Some("data:text/html,<html>call microsoft support</html>".into()),
            coverage_percent: 95,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        },
        &rules,
    );
    assert!(
        v.score >= 100,
        "data_uri_page + phone must reach Block; score = {}",
        v.score
    );
}

// ── E46: charity_scam_lure ────────────────────────────────────────

#[test]
fn charity_scam_lure_fires_on_alert_shaped_window() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "hurricane relief fund — donate now — send bitcoin donation".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "charity_scam_lure"),
        "expected charity_scam_lure; got {:?}",
        v.signals
    );
}

#[test]
fn charity_scam_lure_fp_guard_no_alert_shape() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "hurricane relief fund — donate now — send bitcoin donation".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        },
        &rules,
    );
    assert!(
        !v.signals.iter().any(|s| s == "charity_scam_lure"),
        "charity_scam_lure must not fire without alert shape; got {:?}",
        v.signals
    );
}

#[test]
fn jp_charity_scam_reaches_suspicious() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "被災者支援義援金 — ギフトカードでお振込みください".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        },
        &rules,
    );
    assert!(
        v.score >= 50,
        "JP charity_scam_lure must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn charity_scam_plus_phone_reaches_block() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "emergency relief fund — help survivors — call 1-800-555-0245 — send via western union".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        },
        &rules,
    );
    assert!(
        v.score >= 100,
        "charity_scam_lure + phone must reach Block; score = {}",
        v.score
    );
}

// ── E47: rental_scam_lure ─────────────────────────────────────────

#[test]
fn rental_scam_lure_fires_on_alert_shaped_window() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "apartment for rent — deposit before viewing to hold unit".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        },
        &rules,
    );
    assert!(
        v.signals.iter().any(|s| s == "rental_scam_lure"),
        "expected rental_scam_lure; got {:?}",
        v.signals
    );
}

#[test]
fn rental_scam_lure_fp_guard_no_alert_shape() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "apartment for rent — deposit before viewing to hold unit".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        },
        &rules,
    );
    assert!(
        !v.signals.iter().any(|s| s == "rental_scam_lure"),
        "rental_scam_lure must not fire without alert shape; got {:?}",
        v.signals
    );
}

#[test]
fn jp_rental_scam_reaches_suspicious() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "賃貸物件 — 内覧前に入金をお願いします — アパート募集 — 先に敷金".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        },
        &rules,
    );
    assert!(
        v.score >= 50,
        "JP rental_scam_lure must reach Suspicious; score = {}",
        v.score
    );
}

#[test]
fn rental_scam_plus_phone_reaches_block() {
    let rules = Ruleset::default();
    let v = classify(
        &OverlayWindow {
            title: "studio apartment available — no credit check rental — call 1-800-555-0256 — deposit upfront to secure".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        },
        &rules,
    );
    assert!(
        v.score >= 100,
        "rental_scam_lure + phone must reach Block; score = {}",
        v.score
    );
}
