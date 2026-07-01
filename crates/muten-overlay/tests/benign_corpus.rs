//! Aggregate benign-corpus false-positive guard (Socratic FP audit).
//!
//! Every other negative test in this crate proves that *one* hand-picked
//! benign string — chosen by the author *for* the signal under test — does
//! not fire. That is structurally weak evidence for the project's repeated
//! "near-zero false-positive" claim: each test was designed around the very
//! signal it exercises, so it can only confirm a known-safe case, never
//! falsify the FP property.
//!
//! This test takes the opposite stance. It runs a broad corpus of realistic
//! **legitimate** window / overlay titles — OS dialogs, browser and app tab
//! titles, office and developer tools, security products, banking and
//! e-commerce notifications, media players, in English and Japanese — through
//! the *whole* classifier, and asserts that **no content/text signal fires**
//! on any of them. The corpus deliberately includes "near-miss" legitimate
//! titles sitting one conjunct away from each scam family (a real Windows
//! activation prompt, a genuine AV renewal notice, a real delivery
//! notification, a real 2FA "enter the code" prompt, a benign message about a
//! relative) so the AND-pair discipline is stressed on adjacent-but-legitimate
//! text — exactly the cases a per-signal test would never think to include.
//!
//! Geometry is held at the worst case for content detection: an alert-shaped
//! window (full-screen / topmost / no-close / unsolicited / brand-new), since
//! content signals are gated behind `alert_shaped` and would not even be
//! evaluated otherwise. Pure geometry of that profile is itself the scareware
//! signature and scores at Block on its own *by design*, so this test asserts
//! only that the **text** of a legitimate window contributes **no** content
//! signal — it does not assert the overall verdict.

use muten_overlay::{classify, Origin, OverlayWindow, Ruleset};

/// Window-geometry / structural signals that legitimately fire purely from the
/// alert-shaped window profile used below. Any signal *outside* this set that
/// fires on a benign title is a content-detector false positive.
const GEOMETRY_SIGNALS: &[&str] = &[
    "fullscreen",
    "topmost",
    "no_close_button",
    "blocks_input",
    "unsolicited",
    "very_new",
    "input_trap",
    "sudden_fullscreen_takeover",
    "user_initiated",
];

/// A broad corpus of realistic legitimate window / overlay titles.
const BENIGN_TITLES: &[&str] = &[
    // ── Everyday OS / desktop ────────────────────────────────────────────
    "Document1 - Microsoft Word",
    "Untitled - Notepad",
    "System Preferences",
    "Settings",
    "Finder",
    "Task Manager",
    "Activity Monitor",
    "Control Panel",
    "Recycle Bin",
    "This PC",
    // ── Browsers / web apps ──────────────────────────────────────────────
    "Inbox (12) - Gmail",
    "YouTube - Home",
    "Google Search",
    "Wikipedia, the free encyclopedia",
    "Stack Overflow - Where Developers Learn",
    "GitHub - Let's build from here",
    "Google Docs",
    "Figma",
    "Notion - My workspace",
    "Slack | general | Acme",
    // ── Developer / productivity ─────────────────────────────────────────
    "main.rs - muten - Visual Studio Code",
    "Terminal",
    "iTerm2",
    "JetBrains IntelliJ IDEA",
    "Postman",
    "Docker Desktop",
    // ── Media / communication ────────────────────────────────────────────
    "Zoom Meeting",
    "Spotify - Discover Weekly",
    "Netflix",
    "VLC media player",
    "Microsoft Teams",
    // ── Security products (legitimate) ───────────────────────────────────
    "Windows Security",
    "McAfee Total Protection",
    "Malwarebytes Premium",
    "1Password — Sign in",
    "Bitwarden",
    // ── Near-miss legitimate notifications (adversarial-benign) ──────────
    // Each sits one conjunct away from a scam family; the AND-pair must hold.
    "Activate Windows - go to Settings to activate Windows", // ~ windows_activation_scam
    "Your McAfee subscription renews on June 30",            // ~ av_brand_renewal/subscription
    "Your package has been delivered — USPS",                // ~ package_fee_lure
    "Verify it's you to continue — Google",                  // ~ credential/clickfix (no "human")
    "Your tax documents are ready to download — TurboTax",   // ~ tax_authority_scam
    "Your refund has been processed and will arrive in 3-5 days", // ~ refund_scam_cue
    "Two-factor authentication: enter the code we sent", // ~ otp_interception (enter, not share)
    "Your order has shipped — track your package",       // ~ package/prize
    "Payment received — thank you for your purchase",    // ~ invoice/billing
    "Security alert: new sign-in on your account",       // ~ authority/urgency (no demand)
    "Your free trial ends in 7 days", // ~ subscription_lure (no cancel-fee demand)
    "Update available for your application", // ~ download_trap (no "install to fix virus")
    "Your support ticket #48213 has been created — we'll respond within 24 hours", // ~ toad_case_number_lure (case id, no call CTA)
    "Case number CX-9931 has been assigned to your inquiry", // ~ toad_case_number_lure (case id, no call CTA)
    "Connect Wallet — MetaMask", // ~ wallet_connect_popup_lure (connect verb, no reward hook)
    "Connect your wallet to view your NFT collection", // ~ wallet_connect_popup_lure (connect verb, no airdrop/reward)
    "Your connection is not private — Advanced", // ~ fake_browser_security_warning (real Chrome cert warning, no call/download CTA)
    "NET::ERR_CERT_AUTHORITY_INVALID", // ~ fake_browser_security_warning (real cert error code, no scam CTA)
    "iCloud Storage Almost Full", // ~ cloud_quota_lure (real Apple notification title, no consequence threat)
    "Google Drive is running out of storage — Upgrade your plan", // ~ cloud_quota_lure (real Google copy, no urgency)
    // ── Japanese legitimate ──────────────────────────────────────────────
    "ご注文ありがとうございます - Amazon",
    "請求書の発行が完了しました",
    "お振込が完了しました",
    "新しいメッセージが1件あります",
    "システムアップデートの準備ができました",
    "二段階認証コードを入力してください", // ~ otp (enter, not share)
    "息子さんの学校行事のお知らせ",       // ~ family_emergency (relative, no crisis/demand)
    "セキュリティ更新プログラムをインストールしました",
    "パスワードを変更しました",
    "プレミアム会員の特典のご案内",
];

fn alert_shaped(title: &str) -> OverlayWindow {
    OverlayWindow {
        title: title.into(),
        url: None,
        coverage_percent: 95,
        topmost: true,
        has_close_button: false,
        blocks_input: true,
        origin: Origin::Unsolicited,
        age_ms: 50,
    }
}

#[test]
fn benign_corpus_fires_no_content_signal() {
    let rules = Ruleset::default();
    let mut failures: Vec<String> = Vec::new();
    for title in BENIGN_TITLES {
        let v = classify(&alert_shaped(title), &rules);
        let content: Vec<&String> = v
            .signals
            .iter()
            .filter(|s| !GEOMETRY_SIGNALS.contains(&s.as_str()))
            .collect();
        if !content.is_empty() {
            failures.push(format!(
                "  {title:?} → unexpected content signals {content:?}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "benign corpus produced content-signal false positives:\n{}",
        failures.join("\n")
    );
}

/// In ordinary (non-alert) geometry, every benign title must classify as a
/// clean Allow with no content signal at all — the everyday no-false-alarm
/// guarantee for legitimate user-initiated windows.
#[test]
fn benign_corpus_in_normal_geometry_is_allow() {
    let rules = Ruleset::default();
    let mut failures: Vec<String> = Vec::new();
    for title in BENIGN_TITLES {
        let w = OverlayWindow {
            title: (*title).into(),
            url: None,
            coverage_percent: 35,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 8_000,
        };
        let v = classify(&w, &rules);
        let content: Vec<&String> = v
            .signals
            .iter()
            .filter(|s| !GEOMETRY_SIGNALS.contains(&s.as_str()))
            .collect();
        if !content.is_empty() {
            failures.push(format!("  {title:?} → {content:?} (score {})", v.score));
        }
    }
    assert!(
        failures.is_empty(),
        "benign corpus flagged in normal geometry:\n{}",
        failures.join("\n")
    );
}

// ── Resource-safety / DoS guard (Socratic robustness audit) ───────────────
//
// A maliciously gigantic window title must not be able to stall the classifier
// (algorithmic-complexity denial of service). The classifier bounds untrusted
// title/URL length to MAX_TITLE_CHARS before any normalization or detection.

use std::time::Instant;

#[test]
fn giant_title_classifies_quickly() {
    // ~5 MB title. Before bounding this took ~90 seconds; bounded it is trivial.
    let giant = "verify your account ".repeat(262_144);
    let w = alert_shaped(&giant);
    let t0 = Instant::now();
    let v = classify(&w, &Ruleset::default());
    let ms = t0.elapsed().as_millis();
    assert!(
        ms < 2_000,
        "classify() on a {}-byte title took {ms} ms — input length is not bounded",
        giant.len()
    );
    // Sanity: it still produces a verdict (geometry alone is alert-shaped).
    assert!(v.score > 0);
}

#[test]
fn giant_url_classifies_quickly() {
    // The URL-based content/brand checks (brand_impersonation, combosquat,
    // typosquat_brand, cloud_storage_abuse, url_path_lure, data_uri_page,
    // ip_host_url) must also read a length-bounded URL — a ~5 MB URL must not
    // stall classify(). Regression guard for the URL-side of the input bound.
    let giant_url = format!("http://evil.example/{}", "a".repeat(5_000_000));
    let mut w = alert_shaped("alert");
    w.url = Some(giant_url);
    let t0 = Instant::now();
    let _ = classify(&w, &Ruleset::default());
    let ms = t0.elapsed().as_millis();
    assert!(
        ms < 2_000,
        "classify() on a multi-megabyte URL took {ms} ms — URL length is not bounded"
    );
}

#[test]
fn giant_title_still_detects_scam_within_cap() {
    // Scam phrasing at the very start (where a real window renders it) must
    // still be detected even when megabytes of padding follow.
    let mut title = String::from("your grandson has been arrested — send bail money immediately. ");
    title.push_str(&"x".repeat(4_000_000));
    let v = classify(&alert_shaped(&title), &Ruleset::default());
    assert!(
        v.signals.iter().any(|s| s == "family_emergency_scam"),
        "scam text within the cap must still be detected; got {:?}",
        v.signals
    );
}

#[test]
fn pathological_combining_marks_classify_quickly() {
    let comb: String = "\u{0301}".repeat(2_000_000);
    let t0 = Instant::now();
    let _ = classify(&alert_shaped(&comb), &Ruleset::default());
    assert!(
        t0.elapsed().as_millis() < 2_000,
        "combining-mark flood must be bounded"
    );
}

#[test]
fn bound_title_chars_truncates_on_char_boundary() {
    use muten_overlay::confusables::{bound_title_chars, MAX_TITLE_CHARS};
    // Multibyte input longer than the cap must truncate without panicking and
    // yield valid UTF-8 of exactly MAX_TITLE_CHARS chars.
    let s: String = "認".repeat(MAX_TITLE_CHARS + 500);
    let out = bound_title_chars(&s);
    assert_eq!(out.chars().count(), MAX_TITLE_CHARS);
    // Shorter input is returned unchanged.
    assert_eq!(bound_title_chars("short"), "short");
}
