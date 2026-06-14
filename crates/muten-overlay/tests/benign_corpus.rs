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
