//! muten-overlay — scam / full-screen overlay detection.
//!
//! This is the pure domain layer for the v0.4.0 "screen" half of
//! muten's endpoint-environment enforcement. It knows nothing about
//! the OS window manager, the browser, or the network. It takes a
//! description of an observed window ([`OverlayWindow`]) plus a
//! [`Ruleset`], and returns a [`Verdict`]. The daemon's OS-specific
//! window enumerator feeds observations in; the OS-specific dismisser
//! acts on `Verdict::Block`. Both of those live elsewhere (like the
//! audio backends), so this crate stays testable without a desktop.
//!
//! ## Why heuristics, not ML
//!
//! Per CLAUDE.md I6 (explainable) and Pike (no cleverness where plain
//! code works): a transparent additive score whose contributions are
//! recorded in the verdict beats an opaque model that can't run
//! offline and can't be audited. Each signal's weight is a named
//! constant; the verdict lists which signals fired.
//!
//! ## Why "Suspicious", not auto-block-everything
//!
//! False positives are catastrophic here: wrongly dismissing a video
//! player, a presentation, a kiosk's own full-screen UI, or an exam
//! app breaks the very environments muten protects. So the default
//! posture is **observe**: only a confirmed blocklist match or a
//! score at/above the block threshold yields `Block`; everything in
//! between is `Suspicious` (audited, not dismissed). This mirrors the
//! audio side's `pilot-observe` philosophy.

#![forbid(unsafe_code)]

pub mod categories;
pub mod confusables;
pub mod controller;
pub mod monitor;
pub mod rules;
pub mod scareware;
pub mod sink;

pub use categories::{categories_of, category_of, DarkPatternCategory};
pub use controller::{
    ControllerError, EnumeratedWindow, NullController, OverlayController, SubprocessController,
    WindowId,
};
pub use monitor::{AuditEvent, AuditSink, MemorySink, Monitor, RunConfig};
pub use rules::Ruleset;
pub use scareware::{assess, RepeatTracker, ScarewareDecision, ScarewareVerdict};
pub use sink::{verify_chain, ChainedFileSink, GENESIS};

use serde::{Deserialize, Serialize};

/// How the window came to exist, as best the enumerator can tell.
/// Unsolicited pop-ups are far more likely to be scams than windows
/// the user explicitly opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// We don't know how it appeared.
    #[default]
    Unknown,
    /// Appeared right after a user click/keypress (likely legitimate).
    UserInitiated,
    /// Appeared with no preceding user input (classic scam pop-up).
    Unsolicited,
}

/// A snapshot of one observed window or browser overlay. All fields
/// are best-effort; the enumerator fills what it can and leaves the
/// rest at defaults. `coverage_percent` is the fraction of the active
/// display the window occupies (0..=100).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OverlayWindow {
    /// Window title or document title. Lower-cased by the enumerator.
    pub title: String,
    /// Source URL/host if this is a browser surface (lower-cased).
    pub url: Option<String>,
    /// Percent of the active display covered (0..=100).
    pub coverage_percent: u8,
    /// Always-on-top / topmost flag.
    pub topmost: bool,
    /// Whether the window exposes a usable close affordance. Scam
    /// overlays often hide or fake the close button.
    pub has_close_button: bool,
    /// Whether the window captured the pointer / blocks input to
    /// everything behind it (modal-like).
    pub blocks_input: bool,
    /// How it appeared.
    pub origin: Origin,
    /// How long it has been on screen, milliseconds. Brand-new
    /// unsolicited full-screen surfaces are the most suspicious.
    pub age_ms: u64,
}

/// The classifier's decision plus its reasoning. `score` is the summed
/// signal weight; `signals` lists which fired (for the audit log).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    pub decision: Decision,
    pub score: i32,
    pub signals: Vec<&'static str>,
    /// Dark-pattern strategy categories (Gray et al. 2018) implied by
    /// the signals that fired, deduped and sorted. Empty when only
    /// descriptive signals fired. See the `categories` module.
    pub categories: Vec<DarkPatternCategory>,
    /// Set when a blocklist rule matched outright.
    pub matched_rule: Option<String>,
}

impl Verdict {
    /// A deterministic, plain-language explanation of the verdict,
    /// assembled from the signals that fired (CLAUDE.md I6 / roadmap
    /// C5-8). For an operator or a SIEM note this reads better than a
    /// raw signal list, e.g.:
    ///
    /// > Block (score 130): the window covers (almost) the whole
    /// > screen, hides or fakes the close button, captures all input
    /// > (modal), appeared with no user action, and shows a support
    /// > phone number; matched blocklist rule "your computer is
    /// > infected".
    ///
    /// Pure and side-effect-free; the wording is stable so tests and
    /// downstream consumers can rely on it.
    #[must_use]
    pub fn explain(&self) -> String {
        let verb = match self.decision {
            Decision::Allow => "Allow",
            Decision::Suspicious => "Suspicious",
            Decision::Block => "Block",
        };
        let phrases: Vec<&str> = self.signals.iter().map(|s| signal_phrase(s)).collect();
        let body = if phrases.is_empty() {
            "no notable signals fired".to_string()
        } else {
            format!("the window {}", join_clauses(&phrases))
        };
        let mut out = format!("{verb} (score {}): {body}", self.score);
        if let Some(rule) = &self.matched_rule {
            out.push_str(&format!("; matched blocklist rule \"{rule}\""));
        }
        out.push('.');
        out
    }
}

/// Map one signal name to a human clause for [`Verdict::explain`].
/// Unknown signals fall back to their raw name (forward-compatible).
fn signal_phrase(signal: &str) -> &str {
    match signal {
        "fullscreen" => "covers (almost) the whole screen",
        "topmost" => "stays always-on-top",
        "no_close_button" => "hides or fakes the close button",
        "blocks_input" => "captures all input (modal)",
        "unsolicited" => "appeared with no user action",
        "user_initiated" => "was opened by the user",
        "very_new" => "just popped up",
        "blocklist_title" => "matches a known scam title",
        "blocklist_host" => "is hosted on a blocklisted domain",
        "phone_number" => "shows a support phone number",
        "mixed_script" => "mixes character sets to disguise its text",
        "input_trap" => "locks the screen by trapping keyboard/mouse",
        other => other,
    }
}

/// Join clauses into "a", "a and b", or "a, b, and c" (Oxford comma).
fn join_clauses(parts: &[&str]) -> String {
    match parts {
        [] => String::new(),
        [one] => (*one).to_string(),
        [a, b] => format!("{a} and {b}"),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Leave it alone.
    Allow,
    /// Record an audit event, but do not dismiss. Operator/IT reviews.
    Suspicious,
    /// Dismiss/close. Reserved for confirmed blocklist matches or
    /// scores at/above the block threshold.
    Block,
}

// ── Scoring weights (named per I6: explainable) ──────────────────

/// At or above this score → Block. Below `SUSPICIOUS_THRESHOLD` →
/// Allow. In between → Suspicious.
pub const BLOCK_THRESHOLD: i32 = 100;
pub const SUSPICIOUS_THRESHOLD: i32 = 50;

const W_FULLSCREEN: i32 = 30; // covers (almost) the whole display
const W_TOPMOST: i32 = 15; // always-on-top
const W_NO_CLOSE: i32 = 25; // hides/fakes the close button
const W_BLOCKS_INPUT: i32 = 20; // modal capture
const W_UNSOLICITED: i32 = 25; // appeared with no user action
const W_VERY_NEW: i32 = 10; // < 1s old (just popped up)
const W_TITLE_HIT: i32 = 40; // title matches a scam pattern
const W_PHONE_NUMBER: i32 = 35; // a phone number in an OS-alert-like window
const W_MIXED_SCRIPT: i32 = 30; // title/host mixes Latin with Cyrillic/Greek
const W_INPUT_TRAP: i32 = 5; // fullscreen+topmost+modal "screen lock" (bounded; see classify)
const W_USER_INITIATED_RELIEF: i32 = -40; // user opened it → trust more

/// Coverage at or above this percent counts as "full-screen".
const FULLSCREEN_COVERAGE: u8 = 85;

/// Extract the host portion of a URL-ish string, scheme/path/port
/// stripped — used to scope the mixed-script check to the host so a
/// Cyrillic word in a *path* (`example.com/привет`) can't false-fire.
/// Mirrors `rules::host_of` intent without allocating.
fn url_host(url: &str) -> &str {
    let after = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => url,
    };
    let authority = after.split(['/', '?', '#']).next().unwrap_or(after);
    let no_userinfo = authority.rsplit('@').next().unwrap_or(authority);
    no_userinfo.split(':').next().unwrap_or(no_userinfo)
}

/// Classify one observed window against a ruleset.
///
/// Order of precedence:
/// 1. A blocklist **URL/host** match is a hard Block (highest trust).
/// 2. Otherwise compute the additive heuristic score and threshold it.
///    A blocklist **title-pattern** match contributes `W_TITLE_HIT`
///    rather than an automatic block, because titles are noisier than
///    hosts.
#[must_use]
pub fn classify(w: &OverlayWindow, rules: &Ruleset) -> Verdict {
    // 1. Hard host/URL block.
    if let Some(url) = w.url.as_deref() {
        if let Some(hit) = rules.match_host(url) {
            let signals = vec!["blocklist_host"];
            return Verdict {
                decision: Decision::Block,
                score: BLOCK_THRESHOLD,
                categories: categories::categories_of(&signals),
                signals,
                matched_rule: Some(hit),
            };
        }
    }

    // 2. Additive heuristic.
    let mut score = 0;
    let mut signals: Vec<&'static str> = Vec::new();
    let mut matched_rule = None;

    if w.coverage_percent >= FULLSCREEN_COVERAGE {
        score += W_FULLSCREEN;
        signals.push("fullscreen");
    }
    if w.topmost {
        score += W_TOPMOST;
        signals.push("topmost");
    }
    if !w.has_close_button {
        score += W_NO_CLOSE;
        signals.push("no_close_button");
    }
    if w.blocks_input {
        score += W_BLOCKS_INPUT;
        signals.push("blocks_input");
    }
    match w.origin {
        Origin::Unsolicited => {
            score += W_UNSOLICITED;
            signals.push("unsolicited");
        }
        Origin::UserInitiated => {
            score += W_USER_INITIATED_RELIEF;
            signals.push("user_initiated");
        }
        Origin::Unknown => {}
    }
    // age_ms == 0 means the enumerator could not determine the
    // window's age (the OS helpers report 0 when window creation time
    // isn't cheaply available). "Unknown age" must not score as
    // "brand new" — otherwise every enumerated window would get
    // W_VERY_NEW unconditionally, turning the signal into constant
    // noise. Only a real, small, *nonzero* age counts as very_new.
    if w.age_ms > 0 && w.age_ms < 1000 {
        score += W_VERY_NEW;
        signals.push("very_new");
    }
    if let Some(rule) = rules.match_title(&w.title) {
        score += W_TITLE_HIT;
        signals.push("blocklist_title");
        matched_rule = Some(rule);
    }

    // Phone-number signal. Per Miramirkhani et al. (NDSS 2017, "Dial
    // One for Scam", 8,698 TSS domains) and FTC guidance, a phone
    // number in an OS-alert-style window is one of the strongest scam
    // tells: a genuine operating-system error never displays a support
    // number. We only count it when the window also *looks* like an
    // alert (full-screen or modal/no-close), so a legitimate window
    // that merely contains a number (a dialer, a contacts app) isn't
    // penalized.
    let alert_shaped =
        w.coverage_percent >= FULLSCREEN_COVERAGE || w.blocks_input || !w.has_close_button;
    if alert_shaped && contains_phone_number(&confusables::fold_confusables(&w.title)) {
        score += W_PHONE_NUMBER;
        signals.push("phone_number");
    }

    // Mixed-script homoglyph evasion. A single token that mixes Latin
    // with Cyrillic/Greek letters (e.g. "раypаl", "miсrosoft") is a
    // strong disguise tell (UTS #39 mixed-script confusables; NDSS 2015
    // typosquatting). Evaluated on the *raw* title and host, because the
    // confusable fold used for blocklist matching erases the evidence.
    // CJK/Kana are ignored, so a legitimate Japanese+Latin title does
    // not fire (false-positive guard for the JP market). The weight
    // nudges toward Suspicious; it never blocks on its own.
    let mixed_script = confusables::has_confusable_mixed_script(&w.title)
        || w.url
            .as_deref()
            .is_some_and(|u| confusables::has_confusable_mixed_script(url_host(u)));
    if mixed_script {
        score += W_MIXED_SCRIPT;
        signals.push("mixed_script");
    }

    // Composite "screen-lock" tell: a window that is full-screen AND
    // always-on-top AND grabs all input is a browser/screen *locker*,
    // not an ordinary modal dialog (which is modal but neither
    // full-screen nor topmost-over-everything). This is the shape of
    // Keyboard-Lock / Pointer-Lock abuse and of browser-locker
    // scareware kits like CypherLoc (Barracuda 2026), whose encrypted
    // in-browser payload evades content scanners but cannot hide the
    // window-level lock shape. We surface it as a named signal (for the
    // audit log / `explain()` / dark-pattern category) and add a small
    // bonus on top of the individual signals it co-occurs with.
    //
    // The bonus is deliberately small (W_INPUT_TRAP): the bare lock
    // shape without any content or provenance tell (origin unknown,
    // no scam title/number) tops out at 95 — still `Suspicious`, never
    // an automatic `Block`. That preserves the observe-first guard for
    // *legitimately* locked-down full-screen apps (kiosk shells, exam
    // lockdown browsers) whose origin a helper can't always attribute.
    // Any real content/provenance evidence still pushes it over.
    let input_trap = w.blocks_input && w.topmost && w.coverage_percent >= FULLSCREEN_COVERAGE;
    if input_trap {
        score += W_INPUT_TRAP;
        signals.push("input_trap");
    }

    // Clamp negative scores to 0 (a user-initiated benign window
    // shouldn't go "extra allowed" and underflow comparisons).
    let score = score.max(0);

    let decision = if score >= BLOCK_THRESHOLD {
        Decision::Block
    } else if score >= SUSPICIOUS_THRESHOLD {
        Decision::Suspicious
    } else {
        Decision::Allow
    };

    Verdict {
        decision,
        score,
        categories: categories::categories_of(&signals),
        signals,
        matched_rule,
    }
}

/// Heuristic phone-number detector, stdlib-only (no regex dep).
///
/// Looks for a run of digits that, ignoring common separators
/// (space, `-`, `.`, `(`, `)`, `+`), totals 7–15 digits — covering
/// toll-free US numbers like "1-800-XXX-XXXX", international "+44 …",
/// and bare 10-digit numbers, while rejecting short years/counts.
/// Conservative on purpose: the goal is "is there a phone number
/// here", not perfect E.164 validation.
#[must_use]
pub fn contains_phone_number(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip if the char just before the run is alphanumeric — we're
        // in the middle of a token like "0x80070005" or "build7234567",
        // not at the start of a real number.
        let prev_is_alnum = i > 0 && bytes[i - 1].is_ascii_alphanumeric();
        if (bytes[i].is_ascii_digit() || bytes[i] == b'+') && !prev_is_alnum {
            let mut digits = 0usize;
            let mut j = i;
            let mut aborted_by_letter = false;
            let mut last_was_digit = false;
            while j < bytes.len() {
                let c = bytes[j];
                if c.is_ascii_digit() {
                    digits += 1;
                    j += 1;
                    last_was_digit = true;
                } else if matches!(c, b' ' | b'-' | b'.' | b'(' | b')' | b'+') {
                    // separator — allowed inside a number run
                    j += 1;
                    last_was_digit = false;
                } else if c.is_ascii_alphabetic() {
                    // A letter *directly* touching a digit (no separator
                    // between) disqualifies the run — that's a hex code,
                    // version, or serial, not a phone number. A letter
                    // after a separator just ends the run normally.
                    if last_was_digit {
                        aborted_by_letter = true;
                    }
                    break;
                } else {
                    break;
                }
            }
            if !aborted_by_letter && (7..=15).contains(&digits) {
                return true;
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    false
}

///
/// The scareware [`RepeatTracker`] needs "the same pop-up" to map to
/// "the same key" across appearances. We define that here so callers
/// don't each invent their own (inconsistent) scheme: the key is the
/// normalized title plus the source host, which is stable across the
/// rapid re-pops of an installed rogue AV while still distinguishing
/// genuinely different alerts.
#[must_use]
pub fn signature(w: &OverlayWindow) -> String {
    let title = confusables::fold_confusables(w.title.trim()).to_ascii_lowercase();
    let host = w
        .url
        .as_deref()
        .and_then(|u| {
            // cheap host extraction; mirrors rules::host_of intent
            let s = u.to_ascii_lowercase();
            let after = s.split("://").last().unwrap_or(&s);
            after
                .split(['/', '?', '#'])
                .next()
                .map(|h| h.rsplit('@').next().unwrap_or(h).to_string())
        })
        .unwrap_or_default();
    format!("{title}|{host}")
}

/// One audited outcome from [`enforce`]: what we decided for a window
/// and whether we dismissed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforceOutcome {
    pub window_id: String,
    pub decision: Decision,
    pub score: i32,
    pub signals: Vec<&'static str>,
    pub matched_rule: Option<String>,
    /// True only when the controller actually dismissed the window.
    pub dismissed: bool,
}

/// Run the full overlay loop once: enumerate every window, classify
/// each against `rules`, and dismiss the ones that score `Block`.
///
/// Returns one [`EnforceOutcome`] per window so the daemon can emit
/// audit events. Only `Block` triggers a dismiss; `Suspicious` and
/// `Allow` are reported but never dismissed (CLAUDE.md I9, and the
/// false-positive-averse design). Controller errors on a single
/// dismiss are folded into `dismissed = false` rather than aborting
/// the sweep — one stuck window shouldn't blind the daemon to the
/// rest.
pub fn enforce(
    controller: &dyn OverlayController,
    rules: &Ruleset,
) -> Result<Vec<EnforceOutcome>, ControllerError> {
    let windows = controller.enumerate()?;
    let mut outcomes = Vec::with_capacity(windows.len());
    for ew in windows {
        let v = classify(&ew.window, rules);
        let dismissed = if v.decision == Decision::Block {
            controller.dismiss(&ew.id).unwrap_or(false)
        } else {
            false
        };
        outcomes.push(EnforceOutcome {
            window_id: ew.id,
            decision: v.decision,
            score: v.score,
            signals: v.signals,
            matched_rule: v.matched_rule,
            dismissed,
        });
    }
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn benign_fullscreen_video() -> OverlayWindow {
        // A user opened a video and went full screen: full coverage +
        // topmost, but user-initiated and has a close button.
        OverlayWindow {
            title: "my vacation video - vlc media player".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        }
    }

    fn classic_scam() -> OverlayWindow {
        OverlayWindow {
            title: "⚠ your computer is infected! call support now".into(),
            url: Some("http://win-prize-now.example/alert".into()),
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 200,
        }
    }

    #[test]
    fn benign_video_is_allowed() {
        let v = classify(&benign_fullscreen_video(), &Ruleset::default());
        assert_eq!(
            v.decision,
            Decision::Allow,
            "score={} {:?}",
            v.score,
            v.signals
        );
    }

    #[test]
    fn classic_scam_is_blocked_by_heuristic_even_without_blocklist() {
        // Empty ruleset: rely purely on the heuristic signals.
        let v = classify(&classic_scam(), &Ruleset::default());
        assert_eq!(
            v.decision,
            Decision::Block,
            "score={} {:?}",
            v.score,
            v.signals
        );
    }

    #[test]
    fn host_blocklist_is_hard_block() {
        let rules = Ruleset::from_lines(&["host: win-prize-now.example"]);
        let mut w = benign_fullscreen_video();
        w.url = Some("http://win-prize-now.example/x".into());
        let v = classify(&w, &rules);
        assert_eq!(v.decision, Decision::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("win-prize-now.example"));
        assert!(v.signals.contains(&"blocklist_host"));
    }

    #[test]
    fn unsolicited_fullscreen_no_close_is_at_least_suspicious() {
        let w = OverlayWindow {
            title: "special offer".into(),
            url: None,
            coverage_percent: 90,
            topmost: false,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 500,
        };
        let v = classify(&w, &Ruleset::default());
        // 30 (fullscreen) + 25 (no_close) + 25 (unsolicited) + 10 (new) = 90.
        // Below BLOCK_THRESHOLD (100) by design: without a confirmed
        // blocklist hit or a topmost+modal combination, we flag for
        // review rather than auto-dismiss. False positives here would
        // break legitimate full-screen apps.
        assert_eq!(v.decision, Decision::Suspicious, "score={}", v.score);
    }

    #[test]
    fn unsolicited_fullscreen_modal_topmost_no_close_is_blocked() {
        // Add topmost (+15) and blocks_input (+20) to the previous
        // case → 125 ≥ 100 → Block. This is the unmistakable scam
        // shape: full-screen, on top, modal, no close, popped up
        // unsolicited.
        let w = OverlayWindow {
            title: "special offer".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 500,
        };
        let v = classify(&w, &Ruleset::default());
        assert_eq!(v.decision, Decision::Block, "score={}", v.score);
    }

    #[test]
    fn small_unsolicited_popup_is_suspicious_not_blocked() {
        let w = OverlayWindow {
            title: "newsletter signup".into(),
            url: None,
            coverage_percent: 30,
            topmost: false,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 2_000,
        };
        let v = classify(&w, &Ruleset::default());
        // 25 (no_close) + 25 (unsolicited) = 50 → Suspicious
        assert_eq!(v.decision, Decision::Suspicious, "score={}", v.score);
    }

    #[test]
    fn title_pattern_contributes_but_is_not_auto_block() {
        let rules = Ruleset::from_lines(&["title: your computer is infected"]);
        let w = OverlayWindow {
            title: "warning: your computer is infected".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        // Only the title hit (40) fires → below suspicious threshold.
        assert_eq!(v.decision, Decision::Allow, "score={}", v.score);
        assert!(v.signals.contains(&"blocklist_title"));
    }

    #[test]
    fn user_initiated_relief_keeps_legit_fullscreen_app_allowed() {
        let w = OverlayWindow {
            title: "presentation".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false, // presentations often hide chrome
            blocks_input: true,
            origin: Origin::UserInitiated,
            age_ms: 1_000,
        };
        let v = classify(&w, &Ruleset::default());
        // 30+15+25+20 = 90, minus 40 relief = 50 → Suspicious (not Block).
        // Acceptable: IT reviews, but we don't dismiss a presentation.
        assert_ne!(v.decision, Decision::Block, "score={}", v.score);
    }

    #[test]
    fn score_never_negative() {
        let w = OverlayWindow {
            title: "x".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated, // -40 relief
            age_ms: 10_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(v.score >= 0);
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn age_zero_is_unknown_not_very_new() {
        // age_ms == 0 means "enumerator couldn't tell" — it must NOT
        // score as very_new (the OS helpers report 0 by default, so
        // scoring it would add +10 to literally every window).
        let w = OverlayWindow {
            title: "x".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 0,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.contains(&"very_new"),
            "age 0 must not be very_new"
        );
        assert_eq!(v.score, 0);
    }

    #[test]
    fn small_nonzero_age_is_very_new() {
        let w = OverlayWindow {
            title: "x".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 300,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(v.signals.contains(&"very_new"));
    }

    #[test]
    fn old_window_is_not_very_new() {
        let w = OverlayWindow {
            title: "x".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 60_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(!v.signals.contains(&"very_new"));
    }

    // ── phone-number signal (arxiv 1607.06891) ───────────────────

    #[test]
    fn detects_toll_free_number() {
        assert!(contains_phone_number("call 1-800-642-7676 now"));
        assert!(contains_phone_number("support: (888) 555-0199"));
        assert!(contains_phone_number("+44 20 7946 0958"));
        assert!(contains_phone_number("dial 18005550199"));
    }

    #[test]
    fn rejects_non_phone_digit_runs() {
        assert!(!contains_phone_number("error code 0x80070005"));
        assert!(!contains_phone_number("copyright 2026"));
        assert!(!contains_phone_number("version 4.10.2"));
        assert!(!contains_phone_number("no digits here"));
    }

    #[test]
    fn phone_number_scores_only_when_alert_shaped() {
        // Fullscreen alert with a number → phone_number fires.
        let scam = OverlayWindow {
            title: "virus alert! call 1-888-555-0142 immediately".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unknown,
            age_ms: 0,
        };
        let v = classify(&scam, &Ruleset::default());
        assert!(
            v.signals.contains(&"phone_number"),
            "signals={:?}",
            v.signals
        );

        // A small, closable, non-modal window with a number (e.g. a
        // contacts app) must NOT get the phone_number signal.
        let benign = OverlayWindow {
            title: "Contact: 1-888-555-0142".into(),
            url: None,
            coverage_percent: 30,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let vb = classify(&benign, &Ruleset::default());
        assert!(
            !vb.signals.contains(&"phone_number"),
            "signals={:?}",
            vb.signals
        );
    }

    #[test]
    fn phone_number_pushes_fullscreen_scam_to_block() {
        // The key win: on a real host where origin=unknown and
        // has_close_button comes back true, a fullscreen TSS page with
        // a phone number now reaches Block on the heuristic alone.
        // fullscreen(30)+topmost(15)+phone(35) = 80 → Suspicious;
        // add no_close (real helper detects borderless) → 105 → Block.
        let w = OverlayWindow {
            title: "Windows Defender: call +1-800-555-0123 to remove virus".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 0,
        };
        let v = classify(&w, &Ruleset::default());
        // 30 + 15 + 25(no_close) + 35(phone) = 105
        assert_eq!(
            v.decision,
            Decision::Block,
            "score={} {:?}",
            v.score,
            v.signals
        );
    }

    #[test]
    fn verdict_carries_dark_pattern_categories() {
        // A fullscreen modal scam with a phone number should surface
        // forced_action (blocks_input), obstruction (no_close), and
        // interface_interference (phone_number).
        let w = OverlayWindow {
            title: "Microsoft Alert: call 1-800-555-0100 now".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 0,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(v.categories.contains(&DarkPatternCategory::ForcedAction));
        assert!(v.categories.contains(&DarkPatternCategory::Obstruction));
        assert!(v
            .categories
            .contains(&DarkPatternCategory::InterfaceInterference));
    }

    #[test]
    fn benign_window_has_no_categories() {
        let w = OverlayWindow {
            title: "report.pdf - reader".into(),
            url: None,
            coverage_percent: 40,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(v.categories.is_empty(), "categories={:?}", v.categories);
    }

    #[test]
    fn host_block_is_interface_interference() {
        let w = OverlayWindow {
            title: "x".into(),
            url: Some("http://scam.example/x".into()),
            ..Default::default()
        };
        let rules = Ruleset::from_lines(&["host: scam.example"]);
        let v = classify(&w, &rules);
        assert_eq!(
            v.categories,
            vec![DarkPatternCategory::InterfaceInterference]
        );
    }

    #[test]
    fn homoglyph_title_still_matches_blocklist() {
        // arXiv:2401.07867 — homoglyph substitution is a top evasion.
        // "your computer is іnfected" uses Cyrillic і (U+0456); it must
        // still hit the ascii "your computer is infected" pattern after
        // confusable folding.
        let rules = Ruleset::from_lines(&["title: your computer is infected"]);
        let w = OverlayWindow {
            title: "your computer is іnfected".into(), // Cyrillic і
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 0,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.contains(&"blocklist_title"),
            "homoglyph title evaded the blocklist: {:?}",
            v.signals
        );
    }

    #[test]
    fn fullwidth_digits_trigger_phone_signal() {
        // Full-width digits in a phone number must still be detected.
        let w = OverlayWindow {
            title: "call \u{FF11}-\u{FF18}\u{FF10}\u{FF10}-\u{FF15}\u{FF15}\u{FF15}-\u{FF10}\u{FF11}\u{FF10}\u{FF10}".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unknown,
            age_ms: 0,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.contains(&"phone_number"),
            "signals={:?}",
            v.signals
        );
    }

    // ── mixed-script evasion signal (UTS #39 / roadmap C8-4) ─────

    #[test]
    fn mixed_script_title_fires_signal_and_sneaking_category() {
        // "раypаl" mixes Cyrillic р/а with Latin — homoglyph disguise.
        let w = OverlayWindow {
            title: "sign in to раypаl".into(),
            coverage_percent: 90,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.contains(&"mixed_script"),
            "signals={:?}",
            v.signals
        );
        assert!(v.categories.contains(&DarkPatternCategory::Sneaking));
    }

    #[test]
    fn mixed_script_host_fires_but_path_does_not() {
        // Homoglyph host → fires.
        let w = OverlayWindow {
            title: "login".into(),
            url: Some("http://раypal.com/secure".into()),
            ..Default::default()
        };
        assert!(classify(&w, &Ruleset::default())
            .signals
            .contains(&"mixed_script"));

        // A Cyrillic word only in the *path* of a Latin host must NOT
        // fire (the check is scoped to the host).
        let w2 = OverlayWindow {
            title: "blog".into(),
            url: Some("http://example.com/привет".into()),
            ..Default::default()
        };
        assert!(!classify(&w2, &Ruleset::default())
            .signals
            .contains(&"mixed_script"));
    }

    #[test]
    fn japanese_plus_latin_title_does_not_fire_mixed_script() {
        // FP guard for the JP market: Japanese is `Other`, not a
        // confusable script, so a legit bilingual title is clean.
        let w = OverlayWindow {
            title: "ウイルス対策 Windows Update".into(),
            coverage_percent: 100,
            topmost: true,
            has_close_button: true,
            origin: Origin::UserInitiated,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.contains(&"mixed_script"),
            "JP+Latin title falsely flagged: {:?}",
            v.signals
        );
    }

    #[test]
    fn mixed_script_alone_is_not_a_block() {
        // The signal nudges toward Suspicious, never blocks on its own
        // (W_MIXED_SCRIPT = 30 < SUSPICIOUS_THRESHOLD).
        let w = OverlayWindow {
            title: "раypаl".into(),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert_ne!(v.decision, Decision::Block);
    }

    // ── input_trap composite "screen lock" signal ───────────────

    #[test]
    fn input_trap_fires_on_fullscreen_topmost_modal() {
        let w = OverlayWindow {
            title: "loading".into(),
            coverage_percent: 100,
            topmost: true,
            blocks_input: true,
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(v.signals.contains(&"input_trap"), "signals={:?}", v.signals);
        assert!(v.categories.contains(&DarkPatternCategory::ForcedAction));
    }

    #[test]
    fn input_trap_requires_all_three_conditions() {
        // Missing topmost → not a lock.
        let mut w = OverlayWindow {
            title: "x".into(),
            coverage_percent: 100,
            topmost: false,
            blocks_input: true,
            has_close_button: true,
            ..Default::default()
        };
        assert!(!classify(&w, &Ruleset::default())
            .signals
            .contains(&"input_trap"));
        // Missing fullscreen → not a lock.
        w.topmost = true;
        w.coverage_percent = 40;
        assert!(!classify(&w, &Ruleset::default())
            .signals
            .contains(&"input_trap"));
    }

    #[test]
    fn input_trap_alone_does_not_block_unknown_origin_lockdown_app() {
        // FP-aversion invariant: the bare lock shape (full-screen,
        // topmost, modal, no close) with UNKNOWN provenance and no
        // content tell must stay Suspicious, not auto-Block — a kiosk
        // shell / exam lockdown browser looks exactly like this. The
        // input_trap bonus is bounded so 90 + 5 = 95 < BLOCK_THRESHOLD.
        let w = OverlayWindow {
            title: "exam in progress".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unknown,
            age_ms: 0,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(v.signals.contains(&"input_trap"));
        assert_eq!(v.decision, Decision::Suspicious, "score={}", v.score);
        assert!(v.score < BLOCK_THRESHOLD);
    }

    // ── Verdict::explain (roadmap C5-8) ──────────────────────────

    #[test]
    fn explain_lists_signals_in_plain_language() {
        let w = OverlayWindow {
            title: "Microsoft Alert: call 1-800-555-0100 now".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 0,
        };
        let v = classify(&w, &Ruleset::default());
        let why = v.explain();
        assert!(why.starts_with("Block (score "));
        assert!(why.contains("covers (almost) the whole screen"));
        assert!(why.contains("hides or fakes the close button"));
        assert!(why.contains("shows a support phone number"));
        assert!(why.ends_with('.'));
    }

    #[test]
    fn explain_mentions_matched_rule() {
        let rules = Ruleset::from_lines(&["host: scam.example"]);
        let w = OverlayWindow {
            title: "x".into(),
            url: Some("http://scam.example/x".into()),
            ..Default::default()
        };
        let why = classify(&w, &rules).explain();
        assert!(why.contains("matched blocklist rule \"scam.example\""));
    }

    #[test]
    fn explain_handles_allow_with_no_signals() {
        let w = OverlayWindow {
            title: "notepad".into(),
            has_close_button: true,
            ..Default::default()
        };
        let why = classify(&w, &Ruleset::default()).explain();
        assert_eq!(why, "Allow (score 0): no notable signals fired.");
    }

    #[test]
    fn homoglyph_variants_share_signature() {
        // Two appearances of the same scam, one with a Cyrillic letter,
        // must produce the same repeat-detection signature so the flood
        // tracker counts them together.
        let a = OverlayWindow {
            title: "Virus Alert".into(),
            ..Default::default()
        };
        let b = OverlayWindow {
            title: "Vіrus Alert".into(), // Cyrillic і
            ..Default::default()
        };
        assert_eq!(signature(&a), signature(&b));
    }

    #[test]
    fn signature_stable_for_same_window() {
        let w = OverlayWindow {
            title: "  Your PC Is Infected  ".into(),
            url: Some("http://scam.example/alert?id=1".into()),
            ..Default::default()
        };
        let w2 = OverlayWindow {
            title: "your pc is infected".into(),
            // different query string, same host → same signature
            url: Some("https://scam.example/alert?id=999".into()),
            ..Default::default()
        };
        assert_eq!(signature(&w), signature(&w2));
    }

    #[test]
    fn signature_differs_for_different_host() {
        let a = OverlayWindow {
            title: "alert".into(),
            url: Some("http://a.example/".into()),
            ..Default::default()
        };
        let b = OverlayWindow {
            title: "alert".into(),
            url: Some("http://b.example/".into()),
            ..Default::default()
        };
        assert_ne!(signature(&a), signature(&b));
    }

    // ── enforce() ────────────────────────────────────────────────

    fn scam_window() -> OverlayWindow {
        OverlayWindow {
            title: "your computer is infected - call support".into(),
            url: Some("http://win-prize-now.example/x".into()),
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 200,
        }
    }

    fn benign_window() -> OverlayWindow {
        OverlayWindow {
            title: "report.pdf - reader".into(),
            url: None,
            coverage_percent: 40,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        }
    }

    #[test]
    fn enforce_dismisses_block_only() {
        let rules = Ruleset::from_lines(&["host: win-prize-now.example"]);
        let ctrl = NullController::with_windows(vec![
            EnumeratedWindow {
                id: "scam".into(),
                window: scam_window(),
            },
            EnumeratedWindow {
                id: "ok".into(),
                window: benign_window(),
            },
        ]);
        let outcomes = enforce(&ctrl, &rules).unwrap();
        assert_eq!(outcomes.len(), 2);

        let scam = outcomes.iter().find(|o| o.window_id == "scam").unwrap();
        assert_eq!(scam.decision, Decision::Block);
        assert!(scam.dismissed);

        let ok = outcomes.iter().find(|o| o.window_id == "ok").unwrap();
        assert_eq!(ok.decision, Decision::Allow);
        assert!(!ok.dismissed);

        // Only the scam window's id was dismissed.
        assert_eq!(ctrl.dismissed(), vec!["scam".to_string()]);
    }

    #[test]
    fn enforce_does_not_dismiss_suspicious() {
        // Build a window that lands Suspicious (50..100), not Block.
        let w = OverlayWindow {
            title: "newsletter".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: false, // +25
            blocks_input: false,
            origin: Origin::Unsolicited, // +25
            age_ms: 5_000,
        };
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            id: "s".into(),
            window: w,
        }]);
        let outcomes = enforce(&ctrl, &Ruleset::default()).unwrap();
        assert_eq!(outcomes[0].decision, Decision::Suspicious);
        assert!(!outcomes[0].dismissed);
        assert!(ctrl.dismissed().is_empty());
    }

    #[test]
    fn enforce_empty_when_nothing_on_screen() {
        let ctrl = NullController::new();
        let outcomes = enforce(&ctrl, &Ruleset::default()).unwrap();
        assert!(outcomes.is_empty());
    }
}
