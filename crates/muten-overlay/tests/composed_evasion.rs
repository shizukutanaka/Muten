//! Composed (stacked) evasion regression tests.
//!
//! The unit tests in `confusables.rs` verify each evasion-defeating layer in
//! isolation (homoglyph folding, zero-width stripping, combining-mark stripping,
//! leet folding, math-alphanumeric folding, spread-character collapse). What
//! they do *not* prove is that the layers **compose**: a real attacker does not
//! pick one technique, they stack several in a single title. Layer composition
//! is exactly where ordering bugs hide — e.g. a zero-width character sitting
//! between two Cyrillic letters must be stripped *before* folding, and a leet
//! digit standing in for a letter must be folded *after* confusable folding has
//! reformed the word token.
//!
//! These tests build maximally-evaded versions of real blocklist titles — each
//! character disguised with a *different* technique — and assert the full
//! `classify()` pipeline still recovers the phrase, fires `blocklist_title`, and
//! reaches `Block`. A benign control proves the stacked normalization does not
//! over-trigger.

use muten_overlay::{classify, Decision, Origin, OverlayWindow, Ruleset};

fn load_example_blocklist() -> Ruleset {
    for path in [
        "../../examples/overlay-blocklist.txt",
        "examples/overlay-blocklist.txt",
    ] {
        if let Ok(text) = std::fs::read_to_string(path) {
            return Ruleset::parse(&text);
        }
    }
    panic!("could not locate examples/overlay-blocklist.txt from CWD");
}

/// A fullscreen, unsolicited, input-blocking overlay carrying `title`.
fn alert(title: &str) -> OverlayWindow {
    OverlayWindow {
        title: title.to_string(),
        url: None,
        coverage_percent: 100,
        topmost: true,
        has_close_button: false,
        blocks_input: true,
        origin: Origin::Unsolicited,
        age_ms: 0,
    }
}

/// Insert a zero-width space (U+200B) between every character, to prove the
/// invisibles-stripping layer composes with whatever disguises the chars carry.
fn interleave_zero_width(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 {
            out.push('\u{200B}');
        }
        out.push(c);
    }
    out
}

#[test]
fn normalization_recovers_stacked_evasion_phrase() {
    // "your computer is infected" with a rotating stack of techniques:
    //   y → у   Cyrillic U+0443
    //   o → 0   leet digit (folded after confusables reform the token)
    //   u → 𝐮   math bold U+1D42E
    //   r → r   plain
    //   c → с   Cyrillic U+0441
    //   o → ο   Greek U+03BF
    //   m → m   plain
    //   p → р   Cyrillic U+0440
    //   u → u   plain
    //   t → т   Cyrillic U+0442
    //   e → 3   leet digit
    //   r → r   plain
    //   i → і   Cyrillic U+0456
    //   s → ѕ   Cyrillic U+0455
    //   i → 1   leet digit
    //   n → n   plain
    //   f → ƒ   f-hook U+0192
    //   e → е   Cyrillic U+0435
    //   c → ⅽ   Roman numeral small c U+217D
    //   t → t   plain
    //   e → е   Cyrillic
    //   d → ԁ   Cyrillic komi-de U+0501
    let evaded = "\u{0443}0\u{1D42E}r \u{0441}\u{03BF}m\u{0440}u\u{0442}3r \u{0456}\u{0455} \
                  1n\u{0192}\u{0435}\u{217D}t\u{0435}\u{0501}";
    let normalized = muten_overlay::confusables::normalize_for_match(evaded);
    assert_eq!(
        normalized, "your computer is infected",
        "stacked evasion must normalize back to the plain phrase, got: {normalized:?}"
    );
}

#[test]
fn stacked_evasion_with_zero_width_still_blocks() {
    let rs = load_example_blocklist();
    // Same stacked-homoglyph phrase, now ALSO sprayed with zero-width spaces
    // between every character — the worst realistic case.
    let evaded = "\u{0443}0\u{1D42E}r \u{0441}\u{03BF}m\u{0440}u\u{0442}3r \u{0456}\u{0455} \
                  1n\u{0192}\u{0435}\u{217D}t\u{0435}\u{0501}";
    let zw = interleave_zero_width(evaded);
    let v = classify(&alert(&zw), &rs);
    assert!(
        v.signals.iter().any(|s| s == "blocklist_title"),
        "stacked+zero-width evasion must still fire blocklist_title: {:?}",
        v.signals
    );
    assert_eq!(
        v.decision,
        Decision::Block,
        "a coercive overlay with a (disguised) blocklisted title must Block"
    );
}

#[test]
fn stacked_evasion_with_combining_marks_still_blocks() {
    let rs = load_example_blocklist();
    // "security alert" — homoglyphs + a combining strikethrough (U+0337) after
    // several characters (Zalgo-style), proving the combining-mark layer composes.
    //   s→ѕ(Cyr) e→е(Cyr) c→ϲ(Greek lunate sigma) u→u r→r i→і(Cyr) t→т(Cyr) y→у(Cyr)
    //   alert: a→а(Cyr) l→ⅼ(Roman) e→3(leet) r→r t→т(Cyr)
    let base = "\u{0455}\u{0435}\u{03F2}urі\u{0442}\u{0443} \u{0430}\u{217C}3r\u{0442}";
    // Splice a combining short-solidus overlay after every char.
    let zalgo: String = base.chars().flat_map(|c| [c, '\u{0337}']).collect();
    let v = classify(&alert(&zalgo), &rs);
    assert!(
        v.signals.iter().any(|s| s == "blocklist_title"),
        "homoglyph+combining-mark 'security alert' must fire blocklist_title: {:?}",
        v.signals
    );
    assert_eq!(v.decision, Decision::Block);
}

#[test]
fn stacked_evasion_spread_characters_still_blocks() {
    let rs = load_example_blocklist();
    // "virus detected" spread with mixed separators (R23 set) AND homoglyphs:
    // v·i·r·u·s with middle-dots, then a homoglyph-disguised "detected".
    //   virus: v i r u s spread by '·' (U+00B7) and '∙' (U+2219)
    //   detected: d→ԁ(Cyr) e→е(Cyr) t→т(Cyr) e→3 c→с(Cyr) t→t e→е d→d
    let spread_virus = "v\u{00B7}i\u{2219}r\u{00B7}u\u{2219}s";
    let homo_detected = "\u{0501}\u{0435}\u{0442}3\u{0441}t\u{0435}d";
    let title = format!("{spread_virus} {homo_detected}");
    let v = classify(&alert(&title), &rs);
    assert!(
        v.signals.iter().any(|s| s == "blocklist_title"),
        "spread+homoglyph 'virus detected' must fire blocklist_title: {:?}",
        v.signals
    );
    assert_eq!(v.decision, Decision::Block);
}

#[test]
fn benign_lookalike_title_does_not_block() {
    // False-positive control: the stacked normalization must not *fabricate* a
    // blocklist_title match on benign text. We use a benign *shape* here
    // (windowed, closable, user-initiated) so the decision reflects the title
    // alone — a maximally coercive shape would Block on shape score regardless
    // of title (fullscreen+topmost+no-close+blocks-input+unsolicited = 120),
    // which is correct behaviour but would not isolate the normalization.
    let rs = load_example_blocklist();
    let benign = OverlayWindow {
        title: "Quarterly Revenue Presentation — Q3 2026".to_string(),
        url: None,
        coverage_percent: 60,
        topmost: false,
        has_close_button: true,
        blocks_input: false,
        origin: Origin::UserInitiated,
        age_ms: 5_000,
    };
    let v = classify(&benign, &rs);
    assert!(
        !v.signals.iter().any(|s| s == "blocklist_title"),
        "benign title must not fire a phantom blocklist_title: {:?}",
        v.signals
    );
    assert_eq!(
        v.decision,
        Decision::Allow,
        "a benign, closable, user-initiated presentation must Allow, got {:?}",
        v.decision
    );
}
