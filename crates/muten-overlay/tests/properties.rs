//! Property-based tests for overlay classification.
//!
//! Two things must always hold no matter the input:
//! 1. The classifier and the blocklist parser never panic.
//! 2. The score is monotone in each "more suspicious" signal — adding
//!    a scam signal never *lowers* the score, and the decision
//!    thresholds are consistent with the score.

use muten_overlay::{classify, Decision, Origin, OverlayWindow, Ruleset};
use muten_overlay::{BLOCK_THRESHOLD, SUSPICIOUS_THRESHOLD};
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
        title in ".*",
        has_url in any::<bool>(),
        host in "[a-z]{1,10}\\.[a-z]{2,4}",
        coverage in 0u8..=100,
        topmost in any::<bool>(),
        has_close in any::<bool>(),
        blocks_input in any::<bool>(),
        origin in origin_strategy(),
        age_ms in 0u64..100_000,
    ) -> OverlayWindow {
        OverlayWindow {
            title,
            url: if has_url { Some(format!("http://{host}/x")) } else { None },
            coverage_percent: coverage,
            topmost,
            has_close_button: has_close,
            blocks_input,
            origin,
            age_ms,
        }
    }
}

proptest! {
    /// classify never panics, and the decision is always consistent
    /// with the reported score and the published thresholds.
    #[test]
    fn classify_never_panics_and_is_threshold_consistent(w in window_strategy()) {
        let v = classify(&w, &Ruleset::default());
        prop_assert!(v.score >= 0, "score must be clamped non-negative");
        // matched_rule from the default (empty) ruleset is always None.
        prop_assert!(v.matched_rule.is_none());
        match v.decision {
            Decision::Block => prop_assert!(v.score >= BLOCK_THRESHOLD),
            Decision::Suspicious => prop_assert!(
                v.score >= SUSPICIOUS_THRESHOLD && v.score < BLOCK_THRESHOLD
            ),
            Decision::Allow => prop_assert!(v.score < SUSPICIOUS_THRESHOLD),
        }
    }

    /// Removing the close button never lowers the score (it's a
    /// suspicious signal). Monotonicity in the no_close dimension.
    #[test]
    fn removing_close_button_does_not_lower_score(w in window_strategy()) {
        let mut with_close = w.clone();
        with_close.has_close_button = true;
        let mut without = w.clone();
        without.has_close_button = false;
        let s_with = classify(&with_close, &Ruleset::default()).score;
        let s_without = classify(&without, &Ruleset::default()).score;
        prop_assert!(s_without >= s_with);
    }

    /// Marking origin Unsolicited never lowers the score vs Unknown,
    /// and UserInitiated never raises it vs Unknown.
    #[test]
    fn origin_ordering_is_monotone(w in window_strategy()) {
        let mut unknown = w.clone();
        unknown.origin = Origin::Unknown;
        let mut unsolicited = w.clone();
        unsolicited.origin = Origin::Unsolicited;
        let mut user = w.clone();
        user.origin = Origin::UserInitiated;

        let s_unknown = classify(&unknown, &Ruleset::default()).score;
        let s_unsol = classify(&unsolicited, &Ruleset::default()).score;
        let s_user = classify(&user, &Ruleset::default()).score;

        prop_assert!(s_unsol >= s_unknown, "unsolicited must not lower score");
        prop_assert!(s_user <= s_unknown, "user-initiated must not raise score");
    }

    /// A host blocklist hit always yields Block regardless of any
    /// other (benign) signals.
    #[test]
    fn blocklisted_host_always_blocks(
        coverage in 0u8..=100,
        has_close in any::<bool>(),
        origin in origin_strategy(),
    ) {
        let rules = Ruleset::from_lines(&["host: scam.example"]);
        let w = OverlayWindow {
            title: "anything".into(),
            url: Some("http://scam.example/page".into()),
            coverage_percent: coverage,
            topmost: false,
            has_close_button: has_close,
            blocks_input: false,
            origin,
            age_ms: 9_999,
        };
        let v = classify(&w, &rules);
        prop_assert_eq!(v.decision, Decision::Block);
        prop_assert_eq!(v.matched_rule.as_deref(), Some("scam.example"));
    }

    /// The blocklist parser never panics on arbitrary text.
    #[test]
    fn ruleset_parse_never_panics(raw in ".*") {
        let _ = Ruleset::parse(&raw);
    }

    /// match_host never panics on arbitrary url-ish input.
    #[test]
    fn match_host_never_panics(url in ".*") {
        let rs = Ruleset::from_lines(&["host: evil.example"]);
        let _ = rs.match_host(&url);
    }

    /// A subdomain of a blocked host always matches the registered
    /// host (suffix matching), for any label prefix.
    #[test]
    fn subdomain_always_matches(prefix in "[a-z]{1,8}(\\.[a-z]{1,8}){0,3}") {
        let rs = Ruleset::from_lines(&["host: evil.example"]);
        let url = format!("http://{prefix}.evil.example/x");
        prop_assert_eq!(rs.match_host(&url), Some("evil.example".to_string()));
    }

    /// The phone-number detector never panics on arbitrary input.
    #[test]
    fn contains_phone_number_never_panics(s in ".*") {
        let _ = muten_overlay::contains_phone_number(&s);
    }

    /// Any string of <7 digits total (with separators) is never a
    /// phone number.
    #[test]
    fn short_digit_strings_are_not_phones(
        groups in prop::collection::vec(0u32..99, 1..3),
    ) {
        let s = groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join("-");
        let total_digits: usize = s.chars().filter(|c| c.is_ascii_digit()).count();
        if total_digits < 7 {
            prop_assert!(!muten_overlay::contains_phone_number(&s));
        }
    }

    /// Confusable folding is idempotent: folding twice equals folding
    /// once, for any input.
    #[test]
    fn fold_confusables_is_idempotent(s in ".*") {
        let once = muten_overlay::confusables::fold_confusables(&s);
        let twice = muten_overlay::confusables::fold_confusables(&once);
        prop_assert_eq!(once, twice);
    }

    /// Folding preserves the character count (1:1 mapping), never
    /// growing the string.
    #[test]
    fn fold_confusables_preserves_char_count(s in ".*") {
        let folded = muten_overlay::confusables::fold_confusables(&s);
        prop_assert_eq!(folded.chars().count(), s.chars().count());
    }

    /// Plain ASCII is a fixed point of folding.
    #[test]
    fn fold_leaves_ascii_unchanged(s in "[ -~]*") {
        prop_assert_eq!(muten_overlay::confusables::fold_confusables(&s), s);
    }

    /// The full match-normalization pipeline never panics and is
    /// idempotent for any input.
    #[test]
    fn normalize_for_match_is_idempotent(s in ".*") {
        let once = muten_overlay::confusables::normalize_for_match(&s);
        let twice = muten_overlay::confusables::normalize_for_match(&once);
        prop_assert_eq!(once, twice);
    }

    /// Stripping invisibles never *grows* the string and is
    /// idempotent (a second pass removes nothing).
    #[test]
    fn strip_invisibles_shrinks_and_is_idempotent(s in ".*") {
        let once = muten_overlay::confusables::strip_invisibles(&s);
        prop_assert!(once.chars().count() <= s.chars().count());
        let twice = muten_overlay::confusables::strip_invisibles(&once);
        prop_assert_eq!(once, twice);
    }

    /// Mixed-script detection never panics on arbitrary Unicode.
    #[test]
    fn has_mixed_script_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_confusable_mixed_script(&s);
    }

    /// A title that is already a single script (here: any ASCII) is
    /// never flagged as mixed-script — the signal requires a
    /// within-token Latin↔Cyrillic/Greek mix.
    #[test]
    fn ascii_is_never_mixed_script(s in "[ -~]*") {
        prop_assert!(!muten_overlay::confusables::has_confusable_mixed_script(&s));
    }

    /// explain() never panics and is non-empty for any classified
    /// window; it ends with a period.
    #[test]
    fn explain_is_well_formed(w in window_strategy()) {
        let v = classify(&w, &Ruleset::default());
        let why = v.explain();
        prop_assert!(!why.is_empty());
        prop_assert!(why.ends_with('.'));
    }

    // ── v0.5.0 new-signal invariants ───────────────────────────────

    /// Whole-script confusable detection never panics on arbitrary input.
    #[test]
    fn has_whole_script_confusable_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_whole_script_confusable(&s);
    }

    /// Pure ASCII can never be a whole-script confusable (no Cyrillic or
    /// Greek letters can appear in a pure-ASCII string).
    #[test]
    fn ascii_is_never_whole_script_confusable(s in "[ -~]*") {
        prop_assert!(!muten_overlay::confusables::has_whole_script_confusable(&s));
    }

    /// BiDi override detection never panics on arbitrary input.
    #[test]
    fn has_bidi_override_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_bidi_override(&s);
    }

    /// Pure ASCII (U+0000-U+007F) contains no BiDi override characters.
    #[test]
    fn ascii_has_no_bidi_override(s in "[ -~]*") {
        prop_assert!(!muten_overlay::confusables::has_bidi_override(&s));
    }

    /// Compatibility-alpha detection never panics on arbitrary input.
    #[test]
    fn has_compat_alpha_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_compat_alpha(&s);
    }

    /// Mixed-number-system detection never panics on arbitrary input.
    #[test]
    fn has_mixed_number_systems_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_mixed_number_systems(&s);
    }

    /// Pure ASCII can never mix numbering systems (all its digits are the
    /// single "western" system).
    #[test]
    fn ascii_never_mixes_number_systems(s in "[ -~]*") {
        prop_assert!(!muten_overlay::confusables::has_mixed_number_systems(&s));
    }

    /// Pure ASCII (U+0020-U+007E) contains no enclosed letters (which
    /// start at U+24B6, well above the ASCII range).
    #[test]
    fn ascii_has_no_compat_alpha(s in "[ -~]*") {
        prop_assert!(!muten_overlay::confusables::has_compat_alpha(&s));
    }

    /// `fold_char` is idempotent: folding a char twice equals folding once.
    /// This covers the new enclosed-letter ranges added in v0.5.0.
    #[test]
    fn fold_char_is_idempotent(s in ".*") {
        for c in s.chars() {
            let once = muten_overlay::confusables::fold_char(c);
            let twice = muten_overlay::confusables::fold_char(once);
            prop_assert_eq!(once, twice);
        }
    }
}
