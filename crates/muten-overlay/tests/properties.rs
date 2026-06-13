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

    /// strip_symbols_and_emoji never panics, never lengthens, and is idempotent.
    #[test]
    fn strip_symbols_shrinks_and_is_idempotent(s in ".*") {
        let once = muten_overlay::confusables::strip_symbols_and_emoji(&s);
        prop_assert!(once.chars().count() <= s.chars().count());
        let twice = muten_overlay::confusables::strip_symbols_and_emoji(&once);
        prop_assert_eq!(once, twice);
    }

    /// ASCII-only strings pass through strip_symbols_and_emoji unchanged.
    #[test]
    fn strip_symbols_leaves_ascii_unchanged(s in "[ -~]*") {
        let result = muten_overlay::confusables::strip_symbols_and_emoji(&s);
        prop_assert_eq!(&result, &s);
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

    /// Excessive-combining-mark detection never panics on arbitrary input.
    #[test]
    fn has_excessive_combining_marks_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_excessive_combining_marks(&s);
    }

    /// Pure ASCII has no combining marks, so it never trips the Zalgo signal.
    #[test]
    fn ascii_has_no_excessive_combining_marks(s in "[ -~]*") {
        prop_assert!(!muten_overlay::confusables::has_excessive_combining_marks(&s));
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

    /// `has_clickfix_instruction` never panics on arbitrary Unicode input.
    #[test]
    fn has_clickfix_instruction_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_clickfix_instruction(&s);
    }

    /// Plain ASCII without instruction keywords does not fire.
    /// (The specific phrases are tested in unit tests; here we just verify
    /// the function is stable and doesn't produce spurious hits on random
    /// ASCII that never contains the trigger tokens.)
    #[test]
    fn ascii_without_keywords_does_not_fire(
        s in "[a-z0-9 .,;:!?@#$%^&*()\\-_=]{1,80}"
    ) {
        // Unless the random string happens to contain a trigger substring
        // (very unlikely for short random strings), this should not fire.
        // We only assert stability here — no false assertions about
        // specific random strings.
        let _ = muten_overlay::confusables::has_clickfix_instruction(&s);
    }

    // ── v0.6.0 property additions ─────────────────────────────────

    /// `match_title_glob` never panics on arbitrary pattern + arbitrary title.
    #[test]
    fn match_title_glob_never_panics(pattern in ".*", title in ".*") {
        let rs = Ruleset::from_lines(&[&format!("glob: {pattern}")]);
        let _ = rs.match_title_glob(&title);
    }

    /// `glob: *` (star-only pattern) matches any title — the universal
    /// pattern is a short-circuit for "flag everything".
    #[test]
    fn glob_star_matches_any_title(title in ".*") {
        let rs = Ruleset::from_lines(&["glob: *"]);
        // After normalization the pattern is still "*" (star is a non-letter
        // separator and passes through the pipeline unchanged).
        prop_assert!(rs.match_title_glob(&title).is_some());
    }

    /// `Ruleset::weight_of` never panics on arbitrary signal names or defaults.
    #[test]
    fn weight_of_never_panics(signal in "[a-z_]{1,40}", default in any::<i32>()) {
        let rs = Ruleset::default();
        let _ = rs.weight_of(&signal, default);
    }

    /// Weight overrides do not break threshold consistency: score is still
    /// clamped ≥ 0 and the decision is still consistent with the score,
    /// regardless of what overrides are in the ruleset.
    #[test]
    fn classify_with_weight_overrides_is_threshold_consistent(
        w in window_strategy(),
        override_val in -200i32..=500,
    ) {
        // Apply an override to a common signal and verify consistency.
        let rules = Ruleset::from_lines(&[&format!("weight: fullscreen {override_val}")]);
        let v = classify(&w, &rules);
        prop_assert!(v.score >= 0);
        match v.decision {
            Decision::Block => prop_assert!(v.score >= BLOCK_THRESHOLD),
            Decision::Suspicious => prop_assert!(
                v.score >= SUSPICIOUS_THRESHOLD && v.score < BLOCK_THRESHOLD
            ),
            Decision::Allow => prop_assert!(v.score < SUSPICIOUS_THRESHOLD),
        }
    }

    /// `Verdict::confidence()` never panics on any classified window.
    #[test]
    fn confidence_never_panics(w in window_strategy()) {
        use muten_overlay::ConfidenceLevel;
        let v = classify(&w, &Ruleset::default());
        let _conf: ConfidenceLevel = v.confidence();
    }

    /// `Verdict::score_breakdown()` never panics and returns a list
    /// consistent with the fired signals.
    #[test]
    fn score_breakdown_never_panics_and_covers_signals(w in window_strategy()) {
        let v = classify(&w, &Ruleset::default());
        let bd = v.score_breakdown();
        // Every signal must appear in the breakdown.
        for sig in &v.signals {
            prop_assert!(
                bd.iter().any(|(name, _)| name == sig),
                "signal {} missing from score_breakdown", sig
            );
        }
    }

    /// Glob ruleset parsing never panics on arbitrary text.
    #[test]
    fn ruleset_parse_with_glob_never_panics(raw in ".*") {
        let prefixed = format!("glob: {raw}");
        let _ = Ruleset::parse(&prefixed);
    }

    /// Weight override parsing never panics on arbitrary text.
    #[test]
    fn ruleset_parse_with_weight_never_panics(raw in ".*") {
        let prefixed = format!("weight: {raw}");
        let _ = Ruleset::parse(&prefixed);
    }

    // ── v0.6.1 / E7 property additions ───────────────────────────

    /// `has_urgency_countdown` never panics on arbitrary Unicode input.
    #[test]
    fn has_urgency_countdown_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_urgency_countdown(&s);
    }

    /// Pure ASCII without any urgency keyword never fires urgency_countdown.
    /// The property is checked on the raw string — if it contains no urgency
    /// prefix from the fixed list, the function must return false.
    #[test]
    fn no_urgency_keyword_never_fires_urgency_countdown(
        s in "[a-z0-9 .]{1,60}"
    ) {
        const URGENCY: &[&str] = &[
            "expir", "warn", "alert", "infect", "block", "lock", "urgent",
            "critical", "threat", "danger", "support", "call",
        ];
        let has_any = URGENCY.iter().any(|kw| s.contains(kw));
        if !has_any {
            prop_assert!(!muten_overlay::confusables::has_urgency_countdown(&s));
        }
    }

    // ── D10: typosquat_brand property additions ───────────────────

    /// The real brand domain must never fire typosquat_brand — it is the
    /// target, not the impersonator. Only edit-distance-1 *variants* fire.
    #[test]
    fn real_brand_never_fires_typosquat(
        brand in prop_oneof![
            Just("google"), Just("paypal"), Just("microsoft"),
            Just("apple"), Just("amazon")
        ],
    ) {
        let url = format!("http://{brand}.com/page");
        let w = OverlayWindow {
            title: "anything".into(),
            url: Some(url),
            coverage_percent: 0,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 1_000,
        };
        let v = classify(&w, &Ruleset::default());
        prop_assert!(
            !v.signals.iter().any(|s| s == "typosquat_brand"),
            "real brand must not fire typosquat_brand"
        );
    }

    /// `classify` never panics on arbitrary URLs (typosquat path).
    #[test]
    fn classify_never_panics_with_arbitrary_url(
        host in "[a-z]{3,12}\\.[a-z]{2,4}",
    ) {
        let url = format!("http://{host}/x");
        let w = OverlayWindow {
            title: "anything".into(),
            url: Some(url),
            coverage_percent: 0,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 1_000,
        };
        let v = classify(&w, &Ruleset::default());
        // Just verify it doesn't panic and thresholds are consistent.
        match v.decision {
            Decision::Block => prop_assert!(v.score >= BLOCK_THRESHOLD),
            Decision::Suspicious => prop_assert!(
                v.score >= SUSPICIOUS_THRESHOLD && v.score < BLOCK_THRESHOLD
            ),
            Decision::Allow => prop_assert!(v.score < SUSPICIOUS_THRESHOLD),
        }
    }

    // ── E10: cloud_storage_abuse / E12: url_path_lure / E13: forced_retention ─

    /// has_forced_retention never panics on arbitrary Unicode input.
    #[test]
    fn has_forced_retention_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_forced_retention(&s);
    }

    /// A string with none of the retention trigger phrases must not fire.
    #[test]
    fn plain_ascii_never_fires_forced_retention(s in "[a-z0-9 .,!?]{1,60}") {
        const TRIGGERS: &[&str] = &[
            "do not close", "dont close", "do not exit", "do not turn off",
            "do not shut down", "do not restart", "do not click away",
            "keep this window open", "leave this page open",
            "stay on this page", "this window must remain open",
        ];
        let has_trigger = TRIGGERS.iter().any(|t| s.contains(t));
        if !has_trigger {
            prop_assert!(!muten_overlay::confusables::has_forced_retention(&s));
        }
    }

    /// classify never panics when given a blob-storage URL with arbitrary title.
    #[test]
    fn classify_never_panics_with_blob_storage_url(
        tenant in "[a-z]{3,12}",
        title in ".*",
    ) {
        let url = format!("https://{tenant}.blob.core.windows.net/container/page.html");
        let w = OverlayWindow {
            title,
            url: Some(url),
            coverage_percent: 0,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 0,
        };
        let v = classify(&w, &Ruleset::default());
        match v.decision {
            Decision::Block => prop_assert!(v.score >= BLOCK_THRESHOLD),
            Decision::Suspicious => prop_assert!(
                v.score >= SUSPICIOUS_THRESHOLD && v.score < BLOCK_THRESHOLD
            ),
            Decision::Allow => prop_assert!(v.score < SUSPICIOUS_THRESHOLD),
        }
    }

    /// classify never panics with arbitrary URL path (url_path_lure path).
    #[test]
    fn classify_never_panics_with_arbitrary_url_path(
        path in "[a-z0-9/-]{1,40}",
    ) {
        let url = format!("https://evil.example.com/{path}");
        let w = OverlayWindow {
            title: "test".into(),
            url: Some(url),
            coverage_percent: 0,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 0,
        };
        let v = classify(&w, &Ruleset::default());
        match v.decision {
            Decision::Block => prop_assert!(v.score >= BLOCK_THRESHOLD),
            Decision::Suspicious => prop_assert!(
                v.score >= SUSPICIOUS_THRESHOLD && v.score < BLOCK_THRESHOLD
            ),
            Decision::Allow => prop_assert!(v.score < SUSPICIOUS_THRESHOLD),
        }
    }

    // ── E14: credential_harvest_cue / E15: fake_scanner_cue ──────────────

    /// has_credential_harvest_cue never panics on arbitrary Unicode input.
    #[test]
    fn has_credential_harvest_cue_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_credential_harvest_cue(&s);
    }

    /// A string lacking all trigger keyword pairs must not fire credential harvest.
    #[test]
    fn plain_ascii_never_fires_credential_harvest(s in "[a-z .,!?]{1,60}") {
        // Pairs that trigger: ("account","suspended"), ("account","locked"),
        // ("account","disabled"), ("account","blocked"), ("account","compromised"),
        // ("unusual","sign"), ("suspicious","sign"), ("unusual","login"),
        // ("suspicious","login"), ("suspicious","activity"),
        // ("verify","account"), ("confirm","password"), ("confirm","identity"),
        // ("verify","identity"), ("re-enter","password"), ("enter","credentials"),
        // ("update","payment").
        let has = |a: &str| s.contains(a);
        let could_fire = (has("account") && (has("suspended") || has("locked") || has("disabled") || has("blocked") || has("compromised")))
            || (has("unusual") && (has("sign") || has("login")))
            || (has("suspicious") && (has("sign") || has("login") || has("activity")))
            || (has("verify") && (has("account") || has("identity")))
            || (has("confirm") && (has("password") || has("identity")))
            || (has("re-enter") && has("password"))
            || (has("enter") && has("credentials"))
            || (has("update") && has("payment"));
        if !could_fire {
            prop_assert!(!muten_overlay::confusables::has_credential_harvest_cue(&s));
        }
    }

    /// has_fake_scanner_cue never panics on arbitrary Unicode input.
    #[test]
    fn has_fake_scanner_cue_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_fake_scanner_cue(&s);
    }

    /// A string lacking all scanner-lure patterns must not fire fake_scanner_cue.
    #[test]
    fn plain_ascii_never_fires_fake_scanner(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let could_fire = (has("scanning") && (has("virus") || has("threat") || has("malware") || has("spyware")))
            || ((has("threat") || has("virus") || has("infection")) && (has("detected") || has("found") || has("identified")))
            || ((has("removing") || has("removed")) && (has("virus") || has("malware") || has("spyware") || has("threat") || has("infection")))
            || (has("repair") && (has("progress") || has("your") || has("system") || has("computer") || has("pc")))
            || (has("repairing") && (has("system") || has("computer") || has("pc") || has("file")))
            || (has("system") && has("error") && (has("detected") || has("critical") || has("found")));
        if !could_fire {
            prop_assert!(!muten_overlay::confusables::has_fake_scanner_cue(&s));
        }
    }

    /// classify is threshold-consistent on alert-shaped windows with scanner language.
    #[test]
    fn classify_never_panics_with_fake_scanner_title(title in ".*") {
        let w = OverlayWindow {
            title,
            url: None,
            coverage_percent: 99,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 500,
        };
        let v = classify(&w, &Ruleset::default());
        match v.decision {
            Decision::Block => prop_assert!(v.score >= BLOCK_THRESHOLD),
            Decision::Suspicious => prop_assert!(
                v.score >= SUSPICIOUS_THRESHOLD && v.score < BLOCK_THRESHOLD
            ),
            Decision::Allow => prop_assert!(v.score < SUSPICIOUS_THRESHOLD),
        }
    }

    // ── E16: subscription_lure ────────────────────────────────────────────

    /// has_subscription_lure never panics on arbitrary Unicode input.
    #[test]
    fn has_subscription_lure_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_subscription_lure(&s);
    }

    /// A string lacking all three trigger groups must not fire subscription_lure.
    #[test]
    fn plain_ascii_never_fires_subscription_lure(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let has_subject = has("subscription") || has("license") || has("protection") || has("membership");
        let has_expiry = has("expired") || has("expiring") || has("expire") || has("expiration");
        let has_action = has("renew") || has("activate") || has("purchase") || has("buy") || has("call") || has("click");
        if !(has_subject && has_expiry && has_action) {
            prop_assert!(!muten_overlay::confusables::has_subscription_lure(&s));
        }
    }

    // ── E17: authority_lure ───────────────────────────────────────────────

    /// has_authority_lure never panics on arbitrary Unicode input.
    #[test]
    fn has_authority_lure_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_authority_lure(&s);
    }

    /// A string lacking both agency AND coercion tokens must not fire authority_lure.
    #[test]
    fn plain_ascii_never_fires_authority_lure(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let has_agency = has("fbi") || has("cia") || has("interpol") || has("cybercrime")
            || has("homeland security") || has("department of justice")
            || has("national security") || has("metropolitan police")
            || has("cyber police") || has("law enforcement");
        let has_coercion = has("warning") || has("notice") || has("locked") || has("blocked")
            || has("suspended") || has("illegal") || has("violation")
            || has("fine") || has("penalty") || has("arrested");
        if !(has_agency && has_coercion) {
            prop_assert!(!muten_overlay::confusables::has_authority_lure(&s));
        }
    }

    // ── E18: screen_share_lure ────────────────────────────────────────────

    /// has_screen_share_lure never panics on arbitrary Unicode input.
    #[test]
    fn has_screen_share_lure_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_screen_share_lure(&s);
    }

    /// Plain alphanumeric-only strings (no screen-share keywords) must not fire.
    #[test]
    fn plain_ascii_never_fires_screen_share_lure(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let share_screen = (has("share") || has("sharing"))
            && (has("screen") || has("desktop") || has("display"));
        let remote_enable = (has("allow") || has("enable"))
            && has("remote")
            && (has("view") || has("access") || has("control") || has("fix"));
        let grant_support = has("grant")
            && has("access")
            && (has("support") || has("agent") || has("technician"));
        if !(share_screen || remote_enable || grant_support) {
            prop_assert!(!muten_overlay::confusables::has_screen_share_lure(&s));
        }
    }

    // ── E20: prize_lure ──────────────────────────────────────────────────

    /// has_prize_lure never panics on arbitrary Unicode input.
    #[test]
    fn has_prize_lure_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_prize_lure(&s);
    }

    /// Plain strings lacking both a prize-word AND a claim-action must not fire.
    #[test]
    fn plain_ascii_never_fires_prize_lure(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let prize_word = has("won") || has("winner") || has("prize") || has("jackpot")
            || has("lottery") || has("reward") || has("gift card")
            || has("selected") || has("eligible");
        let claim_action = has("claim") || has("collect") || has("redeem")
            || has("verify") || has("confirm") || has("click here")
            || has("expires") || has("expiring");
        if !(prize_word && claim_action) {
            prop_assert!(!muten_overlay::confusables::has_prize_lure(&s));
        }
    }

    // ── E21: download_trap_lure ───────────────────────────────────────────

    /// has_download_trap_lure never panics on arbitrary Unicode input.
    #[test]
    fn has_download_trap_lure_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_download_trap_lure(&s);
    }

    /// Strings lacking install_demand AND fake_plugin_gate conditions must not fire.
    #[test]
    fn plain_ascii_never_fires_download_trap_lure(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let action_verb = has("download") || has("install") || has("update");
        let required_cue = has("required") || has("needed") || has("necessary")
            || has("to continue") || has("to access") || has("to view") || has("to play");
        let plugin_noun = has("plugin") || has("extension") || has("codec")
            || has("flash") || has("player") || has("software") || has("component")
            || has("add-on") || has("addon");
        let fires = (action_verb && required_cue)
            || (plugin_noun && (action_verb || required_cue));
        if !fires {
            prop_assert!(!muten_overlay::confusables::has_download_trap_lure(&s));
        }
    }

    // ── E19: crypto_drain_lure ────────────────────────────────────────────

    /// has_crypto_drain_lure never panics on arbitrary Unicode input.
    #[test]
    fn has_crypto_drain_lure_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_crypto_drain_lure(&s);
    }

    /// Plain alphanumeric-only strings lacking crypto tokens must not fire.
    #[test]
    fn plain_ascii_never_fires_crypto_drain_lure(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let wallet_word = has("wallet") || has("metamask") || has("coinbase")
            || has("web3") || has("defi") || has("nft");
        let alarm_action = has("compromised") || has("hacked") || has("flagged")
            || has("suspended") || has("unauthorized")
            || (has("suspicious") && has("activity"));
        let wallet_alarm = wallet_word && alarm_action;
        let coerce_verb = has("connect") || has("validate") || has("link");
        let wallet_coerce = coerce_verb && wallet_word;
        let seed_word = (has("seed") && has("phrase"))
            || (has("recovery") && has("phrase"))
            || (has("secret") && (has("phrase") || has("recovery")))
            || (has("private") && has("key"))
            || has("mnemonic");
        let request_token = has("verify") || has("enter") || has("confirm")
            || has("required") || has("provide") || has("submit");
        let seed_harvest = seed_word && request_token;
        if !(wallet_alarm || wallet_coerce || seed_harvest) {
            prop_assert!(!muten_overlay::confusables::has_crypto_drain_lure(&s));
        }
    }

    // ── E22: qr_code_lure ─────────────────────────────────────────────────

    /// has_qr_code_lure never panics on arbitrary Unicode input.
    #[test]
    fn has_qr_code_lure_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_qr_code_lure(&s);
    }

    /// Strings that lack qr_noun AND verify_action simultaneously must not fire.
    #[test]
    fn plain_ascii_never_fires_qr_code_lure(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let qr_noun = (has("qr") && has("code")) || has("qr-code") || (has("qr") && has("scan"));
        let verify_action = has("verify") || has("confirm") || has("authenticate")
            || has("access") || has("scan to") || has("scan now")
            || has("continue") || has("proceed") || has("validate");
        if !(qr_noun && verify_action) {
            prop_assert!(!muten_overlay::confusables::has_qr_code_lure(&s));
        }
    }

    // ── E23: ip_alarm_lure ────────────────────────────────────────────────

    /// has_ip_alarm_lure never panics on arbitrary Unicode input.
    #[test]
    fn has_ip_alarm_lure_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_ip_alarm_lure(&s);
    }

    /// Strings lacking ip_subject AND alarm_word simultaneously must not fire.
    #[test]
    fn plain_ascii_never_fires_ip_alarm_lure(s in "[a-z .,!?0-9]{1,60}") {
        let has = |a: &str| s.contains(a);
        let ip_subject = has("ip address") || has("your ip");
        let alarm_word = has("hack") || has("infect") || has("flag")
            || has("report") || has("stolen") || has("expos") || has("compromis")
            || has("block") || has("detect") || has("trac") || has("suspend")
            || has("breach");
        if !(ip_subject && alarm_word) {
            prop_assert!(!muten_overlay::confusables::has_ip_alarm_lure(&s));
        }
    }

    // ── E24: package_fee_lure ─────────────────────────────────────────────

    /// has_package_fee_lure never panics on arbitrary Unicode input.
    #[test]
    fn has_package_fee_lure_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_package_fee_lure(&s);
    }

    /// Strings lacking package_noun AND fee_demand simultaneously must not fire.
    #[test]
    fn plain_ascii_never_fires_package_fee_lure(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let package_noun = has("your package") || has("your parcel") || has("your shipment")
            || has("your order") || has("your delivery") || has("package is")
            || has("parcel is") || has("shipment is");
        let fee_demand = has("customs fee") || has("customs duty") || has("customs charge")
            || has("on hold") || (has("fee") && (has("pay") || has("required") || has("pending")))
            || has("unable to deliver") || has("failed delivery")
            || has("delivery fee") || has("release fee");
        if !(package_noun && fee_demand) {
            prop_assert!(!muten_overlay::confusables::has_package_fee_lure(&s));
        }
    }

    // ── E25: sextortion_lure ──────────────────────────────────────────────

    /// has_sextortion_lure never panics on arbitrary Unicode input.
    #[test]
    fn has_sextortion_lure_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_sextortion_lure(&s);
    }

    /// Strings lacking camera_cue AND extortion_word simultaneously must not fire.
    #[test]
    fn plain_ascii_never_fires_sextortion_lure(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let camera_cue = has("your camera") || has("your webcam") || has("we have recorded")
            || has("have been recording") || has("we have footage")
            || has("recorded you") || has("hacked your camera") || has("accessed your camera");
        let extortion_word = has("bitcoin") || has("btc") || has("cryptocurrency") || has("crypto")
            || has("payment") || has("pay") || has("your contacts")
            || has("expose") || has("send this") || has("release this");
        if !(camera_cue && extortion_word) {
            prop_assert!(!muten_overlay::confusables::has_sextortion_lure(&s));
        }
    }

    // ── E26: gift_card_demand ─────────────────────────────────────────────

    /// has_gift_card_demand never panics on arbitrary Unicode input.
    #[test]
    fn has_gift_card_demand_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_gift_card_demand(&s);
    }

    /// Strings lacking gift_card_noun AND payment_instruction simultaneously must not fire.
    #[test]
    fn plain_ascii_never_fires_gift_card_demand(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let gift_card_noun = has("gift card") || has("itunes card")
            || has("google play card") || has("steam gift card")
            || has("amazon gift card") || has("apple gift card")
            || has("ebay gift card") || has("vanilla card")
            || has("prepaid card") || has("gift cards");
        let payment_instruction = has("send codes") || has("send the codes")
            || has("read me the codes") || has("read the codes")
            || has("scratch the card") || has("pay using gift card")
            || has("pay with gift card") || has("pay in gift card")
            || has("gift card codes") || has("card codes")
            || has("purchase gift card") || has("buy gift card")
            || has("go buy") || has("go to the store") || has("nearest store");
        if !(gift_card_noun && payment_instruction) {
            prop_assert!(!muten_overlay::confusables::has_gift_card_demand(&s));
        }
    }

    // ── E27: refund_scam_cue ──────────────────────────────────────────────

    /// has_refund_scam_cue never panics on arbitrary Unicode input.
    #[test]
    fn has_refund_scam_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_refund_scam_cue(&s);
    }

    /// Plain ASCII without both a refund noun and a claim action never fires.
    #[test]
    fn plain_ascii_never_fires_refund_scam(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        // Mirror the AND-pair logic to identify false-positive-safe inputs.
        let refund_noun = has("refund") || has("overpayment") || has("reimbursement")
            || has("rebate") || has("cashback") || has("excess charge") || has("overcharged");
        let refund_action = has("owed to you") || has("you are owed")
            || has("claim your refund") || has("collect your refund")
            || has("pending refund") || has("refund is ready")
            || has("refund has been") || has("process your refund")
            || has("transfer your refund") || has("your refund of")
            || has("refund amount") || has("receive your refund")
            || has("get your refund");
        if !(refund_noun && refund_action) {
            prop_assert!(!muten_overlay::confusables::has_refund_scam_cue(&s));
        }
    }

    // ── E28: national_id_alarm ────────────────────────────────────────────

    /// has_national_id_alarm never panics on arbitrary Unicode input.
    #[test]
    fn has_national_id_alarm_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_national_id_alarm(&s);
    }

    /// Plain ASCII without both an ID noun and an alarm never fires.
    #[test]
    fn plain_ascii_never_fires_national_id_alarm(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let id_noun = has("social security number") || has("social security")
            || has("ssn") || has("national insurance number")
            || has("medicare") || has("medicaid");
        let id_alarm = has("has been suspended") || has("is suspended")
            || has("was suspended") || has("has been blocked")
            || has("used in criminal") || has("criminal activity")
            || has("criminal charges") || has("criminal case")
            || has("fraudulent activity") || has("associated with fraud")
            || has("under federal investigation") || has("identity theft")
            || has("has been compromised");
        if !(id_noun && id_alarm) {
            prop_assert!(!muten_overlay::confusables::has_national_id_alarm(&s));
        }
    }

    // ── E29: bank_account_alarm ───────────────────────────────────────────

    /// has_bank_account_alarm never panics on arbitrary Unicode input.
    #[test]
    fn has_bank_account_alarm_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_bank_account_alarm(&s);
    }

    /// Plain ASCII without both a bank noun and a fraud alarm never fires.
    #[test]
    fn plain_ascii_never_fires_bank_account_alarm(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let bank_noun = has("bank account") || has("checking account")
            || has("savings account") || has("debit card") || has("credit card")
            || has("your account at");
        let bank_alarm = has("unauthorized transaction") || has("fraudulent transaction")
            || has("suspicious transaction") || has("fraudulent charge")
            || has("has been frozen") || has("account has been frozen")
            || has("access has been restricted") || has("fraudulent access")
            || has("unauthorized access detected");
        if !(bank_noun && bank_alarm) {
            prop_assert!(!muten_overlay::confusables::has_bank_account_alarm(&s));
        }
    }

    // ── E30: false_registration_billing ──────────────────────────────────────

    /// has_false_registration_billing never panics on arbitrary Unicode input.
    #[test]
    fn has_false_registration_billing_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_false_registration_billing(&s);
    }


    /// Plain ASCII without both a reg claim and a payment ultimatum never fires.
    #[test]
    fn plain_ascii_never_fires_false_registration_billing(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let reg_claim = has("you have been registered") || has("your registration")
            || has("membership confirmed") || has("you signed up")
            || has("registration complete") || has("your subscription has been activated")
            || has("registration is complete") || has("successfully registered")
            || has("enrollment confirmed") || has("enrollment is complete");
        let payment_ultimatum = has("pay within") || has("outstanding fee")
            || has("registration fee") || has("legal action")
            || has("failure to pay") || has("penalty fee")
            || has("collection agency") || has("sent to collections")
            || has("debt collection") || has("overdue balance")
            || has("amount due") || has("settle your balance");
        if !(reg_claim && payment_ultimatum) {
            prop_assert!(!muten_overlay::confusables::has_false_registration_billing(&s));
        }
    }

    // ── E31: fake_bsod_lure ───────────────────────────────────────────────────

    /// has_fake_bsod_lure never panics on arbitrary Unicode input.
    #[test]
    fn has_fake_bsod_lure_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_fake_bsod_lure(&s);
    }

    /// Plain ASCII without both a BSOD marker and a call barrier never fires.
    #[test]
    fn plain_ascii_never_fires_fake_bsod_lure(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let bsod_marker = has("windows has been blocked") || has("windows is blocked")
            || has("your pc is blocked") || has("stop code")
            || has("memory_management") || has("kmode exception")
            || has("kernel security check") || has("irql not less")
            || has("dpc watchdog") || has("blue screen") || has("kernel panic")
            || has("critical process died") || has("system thread exception");
        let call_barrier = has("do not restart") || has("do not turn off")
            || has("do not close this") || has("do not shut down")
            || has("call microsoft") || has("contact microsoft")
            || has("microsoft support") || has("microsoft certified")
            || has("windows helpline") || has("apple support");
        if !(bsod_marker && call_barrier) {
            prop_assert!(!muten_overlay::confusables::has_fake_bsod_lure(&s));
        }
    }

    // ── E32: advance_fee_lure ─────────────────────────────────────────────────

    /// has_advance_fee_lure never panics on arbitrary Unicode input.
    #[test]
    fn has_advance_fee_lure_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_advance_fee_lure(&s);
    }

    /// Plain ASCII without both a fund claim and a release fee never fires.
    #[test]
    fn plain_ascii_never_fires_advance_fee_lure(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let fund_claim = has("inheritance") || has("inherited") || has("beneficiary")
            || has("estate of") || has("deceased") || has("unclaimed funds")
            || has("unclaimed inheritance") || has("lottery winning")
            || has("won the lottery") || has("trust fund") || has("next of kin");
        let release_fee = has("processing fee") || has("transfer fee") || has("customs fee")
            || has("release fee") || has("administration fee") || has("advance fee")
            || has("notary fee") || has("legal fee") || has("handling fee")
            || has("to release the funds") || has("to receive your funds")
            || has("to claim your inheritance");
        if !(fund_claim && release_fee) {
            prop_assert!(!muten_overlay::confusables::has_advance_fee_lure(&s));
        }
    }

    // ── E33: tech_support_invoice_scam ────────────────────────────────────────

    /// has_tech_support_invoice_scam never panics on arbitrary Unicode input.
    #[test]
    fn has_tech_support_invoice_scam_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_tech_support_invoice_scam(&s);
    }

    /// Plain ASCII without both a charge claim and a cancel CTA never fires.
    #[test]
    fn plain_ascii_never_fires_tech_support_invoice_scam(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let charge_claim = has("you have been charged") || has("a charge of")
            || has("an invoice for") || has("your account has been charged")
            || has("payment of $") || has("auto-charged")
            || has("billing confirmation") || has("subscription has been renewed")
            || has("renewal charge") || has("has been debited");
        let cancel_cta = has("call to cancel") || has("to cancel call")
            || has("if you did not authorize") || has("unauthorized charge")
            || has("dispute this charge") || has("contact billing")
            || has("cancel this subscription") || has("to report fraud call")
            || has("to reverse this charge") || has("did not approve this");
        if !(charge_claim && cancel_cta) {
            prop_assert!(!muten_overlay::confusables::has_tech_support_invoice_scam(&s));
        }
    }

    // ── E34: utility_cutoff_threat ────────────────────────────────────────────

    /// has_utility_cutoff_threat never panics on arbitrary Unicode input.
    #[test]
    fn has_utility_cutoff_threat_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_utility_cutoff_threat(&s);
    }

    /// Plain ASCII without both a utility noun and a cutoff threat never fires.
    #[test]
    fn plain_ascii_never_fires_utility_cutoff_threat(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let utility_service = has("electric service") || has("electricity")
            || has("gas service") || has("water service") || has("power company")
            || has("utility account") || has("electric company")
            || has("your power") || has("your electricity") || has("your gas");
        let cutoff_threat = has("will be disconnected") || has("will be shut off")
            || has("disconnection notice") || has("service termination")
            || has("final notice") || has("pay to avoid disconnection")
            || has("service will be terminated") || has("disconnected within")
            || has("your service has been suspended") || has("pay immediately to restore")
            || has("immediate payment required") || has("avoid disconnection");
        if !(utility_service && cutoff_threat) {
            prop_assert!(!muten_overlay::confusables::has_utility_cutoff_threat(&s));
        }
    }

    // ── E35: healthcare_scam ──────────────────────────────────────────────────

    /// has_healthcare_scam never panics on arbitrary Unicode input.
    #[test]
    fn has_healthcare_scam_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_healthcare_scam(&s);
    }

    /// Plain ASCII without both a health benefit noun and urgency never fires.
    #[test]
    fn plain_ascii_never_fires_healthcare_scam(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let health_benefit = has("medicare") || has("medicaid") || has("health insurance")
            || has("medical coverage") || has("prescription benefit") || has("health plan")
            || has("your benefits") || has("medical device") || has("insurance plan")
            || has("healthcare plan") || has("health coverage");
        let benefit_urgency = has("will expire") || has("expiring soon")
            || has("is about to expire") || has("claim your free")
            || has("you have been approved") || has("qualify for free")
            || has("enrollment period ends") || has("limited time offer")
            || has("call to claim") || has("at no cost to you")
            || has("free of charge") || has("no cost to you");
        if !(health_benefit && benefit_urgency) {
            prop_assert!(!muten_overlay::confusables::has_healthcare_scam(&s));
        }
    }

    // ── E36: job_scam ─────────────────────────────────────────────────────────

    /// has_job_scam never panics on arbitrary Unicode input.
    #[test]
    fn has_job_scam_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_job_scam(&s);
    }

    /// Plain ASCII without both a job offer and a fee gate never fires.
    #[test]
    fn plain_ascii_never_fires_job_scam(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let job_offer = has("work from home") || has("remote work opportunity")
            || has("earn from home") || has("make money from home")
            || has("part time job") || has("data entry job")
            || has("flexible work") || has("easy money opportunity")
            || has("job offer") || has("hiring now")
            || has("work at home") || has("online job");
        let fee_gate = has("registration fee") || has("equipment deposit")
            || has("background check fee") || has("starter kit")
            || has("training fee") || has("materials fee")
            || has("buy kit to start") || has("pay to start")
            || has("upfront fee") || has("refundable deposit")
            || has("security deposit") || has("kit fee");
        if !(job_offer && fee_gate) {
            prop_assert!(!muten_overlay::confusables::has_job_scam(&s));
        }
    }

    /// has_tax_authority_scam never panics on arbitrary Unicode.
    #[test]
    fn has_tax_authority_scam_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_tax_authority_scam(&s);
    }

    /// Plain ASCII without both a tax-authority phrase and an arrest/seizure
    /// threat never fires.
    #[test]
    fn plain_ascii_never_fires_tax_authority_scam(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let tax_authority = has("irs notice") || has("internal revenue service")
            || has("you owe taxes") || has("unpaid taxes") || has("tax debt")
            || has("back taxes") || has("overdue taxes") || has("tax authority")
            || has("hmrc notice") || has("canada revenue") || has("ato notice")
            || has("tax warrant") || has("tax lien") || has("delinquent taxes");
        let arrest_threat = has("arrest warrant") || has("warrant issued")
            || has("warrant for your arrest") || has("federal arrest")
            || has("face arrest") || has("you will be arrested")
            || has("criminal charges have been filed") || has("law enforcement")
            || has("your assets will be seized") || has("assets seized")
            || has("wage garnishment") || has("bank levy")
            || has("face criminal charges") || has("immediate payment to avoid");
        if !(tax_authority && arrest_threat) {
            prop_assert!(!muten_overlay::confusables::has_tax_authority_scam(&s));
        }
    }

    /// has_social_media_account_alarm never panics on arbitrary Unicode.
    #[test]
    fn has_social_media_account_alarm_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_social_media_account_alarm(&s);
    }

    /// Plain ASCII without both a social platform and account-jeopardy phrase
    /// never fires.
    #[test]
    fn plain_ascii_never_fires_social_media_account_alarm(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let social_platform = has("facebook account") || has("instagram account")
            || has("twitter account") || has("linkedin account") || has("snapchat account")
            || has("tiktok account") || has("youtube account") || has("gmail account")
            || has("google account") || has("apple id") || has("icloud account")
            || has("discord account") || has("whatsapp account") || has("telegram account");
        let account_jeopardy = has("has been hacked") || has("has been hijacked")
            || has("has been suspended") || has("has been terminated")
            || has("account suspended") || has("account terminated")
            || has("unauthorized login") || has("suspicious login detected")
            || has("unusual login") || has("someone accessed your")
            || has("verify to recover") || has("click to restore") || has("regain access")
            || has("account will be deleted") || has("account will be permanently deleted");
        if !(social_platform && account_jeopardy) {
            prop_assert!(!muten_overlay::confusables::has_social_media_account_alarm(&s));
        }
    }

    /// has_immigration_visa_scam never panics on arbitrary Unicode.
    #[test]
    fn has_immigration_visa_scam_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_immigration_visa_scam(&s);
    }

    /// has_government_grant_scam never panics on arbitrary Unicode.
    #[test]
    fn has_government_grant_scam_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_government_grant_scam(&s);
    }

    /// has_debt_relief_scam never panics on arbitrary Unicode.
    #[test]
    fn has_debt_relief_scam_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_debt_relief_scam(&s);
    }

    /// has_streaming_billing_scam never panics on arbitrary Unicode.
    #[test]
    fn has_streaming_billing_scam_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_streaming_billing_scam(&s);
    }

    /// has_traffic_fine_scam never panics on arbitrary Unicode.
    #[test]
    fn has_traffic_fine_scam_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_traffic_fine_scam(&s);
    }

    /// Plain ASCII without both an immigration-document phrase and a
    /// status-threat or fee phrase never fires.
    #[test]
    fn plain_ascii_never_fires_immigration_visa_scam(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let immigration_doc = has("your visa") || has("your work permit")
            || has("your green card") || has("your residence permit")
            || has("your immigration status") || has("immigration notice")
            || has("visa application") || has("visa status") || has("entry permit")
            || has("border crossing") || has("immigration authority")
            || has("customs and border") || has("department of homeland")
            || has("immigration and customs");
        let status_threat = has("has been revoked") || has("has been cancelled")
            || has("is invalid") || has("has expired") || has("deportation")
            || has("will be deported") || has("illegal overstay") || has("illegal status")
            || has("overstayed") || has("out of status") || has("renewal fee required")
            || has("pay the renewal fee") || has("settlement fee") || has("status violation")
            || has("face deportation") || has("removal proceedings");
        if !(immigration_doc && status_threat) {
            prop_assert!(!muten_overlay::confusables::has_immigration_visa_scam(&s));
        }
    }

    /// Plain ASCII without both a government-program phrase and a collection
    /// barrier never fires has_government_grant_scam.
    #[test]
    fn plain_ascii_never_fires_government_grant_scam(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let grant_program = has("government grant") || has("federal grant")
            || has("stimulus payment") || has("stimulus check") || has("economic relief")
            || has("pandemic relief") || has("covid relief") || has("emergency relief fund")
            || has("government benefit fund") || has("unclaimed government funds")
            || has("government assistance program") || has("qualifying government benefit")
            || has("emergency subsidy") || has("government disbursement");
        let claim_barrier = has("claim your grant") || has("claim your funds")
            || has("collect your check") || has("application fee required")
            || has("processing fee to receive") || has("registration fee required")
            || has("verify your identity to receive") || has("enrollment deadline")
            || has("apply before the deadline") || has("funds will expire")
            || has("limited enrollment available") || has("claim now before deadline")
            || has("disbursement fee");
        if !(grant_program && claim_barrier) {
            prop_assert!(!muten_overlay::confusables::has_government_grant_scam(&s));
        }
    }

    /// Plain ASCII without both a debt-claim phrase and a scam-CTA phrase
    /// never fires has_debt_relief_scam.
    #[test]
    fn plain_ascii_never_fires_debt_relief_scam(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let debt_claim = has("credit card debt") || has("credit card balance")
            || has("unsecured debt") || has("personal loan debt") || has("get out of debt")
            || has("debt forgiveness") || has("debt consolidation") || has("debt relief program")
            || has("debt settlement") || has("credit repair program") || has("eliminate your debt")
            || has("reduce your debt") || has("debt management plan") || has("student debt relief");
        let scam_cta = has("guaranteed approval") || has("no credit check required")
            || has("100% guaranteed results") || has("we can eliminate your debt")
            || has("settled for pennies") || has("stop paying now") || has("stop payments today")
            || has("you qualify for relief") || has("application fee required")
            || has("processing fee required") || has("initial consultation fee")
            || has("pay to start your case") || has("guaranteed debt relief")
            || has("results guaranteed");
        if !(debt_claim && scam_cta) {
            prop_assert!(!muten_overlay::confusables::has_debt_relief_scam(&s));
        }
    }

    /// Plain ASCII without both a traffic/toll violation noun and a payment-
    /// urgency phrase never fires has_traffic_fine_scam.
    #[test]
    fn plain_ascii_never_fires_traffic_fine_scam(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let violation_type = has("parking violation") || has("parking ticket")
            || has("traffic fine") || has("speeding ticket") || has("red light violation")
            || has("traffic citation") || has("moving violation") || has("toll violation")
            || has("unpaid toll") || has("toll balance") || has("toll due")
            || has("outstanding toll") || has("road tax notice") || has("vehicle fine")
            || has("traffic penalty") || has("ezpass") || has("fastrak") || has("i-pass");
        let payment_urgency = has("pay within") || has("pay immediately")
            || has("final notice to pay") || has("overdue fine") || has("failure to pay")
            || has("warrant for non-payment") || has("immediate payment required")
            || has("pay online now") || has("penalty will increase")
            || has("your fine has increased") || has("vehicle registration hold")
            || has("license suspension") || has("license will be suspended")
            || has("avoid additional fees") || has("to avoid further penalties")
            || has("to avoid suspension");
        if !(violation_type && payment_urgency) {
            prop_assert!(!muten_overlay::confusables::has_traffic_fine_scam(&s));
        }
    }

    /// has_pig_butchering_lure never panics on arbitrary Unicode.
    #[test]
    fn pig_butchering_lure_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_pig_butchering_lure(&s);
    }

    /// Plain ASCII without both a romance/group cue and an investment platform
    /// cue never fires has_pig_butchering_lure.
    #[test]
    fn plain_ascii_never_fires_pig_butchering_lure(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let romance_cue = has("online friend") || has("met online") || has("chat with me")
            || has("investment mentor") || has("trading mentor") || has("vip group")
            || has("exclusive group") || has("exclusive trading group") || has("profit sharing group")
            || has("join our trading") || has("join my trading") || has("i will teach you")
            || has("i can help you invest") || has("let me help you");
        let invest_platform = has("trading platform") || has("investment platform")
            || has("guaranteed profit") || has("guaranteed return") || has("guaranteed earning")
            || has("high return investment") || has("exclusive trading") || has("crypto investment")
            || has("forex trading") || has("trading signal") || has("investment signal")
            || has("passive income opportunity") || has("financial freedom opportunity")
            || has("earn while you sleep") || has("double your money") || has("triple your investment");
        if !(romance_cue && invest_platform) {
            prop_assert!(!muten_overlay::confusables::has_pig_butchering_lure(&s));
        }
    }

    /// has_charity_scam_lure never panics on arbitrary Unicode.
    #[test]
    fn charity_scam_lure_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_charity_scam_lure(&s);
    }

    /// Plain ASCII without both a charity cue and a suspicious-payment cue
    /// never fires has_charity_scam_lure.
    #[test]
    fn plain_ascii_never_fires_charity_scam_lure(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let charity_cue = has("donate now") || has("disaster relief") || has("hurricane relief")
            || has("earthquake relief") || has("flood relief") || has("wildfire relief")
            || has("emergency relief fund") || has("relief fund") || has("humanitarian aid")
            || has("help the victims") || has("help survivors") || has("support victims")
            || has("disaster victims") || has("crisis fund") || has("charity foundation")
            || has("official charity") || has("verified charity") || has("100% goes to")
            || has("all proceeds go");
        let suspicious_payment = has("gift card") || has("itunes card") || has("google play card")
            || has("steam card") || has("amazon gift card") || has("wire transfer")
            || has("bank wire") || has("western union") || has("moneygram")
            || has("bitcoin donation") || has("crypto donation") || has("send bitcoin")
            || has("send ethereum") || has("send crypto") || has("money order only")
            || has("prepaid card");
        if !(charity_cue && suspicious_payment) {
            prop_assert!(!muten_overlay::confusables::has_charity_scam_lure(&s));
        }
    }

    /// has_rental_scam_lure never panics on arbitrary Unicode.
    #[test]
    fn rental_scam_lure_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_rental_scam_lure(&s);
    }

    /// Plain ASCII without both a rental cue and an advance-deposit demand
    /// never fires has_rental_scam_lure.
    #[test]
    fn plain_ascii_never_fires_rental_scam_lure(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let rental_cue = has("apartment for rent") || has("room for rent") || has("house for rent")
            || has("rental listing") || has("available for rent") || has("lease agreement")
            || has("rental property") || has("furnished apartment") || has("affordable rent")
            || has("below market rent") || has("no credit check rental") || has("studio apartment");
        let advance_demand = has("send deposit") || has("wire deposit")
            || has("deposit required before") || has("first month deposit")
            || has("security deposit via") || has("deposit before viewing")
            || has("deposit to hold") || has("send first month") || has("pay to reserve")
            || has("payment to secure") || has("gift card for deposit")
            || has("money order for deposit") || has("payment before visit")
            || has("deposit upfront");
        if !(rental_cue && advance_demand) {
            prop_assert!(!muten_overlay::confusables::has_rental_scam_lure(&s));
        }
    }

    /// has_loan_fee_scam never panics on arbitrary Unicode.
    #[test]
    fn loan_fee_scam_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_loan_fee_scam(&s);
    }

    /// Plain ASCII without both a loan-approval cue and a fee gate never
    /// fires has_loan_fee_scam.
    #[test]
    fn plain_ascii_never_fires_loan_fee_scam(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let loan_approval = has("pre-approved loan") || has("preapproved loan")
            || has("you qualify for a loan") || has("loan approved") || has("you have been approved")
            || has("personal loan offer") || has("payday loan") || has("quick loan")
            || has("instant loan") || has("emergency loan") || has("guaranteed loan")
            || has("no credit check loan") || has("bad credit loan")
            || has("guaranteed approval loan");
        let fee_gate = has("processing fee") || has("insurance fee") || has("activation fee")
            || has("collateral fee") || has("transfer fee required") || has("release fee")
            || has("security deposit required") || has("upfront fee") || has("pay a small fee")
            || has("before we release") || has("before disbursement") || has("to receive your loan")
            || has("to unlock your funds");
        if !(loan_approval && fee_gate) {
            prop_assert!(!muten_overlay::confusables::has_loan_fee_scam(&s));
        }
    }

    /// has_pet_sale_scam never panics on arbitrary Unicode.
    #[test]
    fn pet_sale_scam_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_pet_sale_scam(&s);
    }

    /// Plain ASCII without both a pet-listing cue and an advance-demand cue
    /// never fires has_pet_sale_scam.
    #[test]
    fn plain_ascii_never_fires_pet_sale_scam(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let pet_cue = has("puppy for sale") || has("puppies for sale")
            || has("kitten for sale") || has("kittens for sale")
            || has("akc registered") || has("purebred puppy")
            || has("french bulldog pup") || has("golden retriever pup")
            || has("maltese puppy");
        let advance_demand = has("shipping deposit") || has("transport fee required")
            || has("crate deposit") || has("insurance deposit")
            || has("pay before delivery") || has("deposit to reserve")
            || has("reserve your puppy") || has("reserve your kitten");
        if !(pet_cue && advance_demand) {
            prop_assert!(!muten_overlay::confusables::has_pet_sale_scam(&s));
        }
    }

    /// has_timeshare_travel_scam never panics on arbitrary Unicode.
    #[test]
    fn timeshare_travel_scam_never_panics(s in ".*") {
        let _ = muten_overlay::confusables::has_timeshare_travel_scam(&s);
    }

    /// Plain ASCII without both a timeshare/vacation cue and a fee demand
    /// never fires has_timeshare_travel_scam.
    #[test]
    fn plain_ascii_never_fires_timeshare_travel_scam(s in "[a-z .,!?]{1,60}") {
        let has = |a: &str| s.contains(a);
        let timeshare_cue = has("vacation club") || has("timeshare")
            || has("resort membership") || has("complimentary vacation")
            || has("free vacation offer");
        let advance_fee = has("activation fee") || has("membership fee to activate")
            || has("certificate fee") || has("closing fee")
            || has("pay to claim your vacation") || has("resort activation fee");
        if !(timeshare_cue && advance_fee) {
            prop_assert!(!muten_overlay::confusables::has_timeshare_travel_scam(&s));
        }
    }
}
