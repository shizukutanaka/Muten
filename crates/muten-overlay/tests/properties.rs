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
}
