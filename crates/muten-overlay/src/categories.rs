//! Dark-pattern strategy categories (Gray et al., 2018).
//!
//! Every behavioural signal muten fires can be mapped to one of the
//! five high-level deceptive-design strategies from Gray et al.,
//! "The Dark (Patterns) Side of UX Design" (CHI 2018) — the taxonomy
//! since adopted across the literature (Mathur et al. 2019, Di
//! Geronimo et al. 2020, Chen et al. UIGuard 2023) and by regulators
//! (the FTC and California's CPRA both define dark patterns).
//!
//! Tagging each verdict with the strategy categories its signals
//! belong to adds three things at zero runtime cost:
//!
//! 1. **Regulatory alignment** — an incident can be reported as, e.g.,
//!    a "forced action + obstruction" overlay, matching the language
//!    used in CPRA / FTC enforcement.
//! 2. **Audit value** — a SIEM can group overlay incidents by
//!    strategy, not just by raw signal name.
//! 3. **Explainability (CLAUDE.md I6)** — the operator sees *why* in
//!    standard terms, not just an internal signal list.
//!
//! This is pure classification over the already-computed signals: no
//! OS calls, no network, no computer vision (muten reasons over window
//! metadata, not pixels). Signals that are merely descriptive display
//! attributes (full-screen, topmost, age) map to no category — they
//! describe the window, they are not themselves a deceptive strategy.

use serde::Serialize;

/// One of the five Gray et al. (2018) dark-pattern strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DarkPatternCategory {
    /// Repeated intrusion: the user's task is interrupted again and
    /// again by unrelated prompts (e.g. a rogue-AV alert flood).
    Nagging,
    /// Task flow impeded: closing/leaving is made unnecessarily hard
    /// (e.g. a missing or fake close button).
    Obstruction,
    /// Information hidden, disguised, or delayed.
    Sneaking,
    /// Attention steered and important actions obscured, often via
    /// brand/authority impersonation or misdirection (e.g. a fake
    /// "Windows Defender" title, a support phone number).
    InterfaceInterference,
    /// The user is forced to act to proceed (e.g. a modal that
    /// captures all input until dismissed).
    ForcedAction,
}

impl DarkPatternCategory {
    /// Stable snake_case name for logs/SIEM.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nagging => "nagging",
            Self::Obstruction => "obstruction",
            Self::Sneaking => "sneaking",
            Self::InterfaceInterference => "interface_interference",
            Self::ForcedAction => "forced_action",
        }
    }
}

/// Map a single signal name to its dark-pattern strategy, if it
/// represents one. Returns `None` for purely descriptive signals
/// (full-screen, topmost, very_new, unsolicited, user_initiated),
/// which characterise the window but are not themselves a deceptive
/// strategy.
#[must_use]
pub fn category_of(signal: &str) -> Option<DarkPatternCategory> {
    use DarkPatternCategory::*;
    match signal {
        // Modal input capture — and the stronger full-screen "screen
        // lock" composite — force the user to deal with it.
        "blocks_input" | "input_trap" => Some(ForcedAction),
        // No/fake close button impedes leaving the task.
        "no_close_button" => Some(Obstruction),
        // Mixed-script, whole-script, BiDi-override, and enclosed-letter
        // homoglyphs all disguise the true text — the textbook "sneaking"
        // strategy (information disguised). mixed_script/whole_script_confusable
        // swap characters to look Latin; bidi_override reverses the visual
        // reading order (Trojan Source); compat_chars_present uses
        // enclosed/circled letters to evade plain-text filters.
        "mixed_script"
        | "whole_script_confusable"
        | "bidi_override"
        | "compat_chars_present"
        | "mixed_number_systems"
        | "excessive_combining_marks" => Some(Sneaking),
        // The rogue-AV flood is the textbook nagging pattern.
        "repeated_flood" => Some(Nagging),
        // Brand/authority impersonation and the call-this-number lure
        // steer the user via misdirection. `brand_impersonation` (a
        // homograph look-alike domain) is the same misdirection strategy.
        "phone_number"
        | "blocklist_title"
        | "blocklist_host"
        | "rogue_av_process"
        | "brand_impersonation" => Some(InterfaceInterference),
        // Descriptive-only signals: not a strategy on their own.
        _ => None,
    }
}

/// Collect the distinct dark-pattern categories present in a set of
/// signals, sorted and deduplicated for a stable audit representation.
#[must_use]
pub fn categories_of<'a, I>(signals: I) -> Vec<DarkPatternCategory>
where
    I: IntoIterator<Item = &'a &'a str>,
{
    let mut cats: Vec<DarkPatternCategory> =
        signals.into_iter().filter_map(|s| category_of(s)).collect();
    cats.sort_unstable();
    cats.dedup();
    cats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptive_signals_have_no_category() {
        for s in [
            "fullscreen",
            "topmost",
            "very_new",
            "unsolicited",
            "user_initiated",
        ] {
            assert_eq!(category_of(s), None, "{s} should have no category");
        }
    }

    #[test]
    fn strategy_signals_map_correctly() {
        assert_eq!(
            category_of("blocks_input"),
            Some(DarkPatternCategory::ForcedAction)
        );
        assert_eq!(
            category_of("no_close_button"),
            Some(DarkPatternCategory::Obstruction)
        );
        assert_eq!(
            category_of("repeated_flood"),
            Some(DarkPatternCategory::Nagging)
        );
        assert_eq!(
            category_of("phone_number"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
        assert_eq!(
            category_of("blocklist_title"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
        assert_eq!(
            category_of("rogue_av_process"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
        assert_eq!(
            category_of("mixed_script"),
            Some(DarkPatternCategory::Sneaking)
        );
        assert_eq!(
            category_of("whole_script_confusable"),
            Some(DarkPatternCategory::Sneaking)
        );
        assert_eq!(
            category_of("bidi_override"),
            Some(DarkPatternCategory::Sneaking)
        );
        assert_eq!(
            category_of("compat_chars_present"),
            Some(DarkPatternCategory::Sneaking)
        );
        assert_eq!(
            category_of("mixed_number_systems"),
            Some(DarkPatternCategory::Sneaking)
        );
        assert_eq!(
            category_of("excessive_combining_marks"),
            Some(DarkPatternCategory::Sneaking)
        );
        assert_eq!(
            category_of("input_trap"),
            Some(DarkPatternCategory::ForcedAction)
        );
        assert_eq!(
            category_of("brand_impersonation"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    #[test]
    fn unknown_signal_has_no_category() {
        assert_eq!(category_of("not_a_real_signal"), None);
    }

    #[test]
    fn categories_dedup_and_sort() {
        // Two interface_interference signals + one forced_action →
        // [forced_action, interface_interference] (sorted, deduped).
        let signals = ["phone_number", "blocklist_title", "blocks_input"];
        let refs: Vec<&&str> = signals.iter().collect();
        let cats = categories_of(refs);
        assert_eq!(
            cats,
            vec![
                DarkPatternCategory::InterfaceInterference,
                DarkPatternCategory::ForcedAction,
            ]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn empty_signals_no_categories() {
        let none: Vec<&&str> = Vec::new();
        assert!(categories_of(none).is_empty());
    }

    #[test]
    fn as_str_round_trips_names() {
        assert_eq!(DarkPatternCategory::ForcedAction.as_str(), "forced_action");
        assert_eq!(
            DarkPatternCategory::InterfaceInterference.as_str(),
            "interface_interference"
        );
    }
}
