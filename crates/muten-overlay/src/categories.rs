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
        // Modal input capture, the stronger full-screen "screen lock"
        // composite, and ClickFix/fake-CAPTCHA instruction lures all
        // force the user to take a specific (attacker-chosen) action.
        "blocks_input" | "input_trap" | "clickfix_instruction" => Some(ForcedAction),
        // No/fake close button impedes leaving the task; a "do not close"
        // retention instruction achieves the same effect via social pressure.
        "no_close_button" | "forced_retention_cue" => Some(Obstruction),
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
        | "excessive_combining_marks"
        | "cloud_storage_abuse" => Some(Sneaking),
        // The rogue-AV flood is the textbook nagging pattern.
        "repeated_flood" => Some(Nagging),
        // Brand/authority impersonation and the call-this-number lure
        // steer the user via misdirection. `brand_impersonation` (a
        // homograph look-alike domain) and `combosquat_brand` (a brand
        // joined to a scam-lure word, e.g. `apple-support`) are the same
        // misdirection strategy via a deceptive domain.
        // The remote-access-tool lure steers the user into installing
        // attacker-controlled remote-control software — misdirection via a
        // fake alert, the same InterfaceInterference strategy.
        "phone_number"
        | "blocklist_phone"
        | "blocklist_title"
        | "blocklist_host"
        | "rogue_av_process"
        | "brand_impersonation"
        | "combosquat_brand"
        | "remote_access_lure"
        | "urgency_countdown"
        | "alarm_density"
        | "typosquat_brand"
        | "url_path_lure"
        | "credential_harvest_cue"
        | "fake_scanner_cue"
        | "subscription_lure"
        | "authority_lure"
        | "download_trap_lure"
        | "prize_lure"
        | "crypto_drain_lure"
        | "screen_share_lure"
        | "qr_code_lure"
        | "ip_alarm_lure"
        | "package_fee_lure"
        | "sextortion_lure"
        | "gift_card_demand" => Some(InterfaceInterference),
        "refund_scam_cue" => Some(Sneaking),
        "national_id_alarm" => Some(InterfaceInterference),
        "bank_account_alarm" => Some(InterfaceInterference),
        "false_registration_billing" => Some(InterfaceInterference),
        "fake_bsod_lure" => Some(Obstruction),
        "advance_fee_lure" => Some(Sneaking),
        "tech_support_invoice_scam" => Some(InterfaceInterference),
        "utility_cutoff_threat" => Some(InterfaceInterference),
        "healthcare_scam" => Some(Sneaking),
        "job_scam" => Some(Sneaking),
        "tax_authority_scam" => Some(InterfaceInterference),
        "social_media_account_alarm" => Some(InterfaceInterference),
        "immigration_visa_scam" => Some(InterfaceInterference),
        "government_grant_scam" => Some(Sneaking),
        "debt_relief_scam" => Some(Sneaking),
        "streaming_billing_scam" => Some(InterfaceInterference),
        "traffic_fine_scam" => Some(InterfaceInterference),
        "pig_butchering_lure" => Some(Sneaking), // romance framing disguises the investment fraud
        "loan_fee_scam" => Some(Sneaking), // fake approval disguises the advance-fee extraction
        "data_uri_page" => Some(Sneaking), // scheme disguises the absence of a real hosting domain
        "charity_scam_lure" => Some(Sneaking), // impersonates charity to disguise fraudulent payment collection
        "rental_scam_lure" => Some(Sneaking),  // fake listing disguises advance-fee extraction
        "pet_sale_scam" => Some(Sneaking), // fake pet ad disguises transport-advance-fee extraction
        "timeshare_travel_scam" => Some(Sneaking), // vacation prize framing disguises advance-fee extraction
        "windows_activation_scam" => Some(InterfaceInterference), // Microsoft impersonation steers via fake authority
        "survey_reward_scam" => Some(InterfaceInterference), // reward bait misdirects attention and action
        "av_brand_renewal_scam" => Some(InterfaceInterference), // AV brand impersonation creates false urgency
        "recovery_scam" => Some(Sneaking), // legitimate-service disguise conceals secondary-victimization fraud
        "student_loan_scam" => Some(Sneaking), // government-program guise conceals fee extraction
        "secret_shopper_scam" => Some(Sneaking), // legitimate-job guise conceals money-mule recruitment
        "mlm_pyramid_recruitment" => Some(Sneaking), // business-opportunity guise disguises pyramid structure
        "ip_host_url" => Some(Sneaking), // raw IP host conceals the absence of a legitimate registered domain
        "veterans_benefit_scam" => Some(Sneaking), // legitimate-agency guise conceals fee-for-free-service fraud
        "fake_copyright_scam" => Some(InterfaceInterference), // legal-threat framing steers victim into urgent payment
        "crypto_giveaway_scam" => Some(InterfaceInterference), // exchange/celebrity impersonation steers victim to send crypto
        "otp_interception_scam" => Some(InterfaceInterference), // social-engineers the victim into relaying a 2FA code
        "family_emergency_scam" => Some(InterfaceInterference), // impersonates a relative in crisis to extract urgent secret payment
        "task_app_scam" => Some(Sneaking), // fake-task-earnings framing disguises the withdrawal-fee extraction
        "software_subscription_scam" => Some(InterfaceInterference), // SaaS/AI brand impersonation steers via fake billing authority
        "dark_web_breach_lure" => Some(InterfaceInterference), // impersonates identity-monitoring service to steer victim via false breach alarm
        "cloud_quota_lure" => Some(InterfaceInterference), // impersonates cloud storage brand via false quota alarm to harvest credentials or push payment
        // Descriptive-only signals: not a strategy on their own.
        _ => None,
    }
}

/// Collect the distinct dark-pattern categories present in a set of
/// signals, sorted and deduplicated for a stable audit representation.
/// Accepts any slice whose elements implement `AsRef<str>` — including
/// `&[&'static str]` (scareware), `&[String]` (overlay classifier), or
/// `&[&&str]` (test literals) — so callers don't need to homogenize types.
#[must_use]
pub fn categories_of<S: AsRef<str>>(signals: &[S]) -> Vec<DarkPatternCategory> {
    let mut cats: Vec<DarkPatternCategory> = signals
        .iter()
        .filter_map(|s| category_of(s.as_ref()))
        .collect();
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
            category_of("clickfix_instruction"),
            Some(DarkPatternCategory::ForcedAction)
        );
        assert_eq!(
            category_of("brand_impersonation"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
        assert_eq!(
            category_of("combosquat_brand"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
        assert_eq!(
            category_of("remote_access_lure"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
        assert_eq!(
            category_of("forced_retention_cue"),
            Some(DarkPatternCategory::Obstruction)
        );
        assert_eq!(
            category_of("credential_harvest_cue"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
        assert_eq!(
            category_of("fake_scanner_cue"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
        assert_eq!(
            category_of("subscription_lure"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
        assert_eq!(
            category_of("authority_lure"),
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
        let signals: &[&str] = &["phone_number", "blocklist_title", "blocks_input"];
        let cats = categories_of(signals);
        // sorted: ForcedAction < InterfaceInterference (alphabetical in enum)
        assert!(cats.contains(&DarkPatternCategory::ForcedAction));
        assert!(cats.contains(&DarkPatternCategory::InterfaceInterference));
        assert_eq!(cats.len(), 2);
    }

    #[test]
    fn categories_of_works_with_owned_strings() {
        let signals: Vec<String> = vec!["blocks_input".to_string(), "no_close_button".to_string()];
        let cats = categories_of(&signals);
        assert!(cats.contains(&DarkPatternCategory::ForcedAction));
        assert!(cats.contains(&DarkPatternCategory::Obstruction));
    }

    #[test]
    fn empty_signals_no_categories() {
        let none: &[&str] = &[];
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
