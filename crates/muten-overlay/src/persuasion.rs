//! Persuasion-principle tags for scam-overlay signals (Cialdini, 1984).
//!
//! `muten` already classifies every verdict along two orthogonal lenses:
//!
//! - [`crate::categories`] — the *UI manipulation mechanic* (Gray et al.
//!   2018: Nagging, Obstruction, Sneaking, InterfaceInterference,
//!   ForcedAction). Answers **how the interface deceives**.
//! - [`crate::mitre`] — the *attacker technique* (MITRE ATT&CK for
//!   Enterprise: T1566 Phishing, T1656 Impersonation, …). Answers **what
//!   the adversary does**.
//!
//! Neither answers the third, distinct question an awareness-training lead
//! or a victim actually asks: **why does the human comply?** A fake
//! Microsoft logo, a 5:00 countdown, and a "10,000 users protected" badge
//! all collapse into a single `InterfaceInterference` UI category, yet they
//! pull three completely different psychological levers — Authority,
//! Scarcity, and Social Proof.
//!
//! This module adds that third lens by mapping each signal to the
//! **persuasion principle(s)** it exploits. The taxonomy is Robert
//! Cialdini's six classic principles of influence (*Influence: The
//! Psychology of Persuasion*, 1984) — Authority, Scarcity, Social Proof,
//! Reciprocity, Liking, Commitment/Consistency — the canonical framework in
//! social-engineering research (Ferreira, Coventry & Lenzini, *"Principles
//! of Persuasion in Social Engineering and Their Use in Phishing"*, HCII
//! 2015). It is extended with one further principle, **Intimidation**
//! (fear / threat / "strong affect"), which the phishing-and-scam
//! literature documents as the dominant lever in *scareware* specifically
//! (Stajano & Wilson, *"Understanding scam victims: seven principles for
//! systems security"*, CACM 2011; Gragg, *"A Multi-Level Defense Against
//! Social Engineering"*, SANS 2003) and which Cialdini's commerce-oriented
//! six do not name.
//!
//! A signal may map to **several** principles at once — a fake Windows
//! Defender malware alert exploits Authority (it wears Microsoft's name)
//! *and* Intimidation (it threatens infection) — so the mapping returns a
//! slice, exactly like [`crate::mitre::techniques_of`].
//!
//! Pure classification over already-computed signals: no OS calls, no
//! network, no ML, no new dependencies. The value to an operator is
//! training alignment — Cialdini's principles are the vocabulary of every
//! major anti-phishing curriculum — and to an end user a plainer answer
//! than a UI-mechanic name: *"this is rushing you with fake urgency"* is
//! more actionable than *"InterfaceInterference"*.

use serde::Serialize;

/// One persuasion principle a scam overlay can exploit.
///
/// The first six are Cialdini's (1984) classic principles of influence;
/// [`Self::Intimidation`] is the fear/threat lever added from the
/// scareware-focused social-engineering literature (Stajano & Wilson 2011;
/// Gragg 2003). Ordering is stable for deduplicated audit output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersuasionPrinciple {
    /// Deferring to a (faked) trusted or official entity — a bank, a
    /// government agency, Microsoft/Apple, an antivirus brand.
    Authority,
    /// A free gift, prize, refund, or windfall that creates a sense of
    /// obligation or entitlement the victim acts to claim.
    Reciprocity,
    /// "Others are already doing this" — crowd validation via participant
    /// counts, member communities, or recruitment framing.
    SocialProof,
    /// A small initial step (complete a task, follow an instruction, join)
    /// that escalates into larger attacker-chosen actions.
    Commitment,
    /// Rapport, friendship, romance, kinship, or charitable kindness used
    /// to lower the victim's guard.
    Liking,
    /// Time pressure and loss-of-opportunity — countdowns, "expires today",
    /// limited slots — that rush the victim past reflection.
    Scarcity,
    /// Fear, threat, and alarm — infection, arrest, account loss, exposure
    /// — the dominant lever in scareware (extension principle).
    Intimidation,
}

impl PersuasionPrinciple {
    /// Stable snake_case name for logs / SIEM / CLI output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::Reciprocity => "reciprocity",
            Self::SocialProof => "social_proof",
            Self::Commitment => "commitment",
            Self::Liking => "liking",
            Self::Scarcity => "scarcity",
            Self::Intimidation => "intimidation",
        }
    }
}

use PersuasionPrinciple::{
    Authority, Commitment, Intimidation, Liking, Reciprocity, Scarcity, SocialProof,
};

/// Map a single signal name to the persuasion principle(s) it exploits.
///
/// Returns an empty slice for signals that carry no persuasive *content* of
/// their own — the window-geometry and modal-force signals (`fullscreen`,
/// `topmost`, `blocks_input`, `input_trap`, `no_close_button`, …). Those
/// coerce mechanically rather than persuade psychologically, so they belong
/// to the UI-mechanic lens ([`crate::categories`]), not this one.
///
/// Many content signals pull more than one lever; the combination is the
/// useful part (e.g. a tax-authority scam is Authority **and**
/// Intimidation), so the return is a slice.
#[must_use]
pub fn principles_of(signal: &str) -> &'static [PersuasionPrinciple] {
    match signal {
        // ── Authority alone: brand / institutional impersonation whose
        // pull is "this is an official source", without a primary threat. ──
        "brand_impersonation" | "combosquat_brand" | "typosquat_brand" => &[Authority],
        "windows_activation_scam"
        | "false_registration_billing"
        | "streaming_billing_scam"
        | "software_subscription_scam"
        | "tech_support_invoice_scam"
        | "tech_support_chat_lure"
        | "toad_case_number_lure"
        | "otp_interception_scam"
        | "healthcare_scam" => &[Authority],

        // ── Authority + Intimidation: official-looking source AND a threat
        // (infection, arrest, account/data loss, legal action, cutoff). ──
        "phone_number" | "blocklist_phone" => &[Authority, Intimidation],
        "fake_bsod_lure"
        | "windows_defender_alert_lure"
        | "fake_scanner_cue"
        | "rogue_av_process"
        | "ip_alarm_lure" => &[Authority, Intimidation],
        "authority_lure"
        | "tax_authority_scam"
        | "national_id_alarm"
        | "immigration_visa_scam"
        | "traffic_fine_scam"
        | "utility_cutoff_threat"
        | "fake_copyright_scam"
        | "fake_browser_security_warning"  // impersonates trusted browser security UI to invoke authority
        => &[Authority, Intimidation],
        "bank_account_alarm"
        | "social_media_account_alarm"
        | "credential_harvest_cue"
        | "cloud_quota_lure"
        | "dark_web_breach_lure"
        | "crypto_drain_lure" => &[Authority, Intimidation],

        // ── Authority + Scarcity: official source + expiry/time pressure. ──
        // package_fee_lure: impersonated carrier (USPS/DHL) + "package on
        // hold, pay the customs fee now or it is returned".
        "av_brand_renewal_scam" | "subscription_lure" | "package_fee_lure" => {
            &[Authority, Scarcity]
        }

        // ── Authority alone (no primary threat): recovery_scam impersonates a
        // fund-recovery agency / law firm / official promising to get money
        // back (FBI IC3 2024 secondary-victimization), pulling deference to a
        // helpful "official" rather than fear. ──
        "recovery_scam" => &[Authority],

        // ── Intimidation alone: pure fear/alarm, no specific brand. ──
        "alarm_density" | "sextortion_lure" | "forced_retention_cue" => &[Intimidation],

        // ── Scarcity alone: countdown / time pressure / limited supply. ──
        // rental_scam_lure: "lots of interest — send the deposit now to
        // secure the property" is loss-of-opportunity pressure.
        "urgency_countdown" | "rental_scam_lure" => &[Scarcity],
        "wallet_connect_popup_lure" => &[Scarcity],   // "limited spots / early access" creates artificial scarcity

        // ── Reciprocity (+ Scarcity / Social Proof): a free windfall the
        // victim acts to claim, often with urgency or crowd framing. The
        // advance-fee / promised-windfall family — a fee or step stands
        // between the victim and money or benefits they are told they are
        // owed (loan, grant, forgiveness, refund, benefit). ──
        "prize_lure" | "timeshare_travel_scam" => &[Reciprocity, Scarcity],
        "advance_fee_lure"
        | "government_grant_scam"
        | "survey_reward_scam"
        | "loan_fee_scam"
        | "debt_relief_scam"
        | "student_loan_scam"
        | "veterans_benefit_scam"
        | "refund_scam_cue" => &[Reciprocity],
        "crypto_giveaway_scam" => &[Reciprocity, SocialProof],

        // ── Social Proof (+ Commitment): "join the community / members". ──
        "mlm_pyramid_recruitment" => &[SocialProof, Commitment],

        // ── Liking: rapport, romance, kinship, charitable kindness. ──
        "pig_butchering_lure" | "charity_scam_lure" | "pet_sale_scam" => &[Liking],
        // Liking (impersonated relative) + Intimidation (they are in danger).
        "family_emergency_scam" => &[Liking, Intimidation],

        // ── Commitment / Consistency: small first step → escalating asks. ──
        "clickfix_instruction" | "task_app_scam" | "job_scam" | "secret_shopper_scam" => {
            &[Commitment]
        }

        // ── Deliberate exemptions: action / payment-rail "mechanic" signals.
        // These name the concrete action the victim is asked to perform — buy
        // gift cards, download a tool, grant remote access, share a screen,
        // scan a QR code — i.e. the *extraction mechanic*, not a psychological
        // lever. The lever that drives compliance is carried by the
        // accompanying scareware / authority signal (a fake-BSOD or
        // tech-support overlay supplies Authority + Intimidation; this signal
        // supplies the cash-out channel, surfaced by the extraction lens).
        // They are listed explicitly so a future signal is a conscious choice,
        // not an accidental omission (guarded by the cross-lens coverage test).
        "gift_card_demand" | "download_trap_lure" | "remote_access_lure" | "screen_share_lure"
        | "qr_code_lure" => &[],

        // Descriptive / geometry / homoglyph-mechanic signals: no persuasion
        // principle of their own (handled by the UI-mechanic lens).
        _ => &[],
    }
}

/// Collect the distinct persuasion principles present in a set of signals,
/// sorted and deduplicated for a stable audit representation.
///
/// Accepts any slice whose elements implement `AsRef<str>` — `&[String]`
/// (overlay classifier), `&[&'static str]` (scareware), or test literals —
/// mirroring [`crate::categories::categories_of`].
#[must_use]
pub fn principles_of_signals<S: AsRef<str>>(signals: &[S]) -> Vec<PersuasionPrinciple> {
    let mut ps: Vec<PersuasionPrinciple> = signals
        .iter()
        .flat_map(|s| principles_of(s.as_ref()))
        .copied()
        .collect();
    ps.sort_unstable();
    ps.dedup();
    ps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_signals_have_no_principle() {
        for s in [
            "fullscreen",
            "topmost",
            "very_new",
            "unsolicited",
            "user_initiated",
            "blocks_input",
            "input_trap",
            "no_close_button",
            "mixed_script",
            "bidi_override",
        ] {
            assert!(
                principles_of(s).is_empty(),
                "{s} should map to no persuasion principle"
            );
        }
    }

    #[test]
    fn authority_only_signals_map_to_authority() {
        assert_eq!(principles_of("brand_impersonation"), &[Authority]);
        assert_eq!(principles_of("software_subscription_scam"), &[Authority]);
        assert_eq!(principles_of("tech_support_chat_lure"), &[Authority]);
    }

    #[test]
    fn scareware_signals_combine_authority_and_intimidation() {
        assert_eq!(
            principles_of("windows_defender_alert_lure"),
            &[Authority, Intimidation]
        );
        assert_eq!(principles_of("fake_bsod_lure"), &[Authority, Intimidation]);
        assert_eq!(
            principles_of("tax_authority_scam"),
            &[Authority, Intimidation]
        );
    }

    #[test]
    fn pure_fear_signals_map_to_intimidation() {
        assert_eq!(principles_of("alarm_density"), &[Intimidation]);
        assert_eq!(principles_of("sextortion_lure"), &[Intimidation]);
    }

    #[test]
    fn urgency_maps_to_scarcity() {
        assert_eq!(principles_of("urgency_countdown"), &[Scarcity]);
    }

    #[test]
    fn prize_combines_reciprocity_and_scarcity() {
        assert_eq!(principles_of("prize_lure"), &[Reciprocity, Scarcity]);
    }

    #[test]
    fn giveaway_combines_reciprocity_and_social_proof() {
        assert_eq!(
            principles_of("crypto_giveaway_scam"),
            &[Reciprocity, SocialProof]
        );
    }

    #[test]
    fn romance_and_kinship_map_to_liking() {
        assert_eq!(principles_of("pig_butchering_lure"), &[Liking]);
        assert_eq!(principles_of("charity_scam_lure"), &[Liking]);
        assert_eq!(
            principles_of("family_emergency_scam"),
            &[Liking, Intimidation]
        );
    }

    #[test]
    fn task_and_clickfix_map_to_commitment() {
        assert_eq!(principles_of("task_app_scam"), &[Commitment]);
        assert_eq!(principles_of("clickfix_instruction"), &[Commitment]);
    }

    #[test]
    fn advance_fee_windfall_family_maps_to_reciprocity() {
        // Structurally identical promised-windfall scams must map consistently
        // with advance_fee_lure / government_grant_scam (cross-lens drift fix).
        for s in [
            "loan_fee_scam",
            "debt_relief_scam",
            "student_loan_scam",
            "veterans_benefit_scam",
            "refund_scam_cue",
        ] {
            assert_eq!(
                principles_of(s),
                &[Reciprocity],
                "{s} should map to Reciprocity like advance_fee_lure"
            );
        }
        // Free-vacation prize scam parallels prize_lure.
        assert_eq!(
            principles_of("timeshare_travel_scam"),
            &[Reciprocity, Scarcity]
        );
    }

    #[test]
    fn rental_and_package_and_recovery_map_consistently() {
        // Housing pressure → Scarcity (loss of opportunity).
        assert_eq!(principles_of("rental_scam_lure"), &[Scarcity]);
        // Carrier impersonation + on-hold urgency → Authority + Scarcity.
        assert_eq!(principles_of("package_fee_lure"), &[Authority, Scarcity]);
        // Recovery agency imposter → Authority.
        assert_eq!(principles_of("recovery_scam"), &[Authority]);
    }

    #[test]
    fn action_mechanic_signals_are_deliberately_exempt() {
        // These name the demanded action (the extraction channel), not a
        // psychological lever — the lever is carried by the accompanying
        // scareware/authority signal. They must stay empty here so the
        // cross-lens coverage guard's exempt list stays accurate.
        for s in [
            "gift_card_demand",
            "download_trap_lure",
            "remote_access_lure",
            "screen_share_lure",
            "qr_code_lure",
        ] {
            assert!(
                principles_of(s).is_empty(),
                "{s} is an action mechanic and should carry no persuasion principle"
            );
        }
    }

    #[test]
    fn unknown_signal_has_no_principle() {
        assert!(principles_of("not_a_real_signal").is_empty());
    }

    #[test]
    fn principles_of_signals_dedups_and_sorts() {
        // Two Authority+Intimidation signals → one of each, sorted.
        let signals: &[&str] = &["windows_defender_alert_lure", "bank_account_alarm"];
        let ps = principles_of_signals(signals);
        assert_eq!(ps, vec![Authority, Intimidation]);
    }

    #[test]
    fn principles_of_signals_combines_distinct_levers() {
        // Authority+Intimidation, Scarcity, Liking → sorted, deduped union.
        let signals: &[&str] = &["fake_scanner_cue", "urgency_countdown", "charity_scam_lure"];
        let ps = principles_of_signals(signals);
        assert_eq!(ps, vec![Authority, Liking, Scarcity, Intimidation]);
    }

    #[test]
    fn principles_of_signals_empty_input() {
        let none: &[&str] = &[];
        assert!(principles_of_signals(none).is_empty());
    }

    #[test]
    fn principles_of_signals_works_with_owned_strings() {
        let signals: Vec<String> = vec!["prize_lure".to_string(), "urgency_countdown".to_string()];
        let ps = principles_of_signals(&signals);
        // prize_lure → Reciprocity+Scarcity, urgency_countdown → Scarcity.
        assert_eq!(ps, vec![Reciprocity, Scarcity]);
    }

    #[test]
    fn as_str_round_trips_names() {
        assert_eq!(Authority.as_str(), "authority");
        assert_eq!(SocialProof.as_str(), "social_proof");
        assert_eq!(Intimidation.as_str(), "intimidation");
    }
}
