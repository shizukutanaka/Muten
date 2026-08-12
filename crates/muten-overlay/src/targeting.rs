//! Victim-targeting profile tags for scam-overlay signals.
//!
//! `muten` already classifies every verdict along five lenses:
//!
//! - [`crate::categories`] (Gray et al. 2018) — **how** the interface deceives.
//! - [`crate::mitre`] (ATT&CK) — **what** technique the adversary uses.
//! - [`crate::persuasion`] (Cialdini 1984) — **why** the human complies.
//! - [`crate::extraction`] (FTC/FBI IC3) — **what** the victim loses / recoverability.
//! - [`crate::lifecycle`] (Kill Chain) — **how far** the attacker has progressed.
//!
//! All five describe the scam as a *type* of attack. None answers the
//! distinct question an awareness-training lead, a compliance officer, or an
//! incident-response team asks when routing an alert: **"who is this scam
//! specifically designed to hurt?"**
//!
//! Two signals with identical categories, MITRE techniques, persuasion
//! principles, extraction vectors, and lifecycle stages may require
//! completely different interventions if one targets Medicare recipients
//! (65+) while the other targets job seekers in financial distress. The
//! awareness material, the protective messaging, and the at-risk employee
//! groups to notify are entirely different.
//!
//! This module adds that sixth, *targeting* lens by mapping each signal to
//! the **victim profile** — the population the scam is specifically
//! engineered to exploit. The taxonomy is grounded in demographic loss data
//! from the FTC Consumer Sentinel Network Data Book and the FBI IC3 Annual
//! Report, which both segment fraud losses and complaint volumes by victim
//! age group, employment status, and vulnerability category.
//!
//! The key functional primitive is [`is_targeted_attack`]: it distinguishes
//! *targeted* scams (a specific demographic hook that demands tailored
//! awareness) from *broadcast* scams (general-population overlays where
//! universal anti-scam messaging is sufficient).
//!
//! Pure classification over already-computed signals: no OS calls, no network,
//! no ML, no new dependencies.
//!
//! Sources: FTC Consumer Sentinel Network Data Book 2024 (loss/complaint
//! breakdown by age, scam type, and payment method); FBI IC3 Annual Report
//! 2024 (elder fraud chapter; crypto investment fraud; business email
//! compromise; recovery asset team; sextortion); AARP Fraud Watch Network
//! 2024 (elder-targeting scam taxonomy); FTC Business Guidance on job and
//! business-opportunity fraud; CFPB student-loan scam alerts 2024.

use serde::Serialize;

/// The primary victim population a scam signal is designed to target.
///
/// Ordered for stable audit output (specific profiles first by name,
/// [`Self::General`] last as the weakest/broadest signal). Use
/// [`is_targeted_attack`] to test whether any non-`General` profile is
/// present — targeted scams need tailored awareness; broadcast scams need
/// general messaging.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VictimProfile {
    /// Cryptocurrency holders and retail investors: pig-butchering
    /// ("sha zhu pan") investment fraud, giveaway/doubling scams, and
    /// wallet-drain lures. FBI IC3 2024: crypto investment fraud = $5.8B
    /// loss — the single largest loss category in the report.
    CryptoInvestor,
    /// Older adults (55+), disproportionately targeted by tech-support,
    /// Medicare/benefit, and family-emergency ("grandparent") scams.
    /// FBI IC3 2024 Elder Fraud Report: adults 60+ lost $3.4B — the most
    /// of any age group; tech support was the #1 elder-fraud type.
    ElderAdult,
    /// Immigrants, visa holders, and non-native speakers threatened with
    /// deportation, visa revocation, or criminal-overstay charges.
    /// FTC 2024: government-impersonation losses are disproportionately
    /// high among immigrant populations.
    Immigrant,
    /// Job seekers, gig workers, and unemployed individuals: fake-employment,
    /// task-app income fraud, secret-shopper money-mule, and
    /// MLM pyramid-scheme recruitment.
    /// FTC 2024: job and business-opportunity fraud cost victims $501M.
    JobSeeker,
    /// Prior fraud victims targeted for secondary victimization: recovery
    /// and refund scams that promise to return previously lost funds.
    /// FBI IC3 2024 Recovery Asset Team specifically tracks this pattern
    /// of re-targeting people who have already lost money to fraud.
    PriorVictim,
    /// Students, young adults, and individuals under financial pressure:
    /// student-loan forgiveness and debt-relief scams.
    /// CFPB 2024: spike in student-loan scams coincided with the SAVE
    /// plan; debt-relief scams target those already in distress.
    Student,
    /// Military veterans and their families: VA disability-claim assistance
    /// fee frauds, veteran-benefit-expiry lures, and GI Bill scams.
    /// FTC 2024 Military Consumer Sentinel: veterans lose disproportionately
    /// to benefit-assistance and impersonation scams.
    Veteran,
    /// General population — broadcast targeting with no specific demographic
    /// hook. Overlays using universal fear triggers (bank fraud alerts,
    /// tax notices, brand phishing, IP alarms) that anyone might encounter.
    /// [`is_targeted_attack`] returns `false` when only `General` profiles
    /// are present.
    General,
}

impl VictimProfile {
    /// Stable snake_case name for logs / SIEM / CLI output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CryptoInvestor => "crypto_investor",
            Self::ElderAdult => "elder_adult",
            Self::Immigrant => "immigrant",
            Self::JobSeeker => "job_seeker",
            Self::PriorVictim => "prior_victim",
            Self::Student => "student",
            Self::Veteran => "veteran",
            Self::General => "general",
        }
    }
}

/// Map a single signal name to the primary victim population it targets.
///
/// Returns `None` for window-geometry, evasion-mechanic, and delivery signals
/// (`fullscreen`, `mixed_script`, `cloud_storage_abuse`, …) — these describe
/// the overlay's *structure*, not the attacker's *targeting strategy*. Also
/// returns `None` for pure-coercion signals (`urgency_countdown`,
/// `alarm_density`, `forced_retention_cue`) that amplify a scam's pressure
/// but carry no demographic information on their own.
///
/// Returns `Some(VictimProfile::General)` for content signals that represent
/// broad-targeting attacks with no specific demographic hook — everyone has a
/// bank account, everyone files taxes, and anyone can receive a brand-phishing
/// overlay. Returns `Some(specific profile)` only when the signal's scam family
/// *primarily* victimises a named population per FTC/FBI IC3 loss data.
#[must_use]
pub fn victim_profile_of(signal: &str) -> Option<VictimProfile> {
    match signal {
        // ── CryptoInvestor ───────────────────────────────────────────────────
        // FBI IC3 2024: $5.8B in crypto investment fraud — the highest single
        // category. These scams require a victim who owns or can obtain
        // cryptocurrency; the signal itself is the demographic selector.
        "pig_butchering_lure"           // romance/mentor → invest on our platform
        | "crypto_giveaway_scam"        // celebrity/exchange doubling scam
        | "crypto_drain_lure"           // wallet alarm / seed-phrase harvest
        | "wallet_connect_popup_lure"   // IC3 2024 #1 loss: wallet-drainer via fake connect popup
        => Some(VictimProfile::CryptoInvestor),

        // ── ElderAdult ───────────────────────────────────────────────────────
        // FBI IC3 2024 Elder Fraud Report: tech support was the #1 elder-fraud
        // type by complaint count. "Refund scams" and "grandparent scams" also
        // appear in the top-5 elder-fraud categories. Medicare/Medicaid targets
        // the 65+ population by statutory design. Timeshare owners skew 55+
        // per FTC travel-prize fraud data.
        "fake_bsod_lure"                // fake OS crash → call "Microsoft" tech support
        | "fake_scanner_cue"            // fake AV scan → call tech support
        | "windows_defender_alert_lure" // Defender brand + malware → tech support
        | "windows_activation_scam"     // fake activation alarm → call tech support
        | "av_brand_renewal_scam"       // named AV expired → call tech support
        | "tech_support_invoice_scam"   // fake charge → call to cancel → elder exploit
        | "tech_support_chat_lure"      // live-chat tech-support pivot
        | "refund_scam_cue"             // FTC 2024: refund/overpayment scam tops elder-fraud
        | "healthcare_scam"             // Medicare/Medicaid: by definition 65+
        | "family_emergency_scam"       // "grandparent scam" — explicitly elder-targeting
        | "timeshare_travel_scam"       // FTC: timeshare owners predominantly 55+
        => Some(VictimProfile::ElderAdult),

        // ── Immigrant ────────────────────────────────────────────────────────
        // Immigration/visa threat scams target non-native speakers and visa
        // holders who cannot easily verify the legal claim and fear real
        // consequences of immigration enforcement.
        "immigration_visa_scam"
        => Some(VictimProfile::Immigrant),

        // ── JobSeeker ────────────────────────────────────────────────────────
        // FTC 2024 report: job and business-opportunity fraud cost $501M.
        // Task-app and secret-shopper scams target the unemployed/underemployed;
        // MLM recruitment targets those seeking supplemental income.
        "job_scam"
        | "task_app_scam"
        | "secret_shopper_scam"
        | "mlm_pyramid_recruitment"
        => Some(VictimProfile::JobSeeker),

        // ── PriorVictim ──────────────────────────────────────────────────────
        // Recovery scams (secondary victimization) target people who have
        // already lost money to fraud and are desperately seeking to recover it.
        // The FBI IC3 Recovery Asset Team tracks this pattern explicitly.
        "recovery_scam"
        => Some(VictimProfile::PriorVictim),

        // ── Student ──────────────────────────────────────────────────────────
        // CFPB 2024 alerts specifically name student-loan scams as a spiking
        // category correlated with the SAVE plan rollout. Debt-relief scams
        // target those already in financial distress — overlapping with students
        // and young adults carrying loan burdens.
        "student_loan_scam"
        | "debt_relief_scam"
        => Some(VictimProfile::Student),

        // ── Veteran ──────────────────────────────────────────────────────────
        // FTC Military Consumer Sentinel 2024: veterans disproportionately
        // targeted by benefit-claim-assistance and pension-advance scams.
        "veterans_benefit_scam"
        => Some(VictimProfile::Veteran),

        // ── General (broad-targeting content signals) ─────────────────────
        // These signals represent scam families that target the general
        // population — anyone with a bank account, tax obligation, social
        // media presence, or internet-connected device. No specific
        // demographic hook is present; universal anti-scam awareness
        // messaging applies.
        "national_id_alarm"             // SSN/NIN alarms: anyone with a national ID
        | "tax_authority_scam"          // IRS/HMRC: all taxpayers
        | "bank_account_alarm"          // bank fraud alert: any bank customer
        | "social_media_account_alarm"  // account suspended: any platform user
        | "credential_harvest_cue"      // account compromise: all users
        | "otp_interception_scam"       // 2FA relay: any service with 2FA
        | "dark_web_breach_lure"        // breach notice: any internet user
        | "brand_impersonation"         // look-alike domain: broad phishing
        | "combosquat_brand"            // brand+lure domain: broad phishing
        | "typosquat_brand"             // brand typo: broad phishing
        | "authority_lure"              // FBI/police: any resident
        | "advance_fee_lure"            // 419/windfall: any recipient of "good news"
        | "loan_fee_scam"               // fake loan: financially distressed (broad)
        | "government_grant_scam"       // fake grant: any citizen
        | "prize_lure"                  // fake prize: anyone
        | "charity_scam_lure"           // fake charity: any donor
        | "rental_scam_lure"            // fake rental: any housing seeker
        | "pet_sale_scam"               // fake pet: any prospective buyer
        | "package_fee_lure"            // delivery fee: any online shopper
        | "subscription_lure"           // fake expiry: any subscription holder
        | "streaming_billing_scam"      // streaming billing: streaming service users
        | "software_subscription_scam"  // SaaS billing: any SaaS/AI tool user
        | "cloud_quota_lure"            // storage full: any cloud storage user
        | "utility_cutoff_threat"       // utility: any utility customer
        | "traffic_fine_scam"           // traffic/toll: any driver
        | "fake_copyright_scam"         // DMCA notice: any internet user
        | "sextortion_lure"             // webcam claim: broad (any adult user)
        | "ip_alarm_lure"               // IP alarm: any internet user
        | "qr_code_lure"                // QR/quishing: any smartphone user
        | "clickfix_instruction"        // ClickFix: any desktop user
        | "screen_share_lure"           // screen share: cross-context (IT + elder)
        | "remote_access_lure"          // remote access: cross-context (IT + elder)
        | "download_trap_lure"          // fake download: any user
        | "notification_permission_bait" // fake content-gate: any browser user
        | "gift_card_demand"            // gift card: cross-scam-type (elder + general)
        | "phone_number"                // support phone: cross-context
        | "blocklist_phone"             // known scam number: cross-context
        | "false_registration_billing"  // ワンクリック詐欺: Japanese internet users (general)
        | "survey_reward_scam"          // survey bait: young adults and general
        | "toad_case_number_lure"       // TOAD: fake case ID + call CTA — broad telephone phishing
        | "fake_browser_security_warning" // fake cert/SSL error: any browser user
        => Some(VictimProfile::General),

        // Window geometry, evasion mechanics, delivery signals, and pure
        // coercion mechanics carry no demographic information.
        _ => None,
    }
}

/// Collect the distinct victim profiles present in a set of signals, sorted
/// and deduplicated for a stable audit representation (`General` sorts last).
///
/// Accepts any slice whose elements implement `AsRef<str>`, mirroring
/// [`crate::extraction::extraction_vectors_of_signals`].
#[must_use]
pub fn victim_profiles_of_signals<S: AsRef<str>>(signals: &[S]) -> Vec<VictimProfile> {
    let mut ps: Vec<VictimProfile> = signals
        .iter()
        .filter_map(|s| victim_profile_of(s.as_ref()))
        .collect();
    ps.sort_unstable();
    ps.dedup();
    ps
}

/// Returns `true` when the signal set contains at least one signal that
/// targets a **specific** victim population — i.e., any profile other than
/// [`VictimProfile::General`].
///
/// This is the triage primitive for awareness-training routing: a *targeted*
/// attack requires custom messaging aimed at the at-risk group (e.g., elder
/// fraud education for a `healthcare_scam`), whereas a *broadcast* attack is
/// addressed by universal anti-scam messaging. Returns `false` when all
/// signals map to `General` or to `None` (mechanics/geometry).
#[must_use]
pub fn is_targeted_attack<S: AsRef<str>>(signals: &[S]) -> bool {
    signals
        .iter()
        .filter_map(|s| victim_profile_of(s.as_ref()))
        .any(|p| p != VictimProfile::General)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Profile spot-checks per category ─────────────────────────────────────

    #[test]
    fn crypto_investor_signals() {
        assert_eq!(
            victim_profile_of("pig_butchering_lure"),
            Some(VictimProfile::CryptoInvestor)
        );
        assert_eq!(
            victim_profile_of("crypto_giveaway_scam"),
            Some(VictimProfile::CryptoInvestor)
        );
        assert_eq!(
            victim_profile_of("crypto_drain_lure"),
            Some(VictimProfile::CryptoInvestor)
        );
    }

    #[test]
    fn elder_adult_signals() {
        assert_eq!(
            victim_profile_of("fake_bsod_lure"),
            Some(VictimProfile::ElderAdult)
        );
        assert_eq!(
            victim_profile_of("healthcare_scam"),
            Some(VictimProfile::ElderAdult)
        );
        assert_eq!(
            victim_profile_of("family_emergency_scam"),
            Some(VictimProfile::ElderAdult)
        );
        assert_eq!(
            victim_profile_of("tech_support_invoice_scam"),
            Some(VictimProfile::ElderAdult)
        );
        assert_eq!(
            victim_profile_of("timeshare_travel_scam"),
            Some(VictimProfile::ElderAdult)
        );
        assert_eq!(
            victim_profile_of("av_brand_renewal_scam"),
            Some(VictimProfile::ElderAdult)
        );
    }

    #[test]
    fn immigrant_signal() {
        assert_eq!(
            victim_profile_of("immigration_visa_scam"),
            Some(VictimProfile::Immigrant)
        );
    }

    #[test]
    fn job_seeker_signals() {
        assert_eq!(
            victim_profile_of("job_scam"),
            Some(VictimProfile::JobSeeker)
        );
        assert_eq!(
            victim_profile_of("task_app_scam"),
            Some(VictimProfile::JobSeeker)
        );
        assert_eq!(
            victim_profile_of("secret_shopper_scam"),
            Some(VictimProfile::JobSeeker)
        );
        assert_eq!(
            victim_profile_of("mlm_pyramid_recruitment"),
            Some(VictimProfile::JobSeeker)
        );
    }

    #[test]
    fn prior_victim_signal() {
        assert_eq!(
            victim_profile_of("recovery_scam"),
            Some(VictimProfile::PriorVictim)
        );
    }

    #[test]
    fn student_signals() {
        assert_eq!(
            victim_profile_of("student_loan_scam"),
            Some(VictimProfile::Student)
        );
        assert_eq!(
            victim_profile_of("debt_relief_scam"),
            Some(VictimProfile::Student)
        );
    }

    #[test]
    fn veteran_signal() {
        assert_eq!(
            victim_profile_of("veterans_benefit_scam"),
            Some(VictimProfile::Veteran)
        );
    }

    #[test]
    fn general_broadcast_signals() {
        for s in [
            "national_id_alarm",
            "tax_authority_scam",
            "bank_account_alarm",
            "social_media_account_alarm",
            "credential_harvest_cue",
            "otp_interception_scam",
            "dark_web_breach_lure",
            "brand_impersonation",
            "advance_fee_lure",
            "prize_lure",
            "sextortion_lure",
            "ip_alarm_lure",
        ] {
            assert_eq!(
                victim_profile_of(s),
                Some(VictimProfile::General),
                "{s} should be General"
            );
        }
    }

    // ── No profile for mechanics/geometry signals ─────────────────────────────

    #[test]
    fn geometry_signals_have_no_profile() {
        for s in [
            "fullscreen",
            "topmost",
            "blocks_input",
            "no_close_button",
            "input_trap",
            "sudden_fullscreen_takeover",
            "unsolicited",
            "very_new",
            "user_initiated",
            "mixed_script",
            "urgency_countdown",
            "alarm_density",
            "forced_retention_cue",
            "cloud_storage_abuse",
            "data_uri_page",
            "ip_host_url",
            "url_path_lure",
        ] {
            assert!(
                victim_profile_of(s).is_none(),
                "{s} should carry no victim profile"
            );
        }
    }

    #[test]
    fn unknown_signal_has_no_profile() {
        assert!(victim_profile_of("not_a_real_signal").is_none());
    }

    // ── victim_profiles_of_signals ────────────────────────────────────────────

    #[test]
    fn collector_dedups_and_sorts() {
        // Two ElderAdult signals → one ElderAdult entry.
        let signals: &[&str] = &["fake_bsod_lure", "healthcare_scam"];
        let ps = victim_profiles_of_signals(signals);
        assert_eq!(ps, vec![VictimProfile::ElderAdult]);
    }

    #[test]
    fn collector_multiple_profiles_sorted() {
        // CryptoInvestor + ElderAdult + General — sorted by declaration order.
        let signals: &[&str] = &[
            "pig_butchering_lure",
            "family_emergency_scam",
            "bank_account_alarm",
        ];
        let ps = victim_profiles_of_signals(signals);
        assert_eq!(
            ps,
            vec![
                VictimProfile::CryptoInvestor,
                VictimProfile::ElderAdult,
                VictimProfile::General
            ]
        );
    }

    #[test]
    fn collector_geometry_only_is_empty() {
        let signals: &[&str] = &["fullscreen", "topmost", "urgency_countdown"];
        assert!(victim_profiles_of_signals(signals).is_empty());
    }

    #[test]
    fn collector_empty_input_is_empty() {
        let none: &[&str] = &[];
        assert!(victim_profiles_of_signals(none).is_empty());
    }

    #[test]
    fn collector_works_with_owned_strings() {
        let signals: Vec<String> = vec![
            "veterans_benefit_scam".to_string(),
            "student_loan_scam".to_string(),
        ];
        let ps = victim_profiles_of_signals(&signals);
        assert_eq!(ps, vec![VictimProfile::Student, VictimProfile::Veteran]);
    }

    // ── is_targeted_attack ────────────────────────────────────────────────────

    #[test]
    fn targeted_attack_true_for_specific_profile() {
        // Healthcare scam (ElderAdult) → targeted.
        let signals: &[&str] = &["healthcare_scam", "alarm_density"];
        assert!(is_targeted_attack(signals));
    }

    #[test]
    fn targeted_attack_true_even_with_general_mixed_in() {
        // Veteran signal + general signals → still targeted.
        let signals: &[&str] = &["veterans_benefit_scam", "national_id_alarm"];
        assert!(is_targeted_attack(signals));
    }

    #[test]
    fn targeted_attack_false_for_general_only() {
        // Only General-targeting signals → not targeted.
        let signals: &[&str] = &[
            "bank_account_alarm",
            "brand_impersonation",
            "sextortion_lure",
        ];
        assert!(!is_targeted_attack(signals));
    }

    #[test]
    fn targeted_attack_false_for_geometry_only() {
        // Only geometry/mechanic signals → no profile → not targeted.
        let signals: &[&str] = &["fullscreen", "topmost", "urgency_countdown"];
        assert!(!is_targeted_attack(signals));
    }

    #[test]
    fn targeted_attack_false_for_empty() {
        let none: &[&str] = &[];
        assert!(!is_targeted_attack(none));
    }

    // ── Profile ordering: General sorts last ─────────────────────────────────

    #[test]
    fn general_sorts_after_all_specific_profiles() {
        assert!(VictimProfile::CryptoInvestor < VictimProfile::General);
        assert!(VictimProfile::ElderAdult < VictimProfile::General);
        assert!(VictimProfile::Immigrant < VictimProfile::General);
        assert!(VictimProfile::JobSeeker < VictimProfile::General);
        assert!(VictimProfile::PriorVictim < VictimProfile::General);
        assert!(VictimProfile::Student < VictimProfile::General);
        assert!(VictimProfile::Veteran < VictimProfile::General);
    }

    // ── as_str round-trip ─────────────────────────────────────────────────────

    #[test]
    fn as_str_round_trips_names() {
        assert_eq!(VictimProfile::CryptoInvestor.as_str(), "crypto_investor");
        assert_eq!(VictimProfile::ElderAdult.as_str(), "elder_adult");
        assert_eq!(VictimProfile::Immigrant.as_str(), "immigrant");
        assert_eq!(VictimProfile::JobSeeker.as_str(), "job_seeker");
        assert_eq!(VictimProfile::PriorVictim.as_str(), "prior_victim");
        assert_eq!(VictimProfile::Student.as_str(), "student");
        assert_eq!(VictimProfile::Veteran.as_str(), "veteran");
        assert_eq!(VictimProfile::General.as_str(), "general");
    }
}
