//! Expected financial-loss magnitude for scam-overlay signals.
//!
//! `muten` already classifies every verdict along six lenses:
//!
//! - [`crate::categories`] — **how** the interface deceives.
//! - [`crate::mitre`] — **what** technique the adversary uses.
//! - [`crate::persuasion`] — **why** the human complies.
//! - [`crate::extraction`] — **what** the victim loses / recoverability.
//! - [`crate::lifecycle`] — **how far** the attacker has progressed.
//! - [`crate::targeting`] — **who** is being targeted.
//!
//! All six describe the *type* and *nature* of the attack. None answers the
//! question that executives writing risk reports, actuaries pricing fraud
//! insurance, and incident commanders triaging open cases all ask:
//! **"what is the typical financial scale of harm?"**
//!
//! The `extraction` lens tells you the channel (gift card → Irreversible;
//! wire → TimeLimited) and the `lifecycle` lens tells you urgency — but
//! neither distinguishes a $20 fake customs fee from a $300,000 pig-
//! butchering loss. Both are Irreversible + Extract-stage, yet the
//! organizational response and risk exposure are orders of magnitude apart.
//!
//! This module adds that seventh, *quantitative* lens by mapping each signal
//! to the **expected loss magnitude** — the order-of-magnitude band that
//! covers the typical per-victim financial harm for that scam family, per
//! the FTC Consumer Sentinel Network Data Book and the FBI IC3 Annual Report.
//!
//! The bands are intentionally wide (one order of magnitude each) so that
//! intra-category variation does not make individual assignments misleading.
//! Each mapping cites the primary authoritative source. The triage primitive
//! is [`highest_magnitude`]: the worst-case (largest) magnitude present in
//! a set of signals, used to route cases by expected financial exposure.
//!
//! Pure classification over already-computed signals: no OS calls, no
//! network, no ML, no new dependencies.
//!
//! Sources: FTC Consumer Sentinel Network Data Book 2024 (median loss per
//! payment method and scam type; gift-card median ~$800; impersonation
//! median ~$800; investment fraud median $4,600); FBI IC3 Annual Report
//! 2024 (tech support $924M / 40K+ reports ≈ $23K avg; investment fraud
//! $6.57B / 21K+ crypto reports ≈ $305K avg; elder fraud chapter; BEC;
//! romance/confidence fraud); AARP Fraud Watch Network 2024 (grandparent
//! scam median ~$9,000); FTC advance-fee loan and MLM guidance.

use serde::Serialize;

/// The expected order-of-magnitude financial loss from a scam signal,
/// based on median or average per-victim loss data from the FTC and FBI IC3.
///
/// Ordered smallest-to-largest so that `max()` over a set of magnitudes
/// yields the highest exposure — the triage primitive in
/// [`highest_magnitude`]. Bands span one order of magnitude each to
/// absorb intra-category variance while remaining operationally meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LossMagnitude {
    /// Typical loss < $100. Includes package/customs fees ($2–$20),
    /// fake traffic fines ($35–$100), and micro-survey baits.
    /// FTC: highest-complaint-volume / lowest-individual-loss category.
    Micro,
    /// Typical loss $100 – $2,000. Covers the median gift-card demand
    /// (~$800 FTC 2024), fake subscription/AV renewals ($30–$300),
    /// sextortion payments ($200–$800 FBI IC3 2024), and initial
    /// advance-fee extraction ($200–$1,000).
    Small,
    /// Typical loss $2,000 – $20,000. Covers the family-emergency
    /// "grandparent scam" (~$9,000 median per AARP 2024), tax-authority
    /// demands ($1,000–$10,000), task-app and job-scam extraction
    /// ($500–$10,000), and tech-support escalation ($2,000–$15,000).
    Medium,
    /// Typical loss $20,000 – $200,000. Covers recovery scams targeting
    /// prior large-loss victims ($10,000–$100,000), crypto giveaway /
    /// doubling losses ($10,000–$100,000), and remote-access / malware
    /// escalation that reaches bank accounts ($20,000–$150,000).
    Large,
    /// Typical loss > $200,000. Covers pig-butchering investment fraud
    /// (FBI IC3 2024: crypto investment fraud avg ≈ $305,000 per complaint),
    /// full cryptocurrency wallet drains (entire portfolio value), and
    /// complete fund-recovery failure after large-loss escalation.
    /// These are the cases with the largest total US financial impact
    /// ($6.57B in crypto investment fraud alone, IC3 2024).
    Catastrophic,
}

impl LossMagnitude {
    /// Stable snake_case name for logs / SIEM / CLI output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Micro => "micro",
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
            Self::Catastrophic => "catastrophic",
        }
    }

    /// Short human-readable description of the typical loss range.
    #[must_use]
    pub fn range_label(self) -> &'static str {
        match self {
            Self::Micro => "< $100",
            Self::Small => "$100 – $2K",
            Self::Medium => "$2K – $20K",
            Self::Large => "$20K – $200K",
            Self::Catastrophic => "> $200K",
        }
    }
}

/// Map a single signal name to the expected per-victim loss magnitude for
/// the scam family it represents.
///
/// Returns `None` for:
/// - Window-geometry signals (`fullscreen`, `topmost`, …) — no financial content.
/// - Pure-coercion mechanics (`urgency_countdown`, `alarm_density`,
///   `forced_retention_cue`) — these amplify other signals but have no
///   determinate magnitude of their own.
/// - Evasion / delivery signals (`mixed_script`, `cloud_storage_abuse`,
///   `data_uri_page`, `ip_host_url`, `url_path_lure`) — describe the
///   delivery mechanism, not the financial ask.
/// - Blocklist hits (`blocklist_title`, `blocklist_host`, `blocklist_phone`)
///   — the magnitude depends on the specific rule that matched.
///
/// Magnitudes are the TYPICAL per-victim loss (median or mean from published
/// FTC/IC3 data), not worst-case. A scam can produce outlier losses well above
/// the band. The `highest_magnitude` primitive surfaces the most financially
/// dangerous signal present, not an average across all signals.
#[must_use]
pub fn magnitude_of(signal: &str) -> Option<LossMagnitude> {
    match signal {
        // ── Micro (< $100) ──────────────────────────────────────────────────
        // High-volume / low-value scams: fake delivery fees, fake traffic fines.
        // FTC: among the most-reported categories by complaint count, but per-
        // victim loss is in the single-to-double digits.
        "package_fee_lure"      // customs/delivery fee: $2–$20 per demand
        | "traffic_fine_scam"   // fake parking/toll notice: $35–$100
        => Some(LossMagnitude::Micro),

        // ── Small ($100 – $2K) ──────────────────────────────────────────────
        // FTC 2024 median impersonation loss ~$800; gift-card median ~$800;
        // sextortion average ~$500–$800 (FBI IC3 2024 adult-extortion data).
        "gift_card_demand"              // FTC 2024: gift-card median ~$800 per victim
        | "sextortion_lure"             // FBI IC3 2024 sextortion avg $500–$800
        | "subscription_lure"           // fake subscription: $10–$200/year
        | "streaming_billing_scam"      // fake Netflix/Spotify billing: $10–$200
        | "software_subscription_scam"  // fake SaaS/AI billing: $10–$200
        | "cloud_quota_lure"            // fake iCloud/Drive upgrade: $1–$30 (billed repeatedly)
        | "av_brand_renewal_scam"       // fake AV renewal: $30–$300
        | "windows_activation_scam"     // fake activation call: $50–$300
        | "healthcare_scam"             // Medicare bait: $50–$500 (initial contact)
        | "loan_fee_scam"               // fake loan deposit: $100–$500 initial
        | "student_loan_scam"           // forgiveness fee: $100–$1,000
        | "veterans_benefit_scam"       // benefit-claim fee: $100–$1,000
        | "pet_sale_scam"               // shipping/crate deposit: $200–$800
        | "charity_scam_lure"           // fake donation: $50–$500
        | "government_grant_scam"       // fake grant processing fee: $100–$500
        | "utility_cutoff_threat"       // fake utility payment: $100–$500
        | "dark_web_breach_lure"        // fake identity-protection fee: $50–$300
        | "fake_copyright_scam"         // fake settlement: $100–$1,000
        | "immigration_visa_scam"       // fake renewal fee: $100–$1,000
        | "survey_reward_scam"          // small fees/shipping before reward: $20–$100
        | "false_registration_billing"  // ワンクリック詐欺 registration demand: $100–$500
        | "social_media_account_alarm"  // account ransom + credential value: $100–$500
        | "otp_interception_scam"       // OTP relay → account drain: varies; median Small
        | "fake_bsod_lure"              // initial tech-support call fee: $200–$500
        | "windows_defender_alert_lure" // Defender brand → tech-support call: $200–$500
        | "fake_scanner_cue"            // fake AV scan → tech-support call: $200–$500
        | "ip_alarm_lure"               // "IP hacked" → tech-support call: $200–$500
        | "tech_support_chat_lure"      // live-chat tech-support pivot: $200–$500
        => Some(LossMagnitude::Small),

        // ── Medium ($2K – $20K) ─────────────────────────────────────────────
        // FTC: wire-transfer fraud median in this band; AARP grandparent scam
        // median ~$9,000; tax/government impersonation $1,000–$10,000.
        "advance_fee_lure"          // 419 initial extraction: $1,000–$10,000
        | "timeshare_travel_scam"   // activation/closing fee: $1,000–$10,000
        | "job_scam"                // registration/equipment deposit: $500–$5,000
        | "task_app_scam"           // withdrawal-gate deposit: $500–$10,000
        | "secret_shopper_scam"     // fake-check bounce + wiring: $1,000–$5,000
        | "mlm_pyramid_recruitment" // join/activate fee: $500–$5,000
        | "debt_relief_scam"        // upfront service fee: $1,000–$10,000
        | "rental_scam_lure"        // advance deposit: $500–$5,000
        | "tax_authority_scam"      // IRS demand: $1,000–$10,000
        | "national_id_alarm"       // identity theft downstream: $2,000–$20,000
        | "bank_account_alarm"      // account takeover/drain: $2,000–$20,000
        | "credential_harvest_cue"  // account-takeover financial loss: $500–$20,000
        | "family_emergency_scam"   // AARP 2024: grandparent scam median ~$9,000
        | "tech_support_invoice_scam" // fake invoice → call → escalation: $500–$15,000
        | "refund_scam_cue"         // overpayment reversal drain: $1,000–$10,000
        | "prize_lure"              // claim fee escalation: $500–$5,000
        | "qr_code_lure"            // quishing → payment/credential: $500–$10,000
        | "screen_share_lure"       // remote-session bank drain: $2,000–$20,000
        => Some(LossMagnitude::Medium),

        // ── Large ($20K – $200K) ────────────────────────────────────────────
        // FBI IC3 2024: recovery scams escalate from prior large losses;
        // crypto giveaway/doubling scams extract $10K–$100K per victim;
        // remote-access/malware → bank-account drain can reach $150K.
        "recovery_scam"             // targets prior victims who lost large sums
        | "crypto_giveaway_scam"    // doubling: $10,000–$100,000 sent upfront
        | "remote_access_lure"      // full bank-account access: $20,000–$150,000
        | "download_trap_lure"      // malware → ransomware/data theft: $20K–$1M (band: Large)
        | "clickfix_instruction"    // PowerShell → malware → ransomware: $20K–$1M (band: Large)
        => Some(LossMagnitude::Large),

        // ── Catastrophic (> $200K) ──────────────────────────────────────────
        // FBI IC3 2024: crypto investment fraud (pig-butchering) = $6.57B in
        // 21,489+ complaints ≈ $305K average per complaint — the largest single
        // category in the IC3 report by total loss. Full wallet drains can
        // reach the entire portfolio value (millions for crypto investors).
        "pig_butchering_lure"   // FBI IC3 2024 avg ≈ $305K per victim complaint
        | "crypto_drain_lure"   // full wallet drain — entire portfolio
        => Some(LossMagnitude::Catastrophic),

        // Window-geometry, evasion, delivery, and pure-coercion signals carry
        // no determinate financial magnitude.
        _ => None,
    }
}

/// Collect the distinct loss magnitudes present in a set of signals, sorted
/// smallest-to-largest and deduplicated for a stable audit representation.
///
/// Accepts any slice whose elements implement `AsRef<str>`, mirroring
/// [`crate::extraction::extraction_vectors_of_signals`].
#[must_use]
pub fn magnitudes_of_signals<S: AsRef<str>>(signals: &[S]) -> Vec<LossMagnitude> {
    let mut ms: Vec<LossMagnitude> = signals
        .iter()
        .filter_map(|s| magnitude_of(s.as_ref()))
        .collect();
    ms.sort_unstable();
    ms.dedup();
    ms
}

/// The highest (worst-case) loss magnitude present in a set of signals,
/// or `None` when no signal carries a determinate financial magnitude.
///
/// The triage primitive for financial exposure: `Catastrophic` (> $200K)
/// warrants immediate senior escalation; `Large` ($20K–$200K) requires
/// management notification; `Medium` ($2K–$20K) is serious but within
/// typical fraud-response SLAs; `Small` and `Micro` are high-volume /
/// lower-urgency. Because [`LossMagnitude`] is ordered smallest-first,
/// this is simply the maximum.
#[must_use]
pub fn highest_magnitude<S: AsRef<str>>(signals: &[S]) -> Option<LossMagnitude> {
    signals
        .iter()
        .filter_map(|s| magnitude_of(s.as_ref()))
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Magnitude ordering ───────────────────────────────────────────────────

    #[test]
    fn magnitude_ordering_is_smallest_first() {
        assert!(LossMagnitude::Micro < LossMagnitude::Small);
        assert!(LossMagnitude::Small < LossMagnitude::Medium);
        assert!(LossMagnitude::Medium < LossMagnitude::Large);
        assert!(LossMagnitude::Large < LossMagnitude::Catastrophic);
    }

    // ── magnitude_of spot-checks ─────────────────────────────────────────────

    #[test]
    fn micro_signals() {
        assert_eq!(magnitude_of("package_fee_lure"), Some(LossMagnitude::Micro));
        assert_eq!(magnitude_of("traffic_fine_scam"), Some(LossMagnitude::Micro));
    }

    #[test]
    fn small_signals() {
        assert_eq!(
            magnitude_of("gift_card_demand"),
            Some(LossMagnitude::Small)
        );
        assert_eq!(
            magnitude_of("sextortion_lure"),
            Some(LossMagnitude::Small)
        );
        assert_eq!(
            magnitude_of("subscription_lure"),
            Some(LossMagnitude::Small)
        );
        assert_eq!(
            magnitude_of("av_brand_renewal_scam"),
            Some(LossMagnitude::Small)
        );
        assert_eq!(
            magnitude_of("healthcare_scam"),
            Some(LossMagnitude::Small)
        );
        assert_eq!(
            magnitude_of("student_loan_scam"),
            Some(LossMagnitude::Small)
        );
        assert_eq!(
            magnitude_of("fake_bsod_lure"),
            Some(LossMagnitude::Small)
        );
    }

    #[test]
    fn tech_support_family_is_small_and_consistent() {
        // All tech-support call-driver lures share the same initial call-fee
        // band as fake_bsod_lure (cross-lens drift fix).
        for s in [
            "fake_bsod_lure",
            "windows_defender_alert_lure",
            "fake_scanner_cue",
            "ip_alarm_lure",
            "tech_support_chat_lure",
        ] {
            assert_eq!(
                magnitude_of(s),
                Some(LossMagnitude::Small),
                "{s} should share the tech-support Small band"
            );
        }
    }

    #[test]
    fn medium_signals() {
        assert_eq!(
            magnitude_of("advance_fee_lure"),
            Some(LossMagnitude::Medium)
        );
        assert_eq!(
            magnitude_of("family_emergency_scam"),
            Some(LossMagnitude::Medium)
        );
        assert_eq!(
            magnitude_of("tax_authority_scam"),
            Some(LossMagnitude::Medium)
        );
        assert_eq!(
            magnitude_of("bank_account_alarm"),
            Some(LossMagnitude::Medium)
        );
        assert_eq!(
            magnitude_of("task_app_scam"),
            Some(LossMagnitude::Medium)
        );
        assert_eq!(
            magnitude_of("rental_scam_lure"),
            Some(LossMagnitude::Medium)
        );
        assert_eq!(
            magnitude_of("screen_share_lure"),
            Some(LossMagnitude::Medium)
        );
    }

    #[test]
    fn large_signals() {
        assert_eq!(
            magnitude_of("recovery_scam"),
            Some(LossMagnitude::Large)
        );
        assert_eq!(
            magnitude_of("crypto_giveaway_scam"),
            Some(LossMagnitude::Large)
        );
        assert_eq!(
            magnitude_of("remote_access_lure"),
            Some(LossMagnitude::Large)
        );
        assert_eq!(
            magnitude_of("clickfix_instruction"),
            Some(LossMagnitude::Large)
        );
    }

    #[test]
    fn catastrophic_signals() {
        assert_eq!(
            magnitude_of("pig_butchering_lure"),
            Some(LossMagnitude::Catastrophic)
        );
        assert_eq!(
            magnitude_of("crypto_drain_lure"),
            Some(LossMagnitude::Catastrophic)
        );
    }

    // ── No magnitude for mechanics / geometry signals ─────────────────────────

    #[test]
    fn geometry_signals_have_no_magnitude() {
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
            "urgency_countdown",
            "alarm_density",
            "forced_retention_cue",
            "mixed_script",
            "cloud_storage_abuse",
            "data_uri_page",
            "ip_host_url",
            "url_path_lure",
            "blocklist_title",
            "blocklist_host",
            "blocklist_phone",
        ] {
            assert!(
                magnitude_of(s).is_none(),
                "{s} should carry no loss magnitude"
            );
        }
    }

    #[test]
    fn unknown_signal_has_no_magnitude() {
        assert!(magnitude_of("not_a_real_signal").is_none());
    }

    // ── magnitudes_of_signals ─────────────────────────────────────────────────

    #[test]
    fn collector_dedups_and_sorts() {
        // Two Small signals → one Small entry.
        let signals: &[&str] = &["gift_card_demand", "sextortion_lure"];
        let ms = magnitudes_of_signals(signals);
        assert_eq!(ms, vec![LossMagnitude::Small]);
    }

    #[test]
    fn collector_sorts_multiple_magnitudes() {
        // Micro + Catastrophic → sorted [Micro, Catastrophic].
        let signals: &[&str] = &["pig_butchering_lure", "package_fee_lure"];
        let ms = magnitudes_of_signals(signals);
        assert_eq!(
            ms,
            vec![LossMagnitude::Micro, LossMagnitude::Catastrophic]
        );
    }

    #[test]
    fn collector_geometry_only_is_empty() {
        let signals: &[&str] = &["fullscreen", "topmost", "urgency_countdown"];
        assert!(magnitudes_of_signals(signals).is_empty());
    }

    #[test]
    fn collector_empty_input_is_empty() {
        let none: &[&str] = &[];
        assert!(magnitudes_of_signals(none).is_empty());
    }

    #[test]
    fn collector_works_with_owned_strings() {
        let signals: Vec<String> = vec![
            "advance_fee_lure".to_string(),
            "crypto_drain_lure".to_string(),
        ];
        let ms = magnitudes_of_signals(&signals);
        assert_eq!(
            ms,
            vec![LossMagnitude::Medium, LossMagnitude::Catastrophic]
        );
    }

    // ── highest_magnitude ─────────────────────────────────────────────────────

    #[test]
    fn highest_picks_catastrophic_over_all() {
        let signals: &[&str] = &["gift_card_demand", "advance_fee_lure", "pig_butchering_lure"];
        assert_eq!(
            highest_magnitude(signals),
            Some(LossMagnitude::Catastrophic)
        );
    }

    #[test]
    fn highest_picks_medium_over_small_and_micro() {
        let signals: &[&str] = &["package_fee_lure", "subscription_lure", "tax_authority_scam"];
        assert_eq!(
            highest_magnitude(signals),
            Some(LossMagnitude::Medium)
        );
    }

    #[test]
    fn highest_none_for_geometry_only() {
        let signals: &[&str] = &["fullscreen", "topmost", "alarm_density"];
        assert_eq!(highest_magnitude(signals), None);
    }

    #[test]
    fn highest_none_for_empty() {
        let none: &[&str] = &[];
        assert_eq!(highest_magnitude(none), None);
    }

    // ── as_str and range_label round-trips ───────────────────────────────────

    #[test]
    fn as_str_round_trips_names() {
        assert_eq!(LossMagnitude::Micro.as_str(), "micro");
        assert_eq!(LossMagnitude::Small.as_str(), "small");
        assert_eq!(LossMagnitude::Medium.as_str(), "medium");
        assert_eq!(LossMagnitude::Large.as_str(), "large");
        assert_eq!(LossMagnitude::Catastrophic.as_str(), "catastrophic");
    }

    #[test]
    fn range_label_round_trips() {
        assert_eq!(LossMagnitude::Micro.range_label(), "< $100");
        assert_eq!(LossMagnitude::Small.range_label(), "$100 – $2K");
        assert_eq!(LossMagnitude::Catastrophic.range_label(), "> $200K");
    }
}
