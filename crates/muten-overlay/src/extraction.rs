//! Extraction-vector and loss-recoverability tags for scam-overlay signals.
//!
//! `muten` already classifies every verdict along three *attacker-side*
//! lenses that describe the deception:
//!
//! - [`crate::categories`] (Gray et al. 2018) — **how** the interface
//!   manipulates (Obstruction, Sneaking, …).
//! - [`crate::mitre`] (ATT&CK) — **what** technique the adversary uses
//!   (T1566 Phishing, T1656 Impersonation, …).
//! - [`crate::persuasion`] (Cialdini 1984) — **why** the human complies
//!   (Authority, Scarcity, Intimidation, …).
//!
//! All three describe the manipulation. None answers the question a victim
//! or first responder asks in the first minute *after* the lure works:
//! **"what did I just lose, and can I get it back?"** This module adds that
//! fourth, *defender-side* lens by mapping each signal to the **extraction
//! vector** — the mechanism by which value leaves the victim — and deriving
//! the **recoverability** of that loss, which sets response urgency.
//!
//! Recoverability is the operational payoff. The right action differs
//! sharply by channel, and the literature is unambiguous on the ordering:
//!
//! - **Gift cards & cryptocurrency** — irreversible once sent; the FTC and
//!   FBI IC3 both name these as the channels with effectively no recovery.
//!   Response is prevention/education, not clawback.
//! - **Wire / money transfer** — a short recall window (hours) exists; the
//!   FBI IC3 Recovery Asset Team's entire premise is racing that window.
//! - **Card charge** — disputable via chargeback for weeks to months
//!   (Fair Credit Billing Act / card-network rules).
//! - **Credential or device compromise** — no money has necessarily moved
//!   yet; the loss is *mitigable* by rotating credentials, revoking
//!   sessions, and scanning — but the account-takeover risk is ongoing.
//!
//! A signal may map to more than one vector (a sextortion lure is paid in
//! crypto *or* gift cards), so the mapping returns a slice, exactly like
//! [`crate::mitre::techniques_of`]. Pure classification over already-
//! computed signals: no OS calls, no network, no ML, no new dependencies.
//!
//! Sources: FTC Consumer Sentinel Network Data Book (annual
//! payment-method-of-fraud breakdowns); FBI IC3 Annual Report (Recovery
//! Asset Team wire-recall statistics; cryptocurrency and gift-card loss
//! irreversibility); CISA / consumer-protection chargeback guidance.

use serde::Serialize;

/// How recoverable a loss via a given [`ExtractionVector`] typically is.
///
/// Ordered from **least** recoverable (`Irreversible`) to **most**
/// (`Mitigable`) so that `min()` over a set yields the worst case for
/// triage — see [`worst_recoverability`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Recoverability {
    /// Effectively unrecoverable once sent (gift cards, cryptocurrency).
    /// Response is prevention, not clawback.
    Irreversible,
    /// A short recall window exists (bank wire / money transfer); recovery
    /// means racing that window — escalate immediately.
    TimeLimited,
    /// Disputable after the fact (card charge / chargeback) over weeks.
    Disputable,
    /// No funds necessarily moved; mitigate by rotating credentials,
    /// revoking sessions, and scanning the device. Ongoing-risk, not loss.
    Mitigable,
}

impl Recoverability {
    /// Stable snake_case name for logs / SIEM / CLI output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Irreversible => "irreversible",
            Self::TimeLimited => "time_limited",
            Self::Disputable => "disputable",
            Self::Mitigable => "mitigable",
        }
    }
}

/// The mechanism by which a scam extracts value from its victim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionVector {
    /// Gift-card / voucher code paid to the attacker. Irreversible.
    GiftCard,
    /// Cryptocurrency transfer or wallet drain. Irreversible.
    Cryptocurrency,
    /// Bank wire / money-transfer service. Short recall window.
    WireTransfer,
    /// Credit/debit card charge or fraudulent subscription. Disputable.
    CardCharge,
    /// Login credentials / one-time codes / identity data harvested for
    /// account takeover. Mitigable (rotate & revoke).
    CredentialHarvest,
    /// Remote-access or malware foothold on the device. Mitigable
    /// (disconnect, scan, rotate), but ongoing risk until cleaned.
    DeviceTakeover,
}

impl ExtractionVector {
    /// Stable snake_case name for logs / SIEM / CLI output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GiftCard => "gift_card",
            Self::Cryptocurrency => "cryptocurrency",
            Self::WireTransfer => "wire_transfer",
            Self::CardCharge => "card_charge",
            Self::CredentialHarvest => "credential_harvest",
            Self::DeviceTakeover => "device_takeover",
        }
    }

    /// The typical recoverability of a loss through this vector.
    #[must_use]
    pub fn recoverability(self) -> Recoverability {
        match self {
            Self::GiftCard | Self::Cryptocurrency => Recoverability::Irreversible,
            Self::WireTransfer => Recoverability::TimeLimited,
            Self::CardCharge => Recoverability::Disputable,
            Self::CredentialHarvest | Self::DeviceTakeover => Recoverability::Mitigable,
        }
    }
}

use ExtractionVector::{
    CardCharge, CredentialHarvest, Cryptocurrency, DeviceTakeover, GiftCard, WireTransfer,
};

/// Map a single signal name to the extraction vector(s) it characteristically
/// uses to monetize the victim.
///
/// Returns an empty slice for signals that are pure *lures* or window
/// mechanics with no determinate cash-out channel of their own — a countdown
/// timer, a homoglyph domain, a fake-scan alarm, a phone number (the phone is
/// a contact channel; the specific scam-type signal that fires alongside it
/// carries the vector). The specific scam-family signals supply the vector.
///
/// Many signals map to more than one vector (the combination is the useful
/// part), so the return is a slice.
#[must_use]
pub fn extraction_vectors_of(signal: &str) -> &'static [ExtractionVector] {
    match signal {
        // ── Gift card ────────────────────────────────────────────────────
        "gift_card_demand" => &[GiftCard],

        // ── Cryptocurrency (irreversible) ────────────────────────────────
        "crypto_drain_lure" | "crypto_giveaway_scam" | "pig_butchering_lure" => &[Cryptocurrency],
        // Sextortion is paid overwhelmingly in crypto, occasionally gift cards.
        "sextortion_lure" => &[Cryptocurrency, GiftCard],
        // Recovery scams (secondary victimization) extract a fresh advance
        // fee, typically in crypto or by wire.
        "recovery_scam" => &[Cryptocurrency, WireTransfer],

        // ── Wire / money transfer (short recall window) ──────────────────
        "advance_fee_lure"
        | "loan_fee_scam"
        | "rental_scam_lure"
        | "pet_sale_scam"
        | "timeshare_travel_scam"
        | "charity_scam_lure"
        | "family_emergency_scam"
        | "package_fee_lure"
        | "task_app_scam"
        | "secret_shopper_scam"
        | "job_scam"
        | "mlm_pyramid_recruitment"
        | "prize_lure"
        | "survey_reward_scam"
        | "government_grant_scam"
        | "debt_relief_scam"
        | "student_loan_scam"
        | "veterans_benefit_scam" => &[WireTransfer],

        // ── Card charge (disputable via chargeback) ──────────────────────
        "subscription_lure"
        | "streaming_billing_scam"
        | "software_subscription_scam"
        | "av_brand_renewal_scam"
        | "windows_activation_scam"
        | "tech_support_invoice_scam"
        | "false_registration_billing"
        | "cloud_quota_lure"
        | "healthcare_scam"
        | "traffic_fine_scam"
        | "utility_cutoff_threat"
        | "refund_scam_cue" => &[CardCharge],
        // Tax-authority scams demand payment by gift card or wire ("pay your
        // tax debt in iTunes cards or face arrest").
        "tax_authority_scam" => &[GiftCard, WireTransfer],

        // ── Credential harvest (account-takeover, mitigable) ─────────────
        "credential_harvest_cue"
        | "otp_interception_scam"
        | "social_media_account_alarm"
        | "bank_account_alarm"
        | "dark_web_breach_lure"
        | "national_id_alarm"
        | "immigration_visa_scam"
        | "brand_impersonation"
        | "combosquat_brand"
        | "typosquat_brand"
        | "url_path_lure" => &[CredentialHarvest],

        // ── Device takeover (remote access / malware, mitigable) ─────────
        "remote_access_lure"
        | "screen_share_lure"
        | "clickfix_instruction"
        | "download_trap_lure"
        | "fake_bsod_lure"
        | "fake_scanner_cue"
        | "windows_defender_alert_lure"
        | "rogue_av_process"
        | "tech_support_chat_lure" => &[DeviceTakeover],

        // Pure lures / scare / geometry / homoglyph mechanics with no
        // determinate cash-out channel of their own.
        _ => &[],
    }
}

/// Collect the distinct extraction vectors present in a set of signals,
/// sorted and deduplicated for a stable audit representation.
///
/// Accepts any slice whose elements implement `AsRef<str>`, mirroring
/// [`crate::persuasion::principles_of_signals`].
#[must_use]
pub fn extraction_vectors_of_signals<S: AsRef<str>>(signals: &[S]) -> Vec<ExtractionVector> {
    let mut vs: Vec<ExtractionVector> = signals
        .iter()
        .flat_map(|s| extraction_vectors_of(s.as_ref()))
        .copied()
        .collect();
    vs.sort_unstable();
    vs.dedup();
    vs
}

/// The worst-case (least recoverable) recoverability across a set of signals,
/// or `None` when no signal carries a determinate extraction vector.
///
/// This is the triage primitive: a verdict that can be monetized through any
/// irreversible channel should be treated with that urgency even if it also
/// has a disputable one. Because [`Recoverability`] is ordered worst-first,
/// this is simply the minimum.
#[must_use]
pub fn worst_recoverability<S: AsRef<str>>(signals: &[S]) -> Option<Recoverability> {
    signals
        .iter()
        .flat_map(|s| extraction_vectors_of(s.as_ref()))
        .map(|v| v.recoverability())
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gift_card_and_crypto_are_irreversible() {
        assert_eq!(extraction_vectors_of("gift_card_demand"), &[GiftCard]);
        assert_eq!(GiftCard.recoverability(), Recoverability::Irreversible);
        assert_eq!(
            extraction_vectors_of("crypto_drain_lure"),
            &[Cryptocurrency]
        );
        assert_eq!(
            Cryptocurrency.recoverability(),
            Recoverability::Irreversible
        );
    }

    #[test]
    fn wire_is_time_limited() {
        assert_eq!(extraction_vectors_of("advance_fee_lure"), &[WireTransfer]);
        assert_eq!(WireTransfer.recoverability(), Recoverability::TimeLimited);
    }

    #[test]
    fn card_charge_is_disputable() {
        assert_eq!(
            extraction_vectors_of("software_subscription_scam"),
            &[CardCharge]
        );
        assert_eq!(CardCharge.recoverability(), Recoverability::Disputable);
    }

    #[test]
    fn credential_and_device_are_mitigable() {
        assert_eq!(
            extraction_vectors_of("credential_harvest_cue"),
            &[CredentialHarvest]
        );
        assert_eq!(
            CredentialHarvest.recoverability(),
            Recoverability::Mitigable
        );
        assert_eq!(
            extraction_vectors_of("remote_access_lure"),
            &[DeviceTakeover]
        );
        assert_eq!(DeviceTakeover.recoverability(), Recoverability::Mitigable);
    }

    #[test]
    fn multi_vector_signals_return_both() {
        assert_eq!(
            extraction_vectors_of("sextortion_lure"),
            &[Cryptocurrency, GiftCard]
        );
        assert_eq!(
            extraction_vectors_of("tax_authority_scam"),
            &[GiftCard, WireTransfer]
        );
    }

    #[test]
    fn pure_lure_and_geometry_signals_have_no_vector() {
        for s in [
            "urgency_countdown",
            "alarm_density",
            "ip_alarm_lure",
            "phone_number",
            "fullscreen",
            "topmost",
            "blocks_input",
            "mixed_script",
        ] {
            assert!(
                extraction_vectors_of(s).is_empty(),
                "{s} should carry no determinate extraction vector"
            );
        }
    }

    #[test]
    fn unknown_signal_has_no_vector() {
        assert!(extraction_vectors_of("not_a_real_signal").is_empty());
    }

    #[test]
    fn collector_dedups_and_sorts() {
        // gift_card_demand → GiftCard, sextortion_lure → Crypto+GiftCard.
        let signals: &[&str] = &["gift_card_demand", "sextortion_lure"];
        let vs = extraction_vectors_of_signals(signals);
        assert_eq!(vs, vec![GiftCard, Cryptocurrency]);
    }

    #[test]
    fn collector_empty_input() {
        let none: &[&str] = &[];
        assert!(extraction_vectors_of_signals(none).is_empty());
    }

    #[test]
    fn collector_works_with_owned_strings() {
        let signals: Vec<String> = vec![
            "advance_fee_lure".to_string(),
            "software_subscription_scam".to_string(),
        ];
        let vs = extraction_vectors_of_signals(&signals);
        assert_eq!(vs, vec![WireTransfer, CardCharge]);
    }

    #[test]
    fn worst_recoverability_picks_least_recoverable() {
        // Card (Disputable) + gift card (Irreversible) → Irreversible wins.
        let signals: &[&str] = &["software_subscription_scam", "gift_card_demand"];
        assert_eq!(
            worst_recoverability(signals),
            Some(Recoverability::Irreversible)
        );
    }

    #[test]
    fn worst_recoverability_credential_only_is_mitigable() {
        let signals: &[&str] = &["credential_harvest_cue", "otp_interception_scam"];
        assert_eq!(
            worst_recoverability(signals),
            Some(Recoverability::Mitigable)
        );
    }

    #[test]
    fn worst_recoverability_none_when_no_vector() {
        let signals: &[&str] = &["urgency_countdown", "fullscreen"];
        assert_eq!(worst_recoverability(signals), None);
    }

    #[test]
    fn recoverability_ordering_is_worst_first() {
        assert!(Recoverability::Irreversible < Recoverability::TimeLimited);
        assert!(Recoverability::TimeLimited < Recoverability::Disputable);
        assert!(Recoverability::Disputable < Recoverability::Mitigable);
    }

    #[test]
    fn as_str_round_trips_names() {
        assert_eq!(GiftCard.as_str(), "gift_card");
        assert_eq!(WireTransfer.as_str(), "wire_transfer");
        assert_eq!(CredentialHarvest.as_str(), "credential_harvest");
        assert_eq!(Recoverability::Irreversible.as_str(), "irreversible");
        assert_eq!(Recoverability::TimeLimited.as_str(), "time_limited");
    }
}
