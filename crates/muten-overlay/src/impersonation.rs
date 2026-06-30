//! Abused-authority (impersonation-target) tags for scam-overlay signals.
//!
//! `muten` already classifies every verdict along several lenses — how the
//! interface deceives ([`crate::categories`]), what technique the adversary
//! uses ([`crate::mitre`]), why the human complies ([`crate::persuasion`]),
//! what the victim loses ([`crate::extraction`]), how far the attack has
//! progressed ([`crate::lifecycle`]), **who** is targeted
//! ([`crate::targeting`]), how much is at stake ([`crate::magnitude`]), which
//! campaign template it is ([`crate::fingerprint`]), and how urgently to
//! respond ([`crate::triage`]).
//!
//! None of those answers the question a **brand-protection or takedown team**
//! asks: *whose trust is being abused?* A scam that impersonates Microsoft
//! support, the IRS, a bank fraud department, and a shipping courier may share
//! identical mechanics, persuasion, and extraction — yet each abuses a
//! **different** institution's reputation, and each routes to a different
//! takedown contact, brand-protection owner, and customer-warning channel.
//!
//! This module adds that lens by mapping each content signal to the *type of
//! trusted institution* the scam impersonates ([`AbusedAuthority`]). It is the
//! mirror image of [`crate::targeting`]: targeting answers *who is the victim*,
//! this answers *who is being impersonated*.
//!
//! ## Deliberately a subset
//!
//! Unlike the targeting / magnitude / lifecycle lenses (which map *every*
//! scam-family content signal), this lens maps **only** signals whose scam
//! family impersonates a specific, identifiable *category of trusted
//! institution*. Pure *opportunity* and *threat* lures — fake prizes, job
//! offers, crypto giveaways, romance/investment (pig-butchering), sextortion,
//! rentals, pet sales, advance-fee windfalls — invent an offer or a threat
//! rather than wearing a real institution's identity, so they return `None`.
//! That distinction is the point: the presence of an `AbusedAuthority` is
//! precisely the signal a brand-protection team filters on.
//!
//! Pure classification over already-computed signals: no OS calls, no network,
//! no ML, no new dependencies.
//!
//! Sources: FTC Consumer Sentinel 2024 (impersonation scam taxonomy: business,
//! government, tech-support); FBI IC3 2024 (tech-support fraud; government
//! impersonation); APWG Phishing Activity Trends 2024 (most-impersonated
//! brands: financial, webmail/social, e-commerce, logistics); CISA / Microsoft
//! / Apple tech-support-scam advisories.

use serde::Serialize;

/// The category of trusted institution a scam signal impersonates.
///
/// Ordered alphabetically by variant for stable audit output. Use
/// [`impersonates_authority`] to test whether a verdict wears any institution's
/// identity at all — the gate a brand-protection workflow filters on.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbusedAuthority {
    /// Disaster-relief and humanitarian charities — fake donation appeals
    /// impersonating well-known relief organizations.
    Charity,
    /// Banks, card issuers, and payment processors — fake fraud alerts,
    /// account-freeze notices, and lender/debt-relief impersonation.
    FinancialInstitution,
    /// Government agencies — tax authorities, law enforcement, courts,
    /// immigration, national-ID offices, benefit programs, and grant bodies.
    Government,
    /// Healthcare payers and insurers — Medicare / Medicaid / private
    /// insurance benefit-expiry and free-device lures.
    Healthcare,
    /// Couriers, postal services, and customs — fake "package on hold,
    /// pay a release/customs fee" delivery notices.
    Logistics,
    /// Retail, e-commerce, and subscription/streaming brands — fake
    /// billing-problem and subscription-expiry payment-credential phishing.
    Retailer,
    /// Social-media platforms and webmail providers — fake account-hacked /
    /// account-suspended recovery flows.
    SocialPlatform,
    /// OS, software, and antivirus vendors (Microsoft, Apple, McAfee, Norton,
    /// …) — the tech-support-scam family: fake BSODs, AV-expiry alarms,
    /// activation lures, and "call support" overlays.
    TechVendor,
    /// Utilities — electric, gas, water, and telecom providers — fake
    /// disconnection-threat "pay now or service is cut" notices.
    Utility,
}

impl AbusedAuthority {
    /// Stable snake_case name for logs / SIEM / CLI output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Charity => "charity",
            Self::FinancialInstitution => "financial_institution",
            Self::Government => "government",
            Self::Healthcare => "healthcare",
            Self::Logistics => "logistics",
            Self::Retailer => "retailer",
            Self::SocialPlatform => "social_platform",
            Self::TechVendor => "tech_vendor",
            Self::Utility => "utility",
        }
    }
}

/// Map a single signal name to the institution category it impersonates, or
/// `None` when the scam family invents an offer/threat rather than wearing a
/// real institution's identity (and for all geometry / evasion / mechanic
/// signals).
///
/// See the module docs for why this is deliberately a *subset* of content
/// signals: the presence of a mapping is itself the brand-protection signal.
#[must_use]
pub fn abused_authority_of(signal: &str) -> Option<AbusedAuthority> {
    match signal {
        // ── TechVendor ───────────────────────────────────────────────────────
        // The tech-support-scam family: every one wears Microsoft / Apple /
        // a named antivirus brand's identity to drive a "call support" action.
        "fake_bsod_lure"                // fake Windows BSOD / kernel panic
        | "fake_scanner_cue"            // fake AV scan "threats found"
        | "ip_alarm_lure"               // "your IP has been hacked" — TSS staple
        | "windows_defender_alert_lure" // Microsoft Defender brand abuse
        | "windows_activation_scam"     // fake Windows/Office activation
        | "av_brand_renewal_scam"       // McAfee/Norton/Avast expiry
        | "tech_support_invoice_scam"   // fake support-plan/AV invoice
        | "tech_support_chat_lure"      // live-chat "support agent" pivot
        | "software_subscription_scam"  // SaaS/AI-tool billing impersonation
        | "fake_browser_security_warning"  // impersonates browser vendor (Chrome/Firefox/Edge/Safari) security UI
        => Some(AbusedAuthority::TechVendor),

        // ── Government ─────────────────────────────────────────────────────────
        // Tax, law-enforcement, courts, immigration, national-ID, veteran and
        // student-loan benefit programs, and grant bodies.
        "tax_authority_scam"            // IRS / HMRC / 国税庁
        | "national_id_alarm"           // SSN / NIN / マイナンバー suspension
        | "immigration_visa_scam"       // visa revocation / deportation threat
        | "authority_lure"              // FBI / police / interpol bluff
        | "traffic_fine_scam"           // toll / parking enforcement
        | "government_grant_scam"       // fake federal grant / stimulus
        | "fake_copyright_scam"         // DMCA / legal-authority threat
        | "veterans_benefit_scam"       // VA benefit-claim impersonation
        | "student_loan_scam"           // Dept. of Education forgiveness program
        => Some(AbusedAuthority::Government),

        // ── FinancialInstitution ──────────────────────────────────────────────
        // Banks, card issuers, lenders, and debt/credit services.
        "bank_account_alarm"            // fake bank fraud-department alert
        | "loan_fee_scam"               // fake pre-approved lender
        | "debt_relief_scam"            // fake debt-relief / credit-repair firm
        => Some(AbusedAuthority::FinancialInstitution),

        // ── Healthcare ─────────────────────────────────────────────────────────
        "healthcare_scam"               // Medicare / Medicaid / insurer
        => Some(AbusedAuthority::Healthcare),

        // ── Utility ────────────────────────────────────────────────────────────
        "utility_cutoff_threat"         // electric/gas/water disconnection bluff
        => Some(AbusedAuthority::Utility),

        // ── Logistics ──────────────────────────────────────────────────────────
        "package_fee_lure"              // courier/customs "release fee" notice
        => Some(AbusedAuthority::Logistics),

        // ── Retailer ───────────────────────────────────────────────────────────
        "streaming_billing_scam"        // Netflix/Spotify/Prime billing problem
        | "subscription_lure"           // generic subscription-expiry renewal
        => Some(AbusedAuthority::Retailer),

        // ── SocialPlatform ─────────────────────────────────────────────────────
        "social_media_account_alarm"    // Facebook/Instagram/Gmail/LINE recovery
        => Some(AbusedAuthority::SocialPlatform),

        // ── Charity ────────────────────────────────────────────────────────────
        "charity_scam_lure"             // disaster-relief / humanitarian appeal
        => Some(AbusedAuthority::Charity),

        // ── No impersonation ──────────────────────────────────────────────────
        // Opportunity / threat lures (prize, job, crypto giveaway, pig-
        // butchering, sextortion, rental, pet sale, advance fee, survey,
        // secret shopper, recovery, task app, MLM, timeshare, family emergency,
        // dark-web breach, cloud quota), generic credential/OTP mechanics,
        // domain-evasion tells, coercion mechanics, and window geometry: these
        // invent an offer/threat or describe structure rather than wearing a
        // named institution's identity.
        _ => None,
    }
}

/// All distinct institution categories impersonated by a signal set,
/// deduplicated and sorted. Empty when no signal impersonates a known
/// institution category.
#[must_use]
pub fn abused_authorities_of_signals<S: AsRef<str>>(signals: &[S]) -> Vec<AbusedAuthority> {
    let mut out: Vec<AbusedAuthority> = signals
        .iter()
        .filter_map(|s| abused_authority_of(s.as_ref()))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Returns `true` when at least one signal impersonates a known institution
/// category — the gate a brand-protection / takedown workflow filters on.
#[must_use]
pub fn impersonates_authority<S: AsRef<str>>(signals: &[S]) -> bool {
    signals
        .iter()
        .any(|s| abused_authority_of(s.as_ref()).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tech_vendor_family() {
        for sig in [
            "fake_bsod_lure",
            "fake_scanner_cue",
            "ip_alarm_lure",
            "windows_defender_alert_lure",
            "windows_activation_scam",
            "av_brand_renewal_scam",
            "tech_support_invoice_scam",
            "tech_support_chat_lure",
            "software_subscription_scam",
            "fake_browser_security_warning",
        ] {
            assert_eq!(
                abused_authority_of(sig),
                Some(AbusedAuthority::TechVendor),
                "{sig} should map to TechVendor"
            );
        }
    }

    #[test]
    fn government_family() {
        for sig in [
            "tax_authority_scam",
            "national_id_alarm",
            "immigration_visa_scam",
            "authority_lure",
            "traffic_fine_scam",
            "government_grant_scam",
            "fake_copyright_scam",
            "veterans_benefit_scam",
            "student_loan_scam",
        ] {
            assert_eq!(
                abused_authority_of(sig),
                Some(AbusedAuthority::Government),
                "{sig} should map to Government"
            );
        }
    }

    #[test]
    fn financial_family() {
        for sig in ["bank_account_alarm", "loan_fee_scam", "debt_relief_scam"] {
            assert_eq!(
                abused_authority_of(sig),
                Some(AbusedAuthority::FinancialInstitution),
                "{sig} should map to FinancialInstitution"
            );
        }
    }

    #[test]
    fn singleton_categories() {
        assert_eq!(
            abused_authority_of("healthcare_scam"),
            Some(AbusedAuthority::Healthcare)
        );
        assert_eq!(
            abused_authority_of("utility_cutoff_threat"),
            Some(AbusedAuthority::Utility)
        );
        assert_eq!(
            abused_authority_of("package_fee_lure"),
            Some(AbusedAuthority::Logistics)
        );
        assert_eq!(
            abused_authority_of("social_media_account_alarm"),
            Some(AbusedAuthority::SocialPlatform)
        );
        assert_eq!(
            abused_authority_of("charity_scam_lure"),
            Some(AbusedAuthority::Charity)
        );
    }

    #[test]
    fn retailer_family() {
        assert_eq!(
            abused_authority_of("streaming_billing_scam"),
            Some(AbusedAuthority::Retailer)
        );
        assert_eq!(
            abused_authority_of("subscription_lure"),
            Some(AbusedAuthority::Retailer)
        );
    }

    #[test]
    fn opportunity_and_threat_lures_do_not_impersonate() {
        // These invent an offer/threat rather than wearing an institution's
        // identity — they must return None.
        for sig in [
            "prize_lure",
            "job_scam",
            "task_app_scam",
            "secret_shopper_scam",
            "mlm_pyramid_recruitment",
            "crypto_giveaway_scam",
            "crypto_drain_lure",
            "pig_butchering_lure",
            "sextortion_lure",
            "rental_scam_lure",
            "pet_sale_scam",
            "advance_fee_lure",
            "survey_reward_scam",
            "recovery_scam",
            "timeshare_travel_scam",
            "family_emergency_scam",
            "dark_web_breach_lure",
            "cloud_quota_lure",
        ] {
            assert_eq!(
                abused_authority_of(sig),
                None,
                "{sig} should NOT map to an impersonated institution"
            );
        }
    }

    #[test]
    fn geometry_and_mechanic_signals_are_none() {
        for sig in [
            "fullscreen",
            "topmost",
            "no_close_button",
            "blocks_input",
            "unsolicited",
            "mixed_script",
            "gift_card_demand",
            "qr_code_lure",
            "urgency_countdown",
            "alarm_density",
            "credential_harvest_cue",
            "otp_interception_scam",
        ] {
            assert_eq!(abused_authority_of(sig), None, "{sig} should be None");
        }
    }

    #[test]
    fn collector_dedups_and_sorts() {
        // Two TechVendor + one Government + one None → [Government, TechVendor].
        let signals: &[&str] = &[
            "fake_bsod_lure",
            "av_brand_renewal_scam",
            "tax_authority_scam",
            "gift_card_demand",
        ];
        let got = abused_authorities_of_signals(signals);
        assert_eq!(
            got,
            vec![AbusedAuthority::Government, AbusedAuthority::TechVendor]
        );
    }

    #[test]
    fn empty_when_no_impersonation() {
        let signals: &[&str] = &["fullscreen", "topmost", "prize_lure", "sextortion_lure"];
        assert!(abused_authorities_of_signals(signals).is_empty());
        assert!(!impersonates_authority(signals));
    }

    #[test]
    fn impersonates_authority_gate() {
        assert!(impersonates_authority(&[
            "fullscreen",
            "bank_account_alarm"
        ]));
        assert!(!impersonates_authority(&["fullscreen", "prize_lure"]));
    }

    #[test]
    fn as_str_is_stable() {
        assert_eq!(AbusedAuthority::TechVendor.as_str(), "tech_vendor");
        assert_eq!(
            AbusedAuthority::FinancialInstitution.as_str(),
            "financial_institution"
        );
        assert_eq!(AbusedAuthority::Government.as_str(), "government");
        assert_eq!(AbusedAuthority::SocialPlatform.as_str(), "social_platform");
    }
}
