//! Social-Engineering Kill-Chain stage tags for scam-overlay signals.
//!
//! `muten` already classifies every verdict along four lenses:
//!
//! - [`crate::categories`] (Gray et al. 2018) — **how** the interface deceives.
//! - [`crate::mitre`] (ATT&CK) — **what** technique the adversary uses.
//! - [`crate::persuasion`] (Cialdini 1984) — **why** the human complies.
//! - [`crate::extraction`] (FTC/FBI IC3) — **what** the victim loses / recoverability.
//!
//! All four describe the scam *as a type*. None tells an operator **how far
//! the attacker has progressed** against this particular victim right now.
//! The same scam family (tech-support) looks identical in the first four lenses
//! whether the victim has only seen a fake BSOD (Lure) or is actively reading
//! gift-card codes to a caller (Extract) — yet the required response is
//! completely different.
//!
//! This module adds that fifth, *temporal* lens by mapping each signal to the
//! **Social Engineering Kill Chain stage** it represents. The framework is
//! analogous to Lockheed Martin's Cyber Kill Chain (Hutchins et al. 2011) but
//! adapted to the social-engineering / scam-overlay domain:
//!
//! 1. **Lure** — Initial attention hook: the fake alert, alarm, prize, or
//!    crisis that captures the victim's attention. No extraction demand yet.
//! 2. **TrustBuild** — Authority and identity establishment: brand impersonation,
//!    an official-looking overlay, a displayed phone number. The victim is being
//!    primed to trust the source.
//! 3. **Pressure** — Cognitive override: countdowns, dense alarm language,
//!    "do not close" instructions, and explicit threats that prevent rational
//!    deliberation or consultation.
//! 4. **Extract** — Active value extraction: the overlay is demanding a
//!    concrete transfer — gift card codes, a password, a one-time code,
//!    remote-access consent, a QR scan, or an advance fee. **Most urgent
//!    stage; intervention must be immediate.**
//!
//! The triage primitive is [`highest_stage`]: it returns the most advanced
//! stage present in a set of signals, using the `Extract > Pressure >
//! TrustBuild > Lure` ordering. An operator who sees `highest_stage: extract`
//! knows the victim is being actively asked to transfer value and should act
//! immediately; `highest_stage: lure` signals early-funnel manipulation where
//! education is still the primary intervention.
//!
//! Many signals are pure mechanics (window geometry, homoglyph evasion) with
//! no stage of their own; `stage_of` returns `None` for those, mirroring the
//! other lenses' treatment of geometry signals.
//!
//! Pure classification over already-computed signals: no OS calls, no network,
//! no ML, no new dependencies.
//!
//! Sources: Hutchins, Cloppert & Amin, *"Intelligence-Driven Computer Network
//! Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill
//! Chains"*, LM-2011; FBI IC3 Annual Report 2024 (stage-specific loss data);
//! Cioffi-Revilla, *"On the Kill Chain in Scam and Social Engineering Attacks"*
//! (academic framework); FTC anti-scam guidance (stage-specific response advice).

use serde::Serialize;

/// The stage of the Social Engineering Kill Chain a signal primarily occupies.
///
/// Ordered from **earliest** (`Lure`) to **most advanced** (`Extract`) so that
/// `max()` over a set of stages yields the most advanced stage present —
/// see [`highest_stage`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScamStage {
    /// Initial attention hook — a fake alarm, prize, breach notice, or
    /// crisis that captures the victim's attention. No extraction demand
    /// has been made yet; the attacker is starting the manipulation.
    ///
    /// Response: educational intervention; victim is reachable.
    Lure,
    /// Authority and identity establishment — brand impersonation, an
    /// official-looking overlay, or a displayed support phone number that
    /// primes the victim to trust the source before the ask is made.
    ///
    /// Response: de-legitimise the source; explain brand-impersonation cues.
    TrustBuild,
    /// Cognitive override — countdown timers, dense alarm language,
    /// "do not close" instructions, and explicit threats (arrest, deportation,
    /// exposure) that prevent the victim from thinking clearly or seeking
    /// outside help.
    ///
    /// Response: urgent; interrupt and provide a cooling-off pause.
    Pressure,
    /// Active value extraction — the overlay is demanding a concrete transfer:
    /// gift card codes, credential entry, a one-time/2FA code, remote-access
    /// consent, a QR scan, or an advance fee. The most advanced stage;
    /// intervention must be immediate before value leaves the victim.
    ///
    /// Response: emergency; stop the interaction and, if funds have moved,
    /// race the recall window (see [`crate::extraction::Recoverability`]).
    Extract,
}

impl ScamStage {
    /// Stable snake_case name for logs / SIEM / CLI output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lure => "lure",
            Self::TrustBuild => "trust_build",
            Self::Pressure => "pressure",
            Self::Extract => "extract",
        }
    }
}

/// Map a single signal name to the Social Engineering Kill Chain stage it
/// primarily represents.
///
/// Returns `None` for window-geometry/evasion signals (`fullscreen`,
/// `topmost`, `blocks_input`, `mixed_script`, …) and for delivery-mechanism
/// signals (`cloud_storage_abuse`, `data_uri_page`, `ip_host_url`) — these
/// describe *how* the overlay is deployed or contained, not *where in the
/// social-engineering flow* the victim is.
///
/// Some signals simultaneously occupy multiple stages (a tax-authority scam is
/// both a Lure hook and a Pressure threat), but each returns its **primary**
/// operational stage — the one that most directly determines the correct
/// responder action.
#[must_use]
pub fn stage_of(signal: &str) -> Option<ScamStage> {
    match signal {
        // ── Extract (most urgent — overlay is making an active demand) ──────
        //
        // These signals describe the overlay literally asking for something
        // valuable: codes, credentials, a code to read aloud, device access,
        // or an upfront payment. The victim is at the point-of-no-return.
        "gift_card_demand"              // "buy iTunes cards and read me the codes"
        | "credential_harvest_cue"      // "enter your password / verify your account"
        | "otp_interception_scam"       // "give me your 2FA code"
        | "remote_access_lure"          // "install AnyDesk / TeamViewer"
        | "screen_share_lure"           // "share your screen with our agent"
        | "clickfix_instruction"        // "press Win+R and paste this command"
        | "download_trap_lure"          // "download our security tool to continue"
        | "qr_code_lure"                // "scan this QR code to verify" (quishing)
        | "crypto_drain_lure"           // "connect your wallet / enter seed phrase"
        | "pig_butchering_lure"         // "invest on this platform" (deposit demand)
        | "loan_fee_scam"               // "pay upfront deposit to receive loan"
        | "task_app_scam"               // "pay to unlock your withdrawal"
        | "secret_shopper_scam"         // "deposit check; wire / buy gift cards"
        | "advance_fee_lure"            // "pay processing fee to release your funds"
        | "recovery_scam"               // "pay our recovery fee to get your money back"
        | "charity_scam_lure"           // "donate via gift card / wire / crypto now"
        | "job_scam"                    // "pay registration / equipment deposit to start"
        | "mlm_pyramid_recruitment"     // "pay to join / activate your account"
        | "pet_sale_scam"               // "pay shipping / crate fee before delivery"
        | "rental_scam_lure"            // "pay advance deposit to hold the property"
        | "timeshare_travel_scam"       // "pay activation fee to claim your free vacation"
        | "survey_reward_scam"          // "complete steps to claim; fee gate follows"
        | "false_registration_billing"  // "pay immediately or face legal action" (ワンクリック)
        | "refund_scam_cue"             // "call to get your refund" → extraction call
        | "family_emergency_scam"       // "wire bail / ransom money RIGHT NOW"
        | "tech_support_invoice_scam"   // "call to cancel this charge" → extraction call
        | "wallet_connect_popup_lure"   // connect-wallet approval is the extraction step
        => Some(ScamStage::Extract),

        // ── Pressure (cognitive override — prevent rational deliberation) ────
        //
        // These signals apply urgency, fear, or containment designed to stop
        // the victim from pausing, consulting others, or escaping.
        "urgency_countdown"             // "you have 3:00 before your data is deleted"
        | "alarm_density"               // ≥3 distinct fear-words stacked in the title
        | "forced_retention_cue"        // "DO NOT CLOSE THIS WINDOW"
        | "sextortion_lure"             // "we have your webcam footage — pay or we send it"
        | "utility_cutoff_threat"       // "your electricity is cut off in 30 minutes"
        | "national_id_alarm"           // "your SSN has been suspended due to criminal activity"
        | "immigration_visa_scam"       // "deportation proceedings begin today"
        | "fake_copyright_scam"         // "legal action will commence within 24 hours"
        | "tax_authority_scam"          // "IRS will arrest you unless you pay NOW"
        | "toad_case_number_lure"       // fake case number creates institutional pressure to call
        => Some(ScamStage::Pressure),

        // ── Lure (initial hook — attention and emotional engagement) ─────────
        //
        // These signals present the scam's opening gambit: the alarm, crisis,
        // prize, or opportunity that gets the victim emotionally invested before
        // any specific demand is made. The hook IS the lie that starts the funnel.
        "fake_bsod_lure"                // fake OS crash screen grabs attention
        | "fake_scanner_cue"            // "scanning… 14 threats found!"
        | "ip_alarm_lure"               // "your IP address has been hacked"
        | "prize_lure"                  // "you've been selected — claim your prize"
        | "crypto_giveaway_scam"        // "send 0.1 BTC — receive 0.2 BTC back!"
        | "dark_web_breach_lure"        // "your password was found on the dark web"
        | "package_fee_lure"            // "your package is on hold — pay customs fee"
        | "subscription_lure"           // "your subscription expires today — renew"
        | "bank_account_alarm"          // "fraudulent activity detected on your card"
        | "social_media_account_alarm"  // "your Facebook / Instagram has been suspended"
        | "cloud_quota_lure"            // "your iCloud storage is full — upgrade now"
        | "debt_relief_scam"            // "eliminate 80% of your debt — guaranteed"
        | "student_loan_scam"           // "you qualify for federal loan forgiveness"
        | "veterans_benefit_scam"       // "VA disability claim — file today"
        | "healthcare_scam"             // "your Medicare benefit is expiring"
        | "government_grant_scam"       // "you've been approved for a federal grant"
        | "traffic_fine_scam"           // "unpaid toll — violation notice"
        | "windows_defender_alert_lure" // "Windows Defender found Trojan:Win32/FakeSys"
        | "windows_activation_scam"     // "Windows is not activated — call to activate"
        | "av_brand_renewal_scam"       // "Your McAfee subscription expired 3 days ago"
        | "streaming_billing_scam"      // "Your Netflix payment failed — update card"
        | "software_subscription_scam"  // "Your ChatGPT Plus payment failed"
        | "tech_support_chat_lure"      // "Chat with Microsoft support now" (live-chat hook)
        => Some(ScamStage::Lure),

        // ── TrustBuild (authority / identity establishment) ──────────────────
        //
        // These signals establish false authority or identity: brand spoofing,
        // an official-sounding overlay, or a phone number displayed to convince
        // the victim that "real support" is available. The victim is being
        // primed to trust the source before the demand arrives.
        "brand_impersonation"           // host is a homograph of a known brand
        | "combosquat_brand"            // brand + scam keyword in domain
        | "typosquat_brand"             // edit-distance-1 keyboard typo of brand
        | "authority_lure"              // FBI/police/Interpol/cybercrime impersonation
        | "phone_number"                // a support phone number is displayed
        | "blocklist_phone"             // a KNOWN scam phone number is displayed
        | "fake_browser_security_warning" // fake browser security warning = trust-building via impersonated UI
        => Some(ScamStage::TrustBuild),

        // Window geometry, delivery mechanism, or evasion signals — these
        // describe the overlay's structure or how it was deployed, not its
        // position in the social-engineering kill chain.
        _ => None,
    }
}

/// Collect the distinct kill-chain stages present in a set of signals,
/// sorted (Lure → TrustBuild → Pressure → Extract) and deduplicated for
/// a stable audit representation.
///
/// Accepts any slice whose elements implement `AsRef<str>`, mirroring
/// [`crate::extraction::extraction_vectors_of_signals`].
#[must_use]
pub fn stages_of_signals<S: AsRef<str>>(signals: &[S]) -> Vec<ScamStage> {
    let mut ss: Vec<ScamStage> = signals
        .iter()
        .filter_map(|s| stage_of(s.as_ref()))
        .collect();
    ss.sort_unstable();
    ss.dedup();
    ss
}

/// The most advanced (highest) kill-chain stage present in a set of signals,
/// or `None` when no signal carries a determinate stage.
///
/// This is the triage primitive: `Extract` signals an active demand for value
/// and demands immediate intervention; `Pressure` signals cognitive-override
/// requiring urgent interruption; `TrustBuild` and `Lure` signal earlier
/// stages where education is the primary response. Because [`ScamStage`] is
/// ordered earliest-first, this is simply the maximum.
#[must_use]
pub fn highest_stage<S: AsRef<str>>(signals: &[S]) -> Option<ScamStage> {
    signals.iter().filter_map(|s| stage_of(s.as_ref())).max()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Stage ordering ───────────────────────────────────────────────────────

    #[test]
    fn stage_ordering_is_lure_first() {
        assert!(ScamStage::Lure < ScamStage::TrustBuild);
        assert!(ScamStage::TrustBuild < ScamStage::Pressure);
        assert!(ScamStage::Pressure < ScamStage::Extract);
    }

    // ── stage_of per-stage spot-checks ───────────────────────────────────────

    #[test]
    fn extract_stage_signals() {
        assert_eq!(stage_of("gift_card_demand"), Some(ScamStage::Extract));
        assert_eq!(stage_of("credential_harvest_cue"), Some(ScamStage::Extract));
        assert_eq!(stage_of("otp_interception_scam"), Some(ScamStage::Extract));
        assert_eq!(stage_of("remote_access_lure"), Some(ScamStage::Extract));
        assert_eq!(stage_of("screen_share_lure"), Some(ScamStage::Extract));
        assert_eq!(stage_of("clickfix_instruction"), Some(ScamStage::Extract));
        assert_eq!(stage_of("download_trap_lure"), Some(ScamStage::Extract));
        assert_eq!(stage_of("qr_code_lure"), Some(ScamStage::Extract));
        assert_eq!(stage_of("crypto_drain_lure"), Some(ScamStage::Extract));
        assert_eq!(stage_of("advance_fee_lure"), Some(ScamStage::Extract));
        assert_eq!(stage_of("family_emergency_scam"), Some(ScamStage::Extract));
        assert_eq!(
            stage_of("false_registration_billing"),
            Some(ScamStage::Extract)
        );
        assert_eq!(
            stage_of("tech_support_invoice_scam"),
            Some(ScamStage::Extract)
        );
        assert_eq!(stage_of("wallet_connect_popup_lure"), Some(ScamStage::Extract));
    }

    #[test]
    fn pressure_stage_signals() {
        assert_eq!(stage_of("urgency_countdown"), Some(ScamStage::Pressure));
        assert_eq!(stage_of("alarm_density"), Some(ScamStage::Pressure));
        assert_eq!(stage_of("forced_retention_cue"), Some(ScamStage::Pressure));
        assert_eq!(stage_of("sextortion_lure"), Some(ScamStage::Pressure));
        assert_eq!(stage_of("utility_cutoff_threat"), Some(ScamStage::Pressure));
        assert_eq!(stage_of("national_id_alarm"), Some(ScamStage::Pressure));
        assert_eq!(stage_of("immigration_visa_scam"), Some(ScamStage::Pressure));
        assert_eq!(stage_of("fake_copyright_scam"), Some(ScamStage::Pressure));
        assert_eq!(stage_of("tax_authority_scam"), Some(ScamStage::Pressure));
        assert_eq!(stage_of("toad_case_number_lure"), Some(ScamStage::Pressure));
    }

    #[test]
    fn lure_stage_signals() {
        assert_eq!(stage_of("fake_bsod_lure"), Some(ScamStage::Lure));
        assert_eq!(stage_of("fake_scanner_cue"), Some(ScamStage::Lure));
        assert_eq!(stage_of("prize_lure"), Some(ScamStage::Lure));
        assert_eq!(stage_of("dark_web_breach_lure"), Some(ScamStage::Lure));
        assert_eq!(stage_of("bank_account_alarm"), Some(ScamStage::Lure));
        assert_eq!(stage_of("cloud_quota_lure"), Some(ScamStage::Lure));
        assert_eq!(
            stage_of("windows_defender_alert_lure"),
            Some(ScamStage::Lure)
        );
        assert_eq!(
            stage_of("software_subscription_scam"),
            Some(ScamStage::Lure)
        );
        assert_eq!(stage_of("tech_support_chat_lure"), Some(ScamStage::Lure));
    }

    #[test]
    fn trust_build_stage_signals() {
        assert_eq!(stage_of("brand_impersonation"), Some(ScamStage::TrustBuild));
        assert_eq!(stage_of("combosquat_brand"), Some(ScamStage::TrustBuild));
        assert_eq!(stage_of("typosquat_brand"), Some(ScamStage::TrustBuild));
        assert_eq!(stage_of("authority_lure"), Some(ScamStage::TrustBuild));
        assert_eq!(stage_of("phone_number"), Some(ScamStage::TrustBuild));
        assert_eq!(stage_of("blocklist_phone"), Some(ScamStage::TrustBuild));
    }

    // ── Geometry / mechanic signals have no stage ────────────────────────────

    #[test]
    fn geometry_signals_have_no_stage() {
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
            "whole_script_confusable",
            "compat_chars_present",
            "bidi_override",
            "mixed_number_systems",
            "excessive_combining_marks",
            "blocklist_title",
            "blocklist_host",
            "cloud_storage_abuse",
            "url_path_lure",
            "data_uri_page",
            "ip_host_url",
        ] {
            assert!(
                stage_of(s).is_none(),
                "{s} should carry no kill-chain stage"
            );
        }
    }

    #[test]
    fn unknown_signal_has_no_stage() {
        assert!(stage_of("not_a_real_signal").is_none());
    }

    // ── stages_of_signals ────────────────────────────────────────────────────

    #[test]
    fn collector_dedups_and_sorts() {
        // Two Extract signals → one Extract entry.
        let signals: &[&str] = &["gift_card_demand", "credential_harvest_cue"];
        let ss = stages_of_signals(signals);
        assert_eq!(ss, vec![ScamStage::Extract]);
    }

    #[test]
    fn collector_sorts_multiple_stages() {
        // Lure + Extract → sorted [Lure, Extract].
        let signals: &[&str] = &["fake_bsod_lure", "gift_card_demand"];
        let ss = stages_of_signals(signals);
        assert_eq!(ss, vec![ScamStage::Lure, ScamStage::Extract]);
    }

    #[test]
    fn collector_all_stages_present() {
        let signals: &[&str] = &[
            "gift_card_demand",  // Extract
            "urgency_countdown", // Pressure
            "phone_number",      // TrustBuild
            "fake_bsod_lure",    // Lure
        ];
        let ss = stages_of_signals(signals);
        assert_eq!(
            ss,
            vec![
                ScamStage::Lure,
                ScamStage::TrustBuild,
                ScamStage::Pressure,
                ScamStage::Extract
            ]
        );
    }

    #[test]
    fn collector_geometry_only_gives_empty() {
        let signals: &[&str] = &["fullscreen", "topmost", "blocks_input"];
        assert!(stages_of_signals(signals).is_empty());
    }

    #[test]
    fn collector_empty_input() {
        let none: &[&str] = &[];
        assert!(stages_of_signals(none).is_empty());
    }

    #[test]
    fn collector_works_with_owned_strings() {
        let signals: Vec<String> =
            vec!["phone_number".to_string(), "urgency_countdown".to_string()];
        let ss = stages_of_signals(&signals);
        assert_eq!(ss, vec![ScamStage::TrustBuild, ScamStage::Pressure]);
    }

    // ── highest_stage ────────────────────────────────────────────────────────

    #[test]
    fn highest_stage_picks_extract_over_all() {
        // Even with Lure and Pressure signals, Extract wins.
        let signals: &[&str] = &["fake_bsod_lure", "alarm_density", "gift_card_demand"];
        assert_eq!(highest_stage(signals), Some(ScamStage::Extract));
    }

    #[test]
    fn highest_stage_pressure_beats_lure_and_trust() {
        let signals: &[&str] = &["fake_bsod_lure", "phone_number", "urgency_countdown"];
        assert_eq!(highest_stage(signals), Some(ScamStage::Pressure));
    }

    #[test]
    fn highest_stage_trust_beats_lure() {
        let signals: &[&str] = &["fake_bsod_lure", "brand_impersonation"];
        assert_eq!(highest_stage(signals), Some(ScamStage::TrustBuild));
    }

    #[test]
    fn highest_stage_none_when_geometry_only() {
        let signals: &[&str] = &["fullscreen", "topmost", "blocks_input"];
        assert_eq!(highest_stage(signals), None);
    }

    #[test]
    fn highest_stage_none_on_empty() {
        let none: &[&str] = &[];
        assert_eq!(highest_stage(none), None);
    }

    // ── as_str round-trip ────────────────────────────────────────────────────

    #[test]
    fn as_str_round_trips_names() {
        assert_eq!(ScamStage::Lure.as_str(), "lure");
        assert_eq!(ScamStage::TrustBuild.as_str(), "trust_build");
        assert_eq!(ScamStage::Pressure.as_str(), "pressure");
        assert_eq!(ScamStage::Extract.as_str(), "extract");
    }
}
