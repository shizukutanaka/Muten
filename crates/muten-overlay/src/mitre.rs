//! MITRE ATT&CK® for Enterprise technique tags for scam-overlay signals.
//!
//! Each built-in signal maps to one or more stable ATT&CK technique IDs
//! (MITRE ATT&CK for Enterprise v16, <https://attack.mitre.org/>).
//! The IDs appear in `Verdict.mitre_techniques` so a SIEM can correlate
//! muten events with ATT&CK-tagged detection rules and regulatory reports
//! (NIST SP 800-61, CISA advisories) that reference the same taxonomy.
//!
//! Purely classification over already-computed signals — no new OS calls,
//! no network, no dependencies.

/// Map a single signal name to the MITRE ATT&CK technique IDs it represents.
/// Returns an empty slice for descriptive-only signals (fullscreen, topmost,
/// …) that have no ATT&CK mapping of their own.
///
/// Technique justifications (ATT&CK for Enterprise v16):
/// - **T1566 Phishing** — deceptive lures using social engineering:
///   a fake-alert phone number, a curated scam number, or a blocklisted
///   alert title is the archetypal phishing hook in tech-support scams.
/// - **T1656 Impersonation** — adversary impersonates a trusted entity
///   (fake-antivirus brand, authority-brand combosquat/homograph domain).
/// - **T1036 Masquerading** — adversary disguises identity/text using
///   homoglyphs, mixed-script tokens, BiDi overrides, or combining-mark
///   stacks to make a window or domain appear legitimate.
/// - **T1204 User Execution** — adversary tricks the user into running
///   attacker-supplied code; ClickFix / fake-CAPTCHA Run-dialog lures
///   are the canonical 2025–2026 instance of this technique.
/// - **T1219 Remote Access Software** — adversary lures the victim into
///   installing legitimate remote-access tooling (AnyDesk, TeamViewer…)
///   to seize the machine (FBI IC3 2024 tech-support scam pattern).
/// - **T1056 Input Capture** — adversary seizes all keyboard/pointer
///   input via a modal window or browser Keyboard-Lock/Pointer-Lock API.
#[must_use]
pub fn techniques_of(signal: &str) -> &'static [&'static str] {
    match signal {
        "phone_number" | "blocklist_phone" | "blocklist_title" => &["T1566"],
        "brand_impersonation"
        | "combosquat_brand"
        | "typosquat_brand"
        | "url_path_lure"
        | "rogue_av_process" => &["T1656"],
        "mixed_script"
        | "whole_script_confusable"
        | "bidi_override"
        | "compat_chars_present"
        | "mixed_number_systems"
        | "excessive_combining_marks" => &["T1036"],
        "clickfix_instruction" => &["T1204"],
        "remote_access_lure" | "screen_share_lure" => &["T1219"],
        "blocks_input" | "input_trap" => &["T1056"],
        // Sudden full-screen takeover, fake BSOD, and fake Windows Defender all
        // impersonate a legitimate OS/security-product UI to deceive the victim: T1036.
        // windows_defender_alert_lure impersonates a named security product (Defender);
        // fake_browser_security_warning impersonates a browser security error page.
        "sudden_fullscreen_takeover"
        | "fake_bsod_lure"
        | "fake_browser_security_warning"
        | "windows_defender_alert_lure" => &["T1036"],
        // Urgency-coercion, forced-retention, cloud-lure delivery, and
        // fake-scanner overlays are social-engineering hooks that steer
        // victims toward the attacker's call or site: T1566 Phishing.
        "urgency_countdown"
        | "cloud_storage_abuse"
        | "blocklist_host"
        | "forced_retention_cue"
        | "credential_harvest_cue"
        | "fake_scanner_cue"
        | "subscription_lure"
        | "authority_lure"
        | "download_trap_lure"
        | "prize_lure"
        | "crypto_drain_lure"
        | "qr_code_lure"
        | "ip_alarm_lure"
        | "package_fee_lure"
        | "sextortion_lure"
        | "gift_card_demand"
        | "refund_scam_cue"
        | "national_id_alarm"
        | "bank_account_alarm"
        | "false_registration_billing"
        | "advance_fee_lure"
        | "tech_support_invoice_scam"
        | "utility_cutoff_threat"
        | "healthcare_scam"
        | "job_scam"
        | "tax_authority_scam"
        | "social_media_account_alarm"
        | "immigration_visa_scam"
        | "government_grant_scam"
        | "debt_relief_scam"
        | "streaming_billing_scam"
        | "traffic_fine_scam"
        | "pig_butchering_lure"
        | "loan_fee_scam"
        | "data_uri_page"
        | "charity_scam_lure"
        | "rental_scam_lure"
        | "pet_sale_scam"
        | "timeshare_travel_scam"
        | "windows_activation_scam"
        | "survey_reward_scam"
        | "av_brand_renewal_scam"
        | "recovery_scam"
        | "student_loan_scam"
        | "secret_shopper_scam"
        | "mlm_pyramid_recruitment"
        | "ip_host_url"
        | "veterans_benefit_scam"
        | "fake_copyright_scam"
        | "crypto_giveaway_scam"
        | "otp_interception_scam"
        | "family_emergency_scam"
        | "toad_case_number_lure"
        | "wallet_connect_popup_lure"
        | "alarm_density"          // excessive fear-word stacking — social-engineering pressure hook
        | "task_app_scam"          // fake-task earnings — social-engineering lure
        | "software_subscription_scam" // fake SaaS billing alert — credential/payment phishing
        | "dark_web_breach_lure"   // fake breach notification — credential phishing
        | "cloud_quota_lure"       // fake storage-full alarm — credential/payment phishing
        | "tech_support_chat_lure" // fake tech-brand live-chat — social-engineering pivot
        => &["T1566"],
        _ => &[],
    }
}

/// Collect the distinct ATT&CK technique IDs present in a set of signals,
/// sorted and deduplicated for a stable, SIEM-friendly representation.
/// Accepts any slice whose elements implement `AsRef<str>`.
#[must_use]
pub fn techniques_of_signals<S: AsRef<str>>(signals: &[S]) -> Vec<String> {
    let mut ids: Vec<&'static str> = signals
        .iter()
        .flat_map(|s| techniques_of(s.as_ref()))
        .copied()
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids.iter().map(|s| (*s).to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptive_signals_have_no_technique() {
        for s in [
            "fullscreen",
            "topmost",
            "very_new",
            "unsolicited",
            "user_initiated",
        ] {
            assert!(
                techniques_of(s).is_empty(),
                "{s} should have no ATT&CK mapping"
            );
        }
    }

    #[test]
    fn known_signals_map_correctly() {
        assert_eq!(techniques_of("phone_number"), &["T1566"]);
        assert_eq!(techniques_of("blocklist_title"), &["T1566"]);
        assert_eq!(techniques_of("brand_impersonation"), &["T1656"]);
        assert_eq!(techniques_of("combosquat_brand"), &["T1656"]);
        assert_eq!(techniques_of("typosquat_brand"), &["T1656"]);
        assert_eq!(techniques_of("url_path_lure"), &["T1656"]);
        assert_eq!(techniques_of("rogue_av_process"), &["T1656"]);
        assert_eq!(techniques_of("urgency_countdown"), &["T1566"]);
        assert_eq!(techniques_of("cloud_storage_abuse"), &["T1566"]);
        assert_eq!(techniques_of("mixed_script"), &["T1036"]);
        assert_eq!(techniques_of("bidi_override"), &["T1036"]);
        assert_eq!(techniques_of("compat_chars_present"), &["T1036"]);
        assert_eq!(techniques_of("mixed_number_systems"), &["T1036"]);
        assert_eq!(techniques_of("excessive_combining_marks"), &["T1036"]);
        assert_eq!(techniques_of("whole_script_confusable"), &["T1036"]);
        assert_eq!(techniques_of("clickfix_instruction"), &["T1204"]);
        assert_eq!(techniques_of("remote_access_lure"), &["T1219"]);
        assert_eq!(techniques_of("screen_share_lure"), &["T1219"]);
        assert_eq!(techniques_of("blocks_input"), &["T1056"]);
        assert_eq!(techniques_of("input_trap"), &["T1056"]);
        assert_eq!(techniques_of("forced_retention_cue"), &["T1566"]);
        assert_eq!(techniques_of("credential_harvest_cue"), &["T1566"]);
        assert_eq!(techniques_of("fake_scanner_cue"), &["T1566"]);
        assert_eq!(techniques_of("subscription_lure"), &["T1566"]);
        assert_eq!(techniques_of("authority_lure"), &["T1566"]);
        assert_eq!(techniques_of("crypto_drain_lure"), &["T1566"]);
        assert_eq!(techniques_of("prize_lure"), &["T1566"]);
        assert_eq!(techniques_of("download_trap_lure"), &["T1566"]);
        assert_eq!(techniques_of("qr_code_lure"), &["T1566"]);
        assert_eq!(techniques_of("ip_alarm_lure"), &["T1566"]);
        assert_eq!(techniques_of("gift_card_demand"), &["T1566"]);
        assert_eq!(techniques_of("refund_scam_cue"), &["T1566"]);
        assert_eq!(techniques_of("national_id_alarm"), &["T1566"]);
        assert_eq!(techniques_of("bank_account_alarm"), &["T1566"]);
        assert_eq!(techniques_of("false_registration_billing"), &["T1566"]);
        assert_eq!(techniques_of("sudden_fullscreen_takeover"), &["T1036"]);
        assert_eq!(techniques_of("fake_bsod_lure"), &["T1036"]);
        assert_eq!(techniques_of("advance_fee_lure"), &["T1566"]);
        assert_eq!(techniques_of("tech_support_invoice_scam"), &["T1566"]);
        assert_eq!(techniques_of("utility_cutoff_threat"), &["T1566"]);
        assert_eq!(techniques_of("healthcare_scam"), &["T1566"]);
        assert_eq!(techniques_of("job_scam"), &["T1566"]);
        assert_eq!(techniques_of("tax_authority_scam"), &["T1566"]);
        assert_eq!(techniques_of("social_media_account_alarm"), &["T1566"]);
        assert_eq!(techniques_of("immigration_visa_scam"), &["T1566"]);
        assert_eq!(techniques_of("government_grant_scam"), &["T1566"]);
        assert_eq!(techniques_of("debt_relief_scam"), &["T1566"]);
        assert_eq!(techniques_of("streaming_billing_scam"), &["T1566"]);
        assert_eq!(techniques_of("traffic_fine_scam"), &["T1566"]);
        assert_eq!(techniques_of("pig_butchering_lure"), &["T1566"]);
        assert_eq!(techniques_of("loan_fee_scam"), &["T1566"]);
        assert_eq!(techniques_of("data_uri_page"), &["T1566"]);
        assert_eq!(techniques_of("charity_scam_lure"), &["T1566"]);
        assert_eq!(techniques_of("rental_scam_lure"), &["T1566"]);
        assert_eq!(techniques_of("pet_sale_scam"), &["T1566"]);
        assert_eq!(techniques_of("timeshare_travel_scam"), &["T1566"]);
        assert_eq!(techniques_of("windows_activation_scam"), &["T1566"]);
        assert_eq!(techniques_of("survey_reward_scam"), &["T1566"]);
        assert_eq!(techniques_of("av_brand_renewal_scam"), &["T1566"]);
        assert_eq!(techniques_of("recovery_scam"), &["T1566"]);
        assert_eq!(techniques_of("student_loan_scam"), &["T1566"]);
        assert_eq!(techniques_of("secret_shopper_scam"), &["T1566"]);
        assert_eq!(techniques_of("mlm_pyramid_recruitment"), &["T1566"]);
        assert_eq!(techniques_of("ip_host_url"), &["T1566"]);
        assert_eq!(techniques_of("veterans_benefit_scam"), &["T1566"]);
        assert_eq!(techniques_of("fake_copyright_scam"), &["T1566"]);
        assert_eq!(techniques_of("crypto_giveaway_scam"), &["T1566"]);
        assert_eq!(techniques_of("otp_interception_scam"), &["T1566"]);
        assert_eq!(techniques_of("family_emergency_scam"), &["T1566"]);
        assert_eq!(techniques_of("toad_case_number_lure"), &["T1566"]);
        assert_eq!(techniques_of("wallet_connect_popup_lure"), &["T1566"]);
        assert_eq!(techniques_of("fake_browser_security_warning"), &["T1036"]);
    }

    #[test]
    fn unknown_signal_has_no_technique() {
        assert!(techniques_of("not_a_real_signal").is_empty());
    }

    #[test]
    fn techniques_of_signals_deduplicates_and_sorts() {
        // Two T1566 signals + one T1036 → [T1036, T1566] (sorted, deduped).
        let signals: &[&str] = &["phone_number", "blocklist_title", "mixed_script"];
        let ids = techniques_of_signals(signals);
        assert_eq!(ids, vec!["T1036", "T1566"]);
    }

    #[test]
    fn techniques_of_signals_empty_input() {
        let none: &[&str] = &[];
        assert!(techniques_of_signals(none).is_empty());
    }

    #[test]
    fn techniques_of_signals_works_with_owned_strings() {
        let signals = vec![
            "clickfix_instruction".to_string(),
            "remote_access_lure".to_string(),
        ];
        let ids = techniques_of_signals(&signals);
        assert!(ids.contains(&"T1204".to_string()));
        assert!(ids.contains(&"T1219".to_string()));
        assert_eq!(ids.len(), 2);
    }
}
