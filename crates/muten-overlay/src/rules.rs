//! Offline blocklist for overlay classification.
//!
//! ## Format
//!
//! A plain-text file, one rule per line. Rule kinds:
//!
//! ```text
//! # comments start with '#'
//! host: win-prize-now.example      # block any URL on this host (or subdomain)
//! title: your computer is infected # substring match against the window title
//! glob: *your computer*infected*   # full-string glob match (*, ?)
//! phone: 1-800-555-0100            # curated scam phone number (digits-only match)
//! process: pc protector plus       # rogue-AV process-name substring
//! composite: <name> <weight> <cond…> # AND-condition named rule
//! ```
//!
//! Bare lines (no prefix) are treated as `host:` rules, which is the
//! common case and matches the muscle memory of hosts-file / pi-hole
//! users. Matching is case-insensitive; hosts match the registered
//! domain and any subdomain (`a.b.evil.example` matches `evil.example`).
//!
//! ### `glob:` patterns
//!
//! Unlike `title:` (which is a substring/contains match), `glob:` patterns
//! are full-string: the entire normalized title must match.  Use `*` at
//! either end for prefix, suffix, or contains behaviour:
//!
//! ```text
//! glob: *your computer is infected*   # contains (equivalent to title:)
//! glob: WARNING: *                    # any title that starts "warning: "
//! glob: * security alert *            # contains " security alert " anywhere
//! ```
//!
//! `*` matches any run of characters (including none); `?` matches exactly
//! one character.  Both the pattern and the title are normalized through
//! the same pipeline as `title:` (`strip_invisibles → fold_confusables →
//! fold_leet_in_words → lowercase`) before matching, so evasion via
//! homoglyphs, zero-width characters, and leetspeak is handled uniformly.
//!
//! ## Why offline
//!
//! Same rationale as the rest of muten: managed PCs may be air-gapped,
//! and shipping the user's browsing to a remote filter service would
//! leak PII (I5) and add a runtime network dependency we refuse to
//! take. IT pushes an updated list via MDM; the daemon reads the file.
//! This is deliberately *not* a 100k-entry EasyList-style filter —
//! it's a focused list of the scam hosts/titles a given deployment
//! actually sees, kept small enough to audit by eye.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The parsed offline blocklist. Parse with [`Ruleset::parse`] (or
/// [`Ruleset::from_lines`] in tests). An empty `Ruleset::default()`
/// matches nothing and is safe to use as a no-op placeholder.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ruleset {
    /// Registered hosts to block (lower-cased, no scheme/path).
    hosts: BTreeSet<String>,
    /// Title substrings to flag.
    title_patterns: Vec<TitlePattern>,
    /// Title glob patterns (`*`/`?` wildcards, full-string match).
    glob_patterns: Vec<GlobPattern>,
    /// Known rogue-AV / scareware process-name substrings (lower-cased).
    /// e.g. "pc protector plus", "advanced mac cleaner", "registrysmart".
    process_patterns: Vec<String>,
    /// Known scam phone numbers, digits-only key + authored display.
    phone_patterns: Vec<PhonePattern>,
    /// Declarative AND-condition composite rules (`composite:` prefix).
    composite_rules: Vec<CompositeRule>,
    /// Per-signal weight overrides from `weight:` lines.  Operators can
    /// raise or lower any named signal's contribution without rebuilding.
    weight_overrides: BTreeMap<String, i32>,
}

/// A blocklist phone rule. `digits` is the number with every non-digit
/// stripped (the form used for matching, robust to how separators are
/// written); `display` is the authored text, surfaced as the matched rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PhonePattern {
    digits: String,
    display: String,
}

/// A testable condition used in a [`CompositeRule`]. Each variant maps to a
/// property of the window under examination or a signal that fired earlier in
/// the same `classify()` call (the "has_*" variants). Unknown condition
/// strings in a `composite:` rule line are silently skipped; a rule with zero
/// recognized conditions is dropped as malformed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositeCondition {
    /// Window covers ≥ 85 % of the active display.
    Fullscreen,
    /// Window is always-on-top.
    Topmost,
    /// Window has no usable close affordance.
    NoCloseButton,
    /// Window grabs all pointer/keyboard input (modal).
    BlocksInput,
    /// Window appeared with no user action (unsolicited).
    Unsolicited,
    /// Window appeared right after a user click or keypress.
    UserInitiated,
    /// Window has been on screen for 0 < age_ms < 1000 ms (genuinely new;
    /// age 0 = "enumerator couldn't tell" and does NOT satisfy this).
    VeryNew,
    /// Window is full-screen, modal, or has no close button — the
    /// "alert shape" used to gate content signals like `clickfix_instruction`.
    AlertShaped,
    /// The `blocklist_title` signal fired earlier in this `classify()` call.
    HasBlocklistTitle,
    /// The `phone_number` signal fired earlier in this `classify()` call.
    HasPhoneNumber,
    /// The `blocklist_phone` signal fired earlier in this `classify()` call.
    HasBlocklistPhone,
    /// The `credential_harvest_cue` signal fired (E14 — account alarm + credential demand).
    HasCredentialHarvestCue,
    /// The `fake_scanner_cue` signal fired (E15 — fake AV scan progress).
    HasFakeScannerCue,
    /// The `subscription_lure` signal fired (E16 — fake subscription expiry).
    HasSubscriptionLure,
    /// The `authority_lure` signal fired (E17 — LEA/government impersonation).
    HasAuthorityLure,
    /// The `screen_share_lure` signal fired (E18 — share-screen social instruction).
    HasScreenShareLure,
    /// The `crypto_drain_lure` signal fired (E19 — wallet alarm / seed-phrase harvest).
    HasCryptoDrainLure,
    /// The `prize_lure` signal fired (E20 — fake prize / lottery / gift-card).
    HasPrizeLure,
    /// The `download_trap_lure` signal fired (E21 — fake download/update gate).
    HasDownloadTrapLure,
    /// The `qr_code_lure` signal fired (E22 — QR/quishing overlay).
    HasQrCodeLure,
    /// The `ip_alarm_lure` signal fired (E23 — IP address alarm / tech-support scam).
    HasIpAlarmLure,
    /// The `package_fee_lure` signal fired (E24 — delivery/customs fee advance-fee scam).
    HasPackageFeeLure,
    /// The `sextortion_lure` signal fired (E25 — webcam recording extortion overlay).
    HasSextortionLure,
    /// The `gift_card_demand` signal fired (E26 — gift-card payment demand).
    HasGiftCardDemand,
    /// The `refund_scam_cue` signal fired (E27 — refund/overpayment scam lure).
    HasRefundScamCue,
    /// The `national_id_alarm` signal fired (E28 — SSN/NIN/マイナンバー suspension scam).
    HasNationalIdAlarm,
    /// The `bank_account_alarm` signal fired (E29 — fake bank-fraud alert overlay).
    HasBankAccountAlarm,
    /// The `false_registration_billing` signal fired (E30 — ワンクリック詐欺 fake billing).
    HasFalseRegistrationBilling,
    /// The `fake_bsod_lure` signal fired (E31 — fake BSOD / Windows-blocked overlay).
    HasFakeBsodLure,
    /// The `advance_fee_lure` signal fired (E32 — 419/inheritance advance-fee fraud).
    HasAdvanceFeeLure,
    /// The `tech_support_invoice_scam` signal fired (E33 — fake invoice cancel-scam).
    HasTechSupportInvoiceScam,
    /// The `utility_cutoff_threat` signal fired (E34 — fake utility disconnection).
    HasUtilityCutoffThreat,
    /// The `healthcare_scam` signal fired (E35 — Medicare/benefit expiry lure).
    HasHealthcareScam,
    /// The `job_scam` signal fired (E36 — fake job offer with advance-fee gate).
    HasJobScam,
    /// The `tax_authority_scam` signal fired (E37 — IRS/HMRC/国税庁 + arrest threat).
    HasTaxAuthorityScam,
    /// The `social_media_account_alarm` signal fired (E38 — social platform + hacked/suspended).
    HasSocialMediaAccountAlarm,
    /// The `immigration_visa_scam` signal fired (E39 — visa/work-permit + revocation threat).
    HasImmigrationVisaScam,
    /// The `government_grant_scam` signal fired (E40 — gov-program impersonation + fee barrier).
    HasGovernmentGrantScam,
    /// The `debt_relief_scam` signal fired (E41 — debt/credit distress + guaranteed-fee CTA).
    HasDebtReliefScam,
    /// The `streaming_billing_scam` signal fired (E42 — named streaming service + payment failure).
    HasStreamingBillingScam,
    /// The `traffic_fine_scam` signal fired (E43 — traffic/parking/toll violation + payment urgency).
    HasTrafficFineScam,
    /// The `pig_butchering_lure` signal fired (E44 — romance/mentor + investment platform cue).
    HasPigButcheringLure,
    /// The `loan_fee_scam` signal fired (E45 — pre-approved loan + upfront fee gate).
    HasLoanFeeScam,
    /// The `data_uri_page` signal fired (A9 — URL uses data: or file:// scheme).
    HasDataUriPage,
    /// The `charity_scam_lure` signal fired (E46 — fake charity + irreversible payment method).
    HasCharityScamLure,
    /// The `rental_scam_lure` signal fired (E47 — fake rental listing + advance deposit demand).
    HasRentalScamLure,
    /// The `pet_sale_scam` signal fired (E48 — fake pet listing + transport/crate deposit demand).
    HasPetSaleScam,
    /// The `timeshare_travel_scam` signal fired (E49 — vacation club + activation fee demand).
    HasTimeshareScam,
    /// The `windows_activation_scam` signal fired (E50 — fake Windows/Office product-key popup).
    HasWindowsActivationScam,
    /// The `survey_reward_scam` signal fired (E51 — survey-invite + gift-card reward bait).
    HasSurveyRewardScam,
    /// The `av_brand_renewal_scam` signal fired (E52 — named AV brand + subscription-expiry).
    HasAvBrandRenewalScam,
    /// The `recovery_scam` signal fired (E53 — fraud-recovery service + fee demand).
    HasRecoveryScam,
    /// The `student_loan_scam` signal fired (E54 — loan forgiveness + processing fee).
    HasStudentLoanScam,
    /// The `secret_shopper_scam` signal fired (E55 — mystery shopper + check/wire-transfer demand).
    HasSecretShopperScam,
    /// The `mlm_pyramid_recruitment` signal fired (E56 — referral/downline framing + join CTA).
    HasMlmPyramidRecruitment,
    /// The `ip_host_url` signal fired (E57 — URL host is a raw IPv4/IPv6 address).
    HasIpHostUrl,
    /// The `veterans_benefit_scam` signal fired (E58 — VA/veteran benefit + processing fee).
    HasVeteransBenefitScam,
    /// The `fake_copyright_scam` signal fired (E59 — DMCA/copyright notice + pay settlement).
    HasFakeCopyrightScam,
    /// The `crypto_giveaway_scam` signal fired (E60 — coin-doubling giveaway + send-to-receive).
    HasCryptoGiveawayScam,
    /// The `otp_interception_scam` signal fired (E61 — OTP/2FA code cue + share-the-code relay).
    HasOtpInterceptionScam,
    /// The `family_emergency_scam` signal fired (E62 — relative + crisis + money/secrecy demand).
    HasFamilyEmergencyScam,
}

impl CompositeCondition {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "fullscreen" => Some(Self::Fullscreen),
            "topmost" => Some(Self::Topmost),
            "no_close_button" => Some(Self::NoCloseButton),
            "blocks_input" => Some(Self::BlocksInput),
            "unsolicited" => Some(Self::Unsolicited),
            "user_initiated" => Some(Self::UserInitiated),
            "very_new" => Some(Self::VeryNew),
            "alert_shaped" => Some(Self::AlertShaped),
            "has_blocklist_title" => Some(Self::HasBlocklistTitle),
            "has_phone_number" => Some(Self::HasPhoneNumber),
            "has_blocklist_phone" => Some(Self::HasBlocklistPhone),
            "has_credential_harvest_cue" => Some(Self::HasCredentialHarvestCue),
            "has_fake_scanner_cue" => Some(Self::HasFakeScannerCue),
            "has_subscription_lure" => Some(Self::HasSubscriptionLure),
            "has_authority_lure" => Some(Self::HasAuthorityLure),
            "has_screen_share_lure" => Some(Self::HasScreenShareLure),
            "has_crypto_drain_lure" => Some(Self::HasCryptoDrainLure),
            "has_prize_lure" => Some(Self::HasPrizeLure),
            "has_download_trap_lure" => Some(Self::HasDownloadTrapLure),
            "has_qr_code_lure" => Some(Self::HasQrCodeLure),
            "has_ip_alarm_lure" => Some(Self::HasIpAlarmLure),
            "has_package_fee_lure" => Some(Self::HasPackageFeeLure),
            "has_sextortion_lure" => Some(Self::HasSextortionLure),
            "has_gift_card_demand" => Some(Self::HasGiftCardDemand),
            "has_refund_scam_cue" => Some(Self::HasRefundScamCue),
            "has_national_id_alarm" => Some(Self::HasNationalIdAlarm),
            "has_bank_account_alarm" => Some(Self::HasBankAccountAlarm),
            "has_false_registration_billing" => Some(Self::HasFalseRegistrationBilling),
            "has_fake_bsod_lure" => Some(Self::HasFakeBsodLure),
            "has_advance_fee_lure" => Some(Self::HasAdvanceFeeLure),
            "has_tech_support_invoice_scam" => Some(Self::HasTechSupportInvoiceScam),
            "has_utility_cutoff_threat" => Some(Self::HasUtilityCutoffThreat),
            "has_healthcare_scam" => Some(Self::HasHealthcareScam),
            "has_job_scam" => Some(Self::HasJobScam),
            "has_tax_authority_scam" => Some(Self::HasTaxAuthorityScam),
            "has_social_media_account_alarm" => Some(Self::HasSocialMediaAccountAlarm),
            "has_immigration_visa_scam" => Some(Self::HasImmigrationVisaScam),
            "has_government_grant_scam" => Some(Self::HasGovernmentGrantScam),
            "has_debt_relief_scam" => Some(Self::HasDebtReliefScam),
            "has_streaming_billing_scam" => Some(Self::HasStreamingBillingScam),
            "has_traffic_fine_scam" => Some(Self::HasTrafficFineScam),
            "has_pig_butchering_lure" => Some(Self::HasPigButcheringLure),
            "has_loan_fee_scam" => Some(Self::HasLoanFeeScam),
            "has_data_uri_page" => Some(Self::HasDataUriPage),
            "has_charity_scam_lure" => Some(Self::HasCharityScamLure),
            "has_rental_scam_lure" => Some(Self::HasRentalScamLure),
            "has_pet_sale_scam" => Some(Self::HasPetSaleScam),
            "has_timeshare_scam" => Some(Self::HasTimeshareScam),
            "has_windows_activation_scam" => Some(Self::HasWindowsActivationScam),
            "has_survey_reward_scam" => Some(Self::HasSurveyRewardScam),
            "has_av_brand_renewal_scam" => Some(Self::HasAvBrandRenewalScam),
            "has_recovery_scam" => Some(Self::HasRecoveryScam),
            "has_student_loan_scam" => Some(Self::HasStudentLoanScam),
            "has_secret_shopper_scam" => Some(Self::HasSecretShopperScam),
            "has_mlm_pyramid_recruitment" => Some(Self::HasMlmPyramidRecruitment),
            "has_ip_host_url" => Some(Self::HasIpHostUrl),
            "has_veterans_benefit_scam" => Some(Self::HasVeteransBenefitScam),
            "has_fake_copyright_scam" => Some(Self::HasFakeCopyrightScam),
            "has_crypto_giveaway_scam" => Some(Self::HasCryptoGiveawayScam),
            "has_otp_interception_scam" => Some(Self::HasOtpInterceptionScam),
            "has_family_emergency_scam" => Some(Self::HasFamilyEmergencyScam),
            _ => None,
        }
    }
}

/// A declarative AND-condition blocklist rule (YARA/Sigma-style named pattern).
/// If **all** `conditions` hold when `classify()` evaluates this rule, `weight`
/// is added to the score and `name` is pushed into the verdict's `signals` list
/// (and therefore appears in `Verdict::explain()` and the audit log). Defined
/// with a `composite:` prefix in the blocklist text.
///
/// Follow the **bounded-composite convention**: keep `weight` below the gap
/// between the highest individual-signal cluster and `BLOCK_THRESHOLD` so a
/// window with no content or provenance tell stays `Suspicious`, not `Block` —
/// the observe-first guard. The two built-in composites (`input_trap`,
/// `sudden_fullscreen_takeover`) use weights 5 and 5 for exactly this reason.
///
/// Grammar: `composite: <name> <weight> <cond1> [<cond2> …]`
///
/// Example:
/// ```text
/// composite: coercive_overlay 90 fullscreen topmost no_close_button blocks_input
/// composite: phone_alert_lure  60 has_phone_number alert_shaped topmost
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositeRule {
    /// Signal name recorded in the verdict when all conditions fire.
    pub name: String,
    /// Additive weight added to the score when all conditions fire.
    pub weight: i32,
    /// All must hold simultaneously (AND logic).
    pub conditions: Vec<CompositeCondition>,
}

/// A blocklist title rule, kept in two forms: `key` is the normalized
/// string used for matching (symmetric with how titles are normalized
/// at match time), and `display` is the text as authored, returned as
/// the matched rule so the audit log shows what the operator wrote
/// rather than the folded skeleton.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TitlePattern {
    key: String,
    display: String,
}

/// A blocklist glob-pattern title rule.  `key` is the pattern after
/// normalization (same pipeline as `TitlePattern`; `*`/`?` preserved);
/// `display` is the authored text for audit-log readability.  Full-string
/// matching: the entire normalized title must match the entire pattern.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GlobPattern {
    key: String,
    display: String,
}

/// Largest absolute per-signal / composite weight an operator blocklist may
/// set. The additive score is `i32`; without a bound, two co-firing signals
/// each overridden near `i32::MAX` (e.g. a fat-fingered `weight: fullscreen
/// 2000000000`) would overflow the accumulation — a debug-build panic, or a
/// release-build two's-complement wrap that can flip a would-be Block to Allow
/// after the `score.max(0)` clamp. Operator weights are clamped to ±this at
/// parse time. The bound is ~250× the largest built-in weight, so it never
/// constrains legitimate tuning, and a value beyond it is semantically
/// identical anyway (anything ≥ `BLOCK_THRESHOLD` already forces Block). Even
/// with every signal and thousands of composites clamped to this, the worst-
/// case sum stays far below `i32::MAX`, so the score arithmetic cannot overflow.
pub(crate) const MAX_ABS_WEIGHT: i32 = 10_000;

impl Ruleset {
    /// Parse a blocklist from its text form. Unknown/blank lines are
    /// skipped silently; a malformed entry never aborts the load
    /// (one bad line shouldn't disable the whole list).
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut hosts = BTreeSet::new();
        let mut title_patterns = Vec::new();
        let mut glob_patterns = Vec::new();
        let mut process_patterns = Vec::new();
        let mut phone_patterns = Vec::new();
        let mut composite_rules = Vec::new();
        let mut weight_overrides = BTreeMap::new();
        for raw in text.lines() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("host:") {
                if let Some(h) = normalize_host(rest.trim()) {
                    hosts.insert(h);
                }
            } else if let Some(rest) = line.strip_prefix("glob:") {
                // Full-string glob pattern. `*` matches any run of chars
                // (including none); `?` matches exactly one char. Normalized
                // at parse time with the same pipeline as `title:` — but `*`
                // and `?` are non-alphanumeric separators and are preserved
                // verbatim by `fold_leet_in_words`, so they remain as
                // metacharacters after normalization.
                let raw_pat = rest.trim();
                let key = crate::confusables::normalize_for_match(raw_pat);
                if !key.is_empty() {
                    glob_patterns.push(GlobPattern {
                        key,
                        display: raw_pat.to_ascii_lowercase(),
                    });
                }
            } else if let Some(rest) = line.strip_prefix("title:") {
                // Normalize the pattern the SAME way titles are
                // normalized at match time (strip invisibles, fold
                // confusables, fold leetspeak, lowercase). Without this
                // the two sides are asymmetric: a pattern containing a
                // letter-adjacent digit ("win32", "office365") or a
                // confusable would never match, because the *title* gets
                // folded ("win32"→"wine2") while the stored pattern does
                // not. See `match_title`.
                let raw = rest.trim();
                let key = crate::confusables::normalize_for_match(raw);
                if !key.is_empty() {
                    title_patterns.push(TitlePattern {
                        key,
                        display: raw.to_ascii_lowercase(),
                    });
                }
            } else if let Some(rest) = line.strip_prefix("process:") {
                let pat = rest.trim().to_ascii_lowercase();
                if !pat.is_empty() {
                    process_patterns.push(pat);
                }
            } else if let Some(rest) = line.strip_prefix("phone:") {
                // Known scam phone number. Match on digits only, so the
                // operator can write it with whatever separators they like
                // (1-800-…, +81-0120-…) and it still matches a title that
                // formats it differently. Require ≥ 7 digits so a stray
                // short number can't become an over-broad rule.
                let display = rest.trim().to_ascii_lowercase();
                let digits: String = display.chars().filter(char::is_ascii_digit).collect();
                let key = normalize_phone_digits(&digits);
                if key.len() >= 7 {
                    phone_patterns.push(PhonePattern {
                        digits: key,
                        display,
                    });
                }
            } else if let Some(rest) = line.strip_prefix("composite:") {
                // Declarative AND-condition rule (C5-2).
                // Format: composite: <name> <weight> <cond1> [<cond2> …]
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if let Some((name, tail)) = parts.split_first() {
                    if let Some((weight_str, cond_strs)) = tail.split_first() {
                        if let Ok(weight) = weight_str.parse::<i32>() {
                            let weight = weight.clamp(-MAX_ABS_WEIGHT, MAX_ABS_WEIGHT);
                            let conditions: Vec<CompositeCondition> = cond_strs
                                .iter()
                                .filter_map(|s| CompositeCondition::from_str(s))
                                .collect();
                            if !name.is_empty() && !conditions.is_empty() {
                                composite_rules.push(CompositeRule {
                                    name: name.to_string(),
                                    weight,
                                    conditions,
                                });
                            }
                        }
                    }
                }
            } else if let Some(rest) = line.strip_prefix("weight:") {
                // Per-signal weight override.
                // Format: weight: <signal_name> <value>
                // Allows operators to tune any named signal's additive
                // contribution without recompiling.  The value is any i32
                // (including negative, to soften or negate a relief signal).
                // Unknown signal names are silently stored — classify() will
                // look them up later; this future-proofs against new signals
                // added after the blocklist was authored.
                let mut parts = rest.split_whitespace();
                if let (Some(sig), Some(val_str)) = (parts.next(), parts.next()) {
                    if let Ok(val) = val_str.parse::<i32>() {
                        let val = val.clamp(-MAX_ABS_WEIGHT, MAX_ABS_WEIGHT);
                        weight_overrides.insert(sig.to_ascii_lowercase(), val);
                    }
                }
            } else {
                // Bare line → treat as host.
                if let Some(h) = normalize_host(line) {
                    hosts.insert(h);
                }
            }
        }
        Self {
            hosts,
            title_patterns,
            glob_patterns,
            process_patterns,
            phone_patterns,
            composite_rules,
            weight_overrides,
        }
    }

    /// Convenience for tests / programmatic construction.
    #[must_use]
    pub fn from_lines(lines: &[&str]) -> Self {
        Self::parse(&lines.join("\n"))
    }

    /// Number of host rules loaded.
    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }
    /// Number of title-substring patterns loaded.
    pub fn title_count(&self) -> usize {
        self.title_patterns.len()
    }
    /// Number of title glob patterns loaded (`glob:` rules).
    pub fn glob_count(&self) -> usize {
        self.glob_patterns.len()
    }
    /// Number of process-name patterns loaded.
    pub fn process_count(&self) -> usize {
        self.process_patterns.len()
    }
    /// Number of known-scam phone-number patterns loaded.
    pub fn phone_count(&self) -> usize {
        self.phone_patterns.len()
    }
    /// Number of declarative composite AND-condition rules loaded.
    pub fn composite_count(&self) -> usize {
        self.composite_rules.len()
    }
    /// Number of per-signal weight overrides (`weight:` lines) loaded.
    pub fn weight_override_count(&self) -> usize {
        self.weight_overrides.len()
    }
    /// Access the composite AND-condition rules (for evaluation in classify).
    #[must_use]
    pub fn composite_rules(&self) -> &[CompositeRule] {
        &self.composite_rules
    }

    /// Effective weight for a named signal.  Returns the operator-supplied
    /// override from a `weight:` blocklist line if one exists, otherwise
    /// falls back to `default` (the compile-time constant for that signal).
    ///
    /// `classify()` uses this for every signal so that a fleet-pushed
    /// blocklist can tune sensitivity without a rebuild — an operator who
    /// observes from `signal_firing_stats()` that `mixed_script` has a high
    /// FP rate in their environment can lower its weight while keeping all
    /// other signals at their compiled defaults.
    #[must_use]
    pub fn weight_of(&self, signal: &str, default: i32) -> i32 {
        self.weight_overrides
            .get(signal)
            .copied()
            .unwrap_or(default)
    }

    /// Does `url` resolve to a blocked host? Returns the matched rule
    /// host on success. Matches the host and any subdomain of it.
    #[must_use]
    pub fn match_host(&self, url: &str) -> Option<String> {
        let host = host_of(url)?;
        // Normalize the host through the shared host pipeline: drop zero-width/
        // BiDi characters (`ev\u{200B}il`), drop combining diacritics
        // (`paypa\u{0337}l`), then fold typosquat/homoglyph confusables (0→o,
        // 1→l, Cyrillic о→o, math-alphanumeric, …) and lower-case — so
        // `micros0ft.example` / `evіl.example` / `paypa\u{0337}l.example` can't
        // dodge an ASCII host blocklist. Both the host and each rule go through
        // the *same* `normalize_host_for_match`, keeping the two sides symmetric
        // and preventing the title/host pipelines from silently drifting apart.
        // We return the *original* matched rule string for the audit log.
        let folded_host = crate::confusables::normalize_host_for_match(&host);
        let labels: Vec<&str> = folded_host.split('.').collect();
        for i in 0..labels.len() {
            let suffix = labels[i..].join(".");
            // Fast path: exact (already-folded-equal) membership.
            if self.hosts.contains(&suffix) {
                return Some(suffix);
            }
            // Normalized comparison against each rule (host set is small).
            for rule in &self.hosts {
                if crate::confusables::normalize_host_for_match(rule) == suffix {
                    return Some(rule.clone());
                }
            }
        }
        None
    }

    /// Does `title` contain a blocked pattern? Returns the pattern.
    ///
    /// The title is fully normalized before matching
    /// ([`normalize_for_match`](crate::confusables::normalize_for_match)):
    /// zero-width/BiDi characters are stripped, homoglyphs
    /// (Cyrillic/Greek/full-width look-alikes) are folded to ASCII, and
    /// leetspeak digits inside words are restored — so a scam that
    /// writes "у\u{200B}our c0mputer is 1nfected" can't slip past an
    /// ASCII substring blocklist. See the `confusables` module. The
    /// stored patterns are normalized the *same* way at parse time, so
    /// the two sides are symmetric.
    #[must_use]
    pub fn match_title(&self, title: &str) -> Option<String> {
        let t = crate::confusables::normalize_for_match(title);
        self.title_patterns
            .iter()
            .find(|p| t.contains(&p.key))
            .map(|p| p.display.clone())
    }

    /// Does `title` match any **glob title pattern**?  Returns the display
    /// form of the first matching pattern.
    ///
    /// The title is normalized through the same pipeline as [`match_title`]
    /// before matching.  Unlike `match_title`, which does a substring
    /// (contains) search, glob matching is **full-string**: the entire
    /// normalized title must match the pattern.  Use `*` at the edges for
    /// contains / prefix / suffix semantics.
    ///
    /// `*` matches any sequence of characters (including the empty sequence).
    /// `?` matches any single character.  Both are matched against normalized
    /// code points; the pattern is also normalized at parse time, so
    /// evasion via homoglyphs, zero-width characters, and leetspeak is
    /// thwarted symmetrically.
    ///
    /// [`match_title`]: Ruleset::match_title
    #[must_use]
    pub fn match_title_glob(&self, title: &str) -> Option<String> {
        if self.glob_patterns.is_empty() {
            return None;
        }
        let t: Vec<char> = crate::confusables::normalize_for_match(title)
            .chars()
            .collect();
        for pat in &self.glob_patterns {
            let p: Vec<char> = pat.key.chars().collect();
            if glob_match(&p, &t) {
                return Some(pat.display.clone());
            }
        }
        None
    }

    /// Does `title` contain a **known scam phone number**? Returns the
    /// authored rule on the first match.
    ///
    /// Matching is digits-only on both sides: the title is confusable-folded
    /// (so full-width / look-alike digits normalize to ASCII), letter-for-digit
    /// homoglyphs are folded (`O`→0, `l`→1 via `fold_letter_digits_for_phone`),
    /// every non-digit is dropped — so *any* separator (spaces, dots, middle-dots,
    /// slashes, …) and any combining/invisible char between digits is transparent —
    /// and each rule's digit string is sought as a substring. A curated scam number
    /// is high-confidence evidence wherever it appears, so — unlike the shape-based
    /// `phone_number` heuristic — this does not require the window to look like an
    /// alert. It remains additive (it does not auto-block), consistent with `title:`.
    /// The letter-digit fold keeps this matcher at least as evasion-resistant as the
    /// heuristic path, which has folded `O`/`l` since round 9.
    #[must_use]
    pub fn match_phone(&self, title: &str) -> Option<String> {
        if self.phone_patterns.is_empty() {
            return None;
        }
        // fold_confusables first (non-ASCII look-alikes → ASCII), THEN
        // fold_letter_digits_for_phone ('o'/'O'→'0', 'l'→'1'); same order as the
        // heuristic `contains_phone_number` call site so "1-8OO-555-O1OO" matches a
        // rule authored as "1-800-555-0100". Non-digits (incl. any separator,
        // combining mark, or invisible) are dropped by the digit filter below.
        let folded = crate::confusables::fold_letter_digits_for_phone(
            &crate::confusables::fold_confusables(title),
        );
        let digits: String = folded.chars().filter(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        // Also try the normalized form so that a title showing an international
        // prefix (+81, +44, +61, +1) matches a rule authored in national form.
        let normalized = normalize_phone_digits(&digits);
        self.phone_patterns
            .iter()
            .find(|p| digits.contains(&p.digits) || normalized.contains(&p.digits))
            .map(|p| p.display.clone())
    }

    /// Does `process_name` contain a known rogue-AV pattern? Used by
    /// the scareware detector to flag an installed fake-antivirus
    /// process (as opposed to a one-off web overlay).
    ///
    /// Matching is space-insensitive: a rule `pc protector plus`
    /// matches `PCProtectorPlus.exe`, `pc-protector-plus`, etc., since
    /// vendors write the same product name with and without
    /// separators. We compare after removing spaces, hyphens, and
    /// underscores from both sides.
    #[must_use]
    pub fn match_process(&self, process_name: &str) -> Option<String> {
        let p = squash(process_name);
        self.process_patterns
            .iter()
            .find(|pat| p.contains(&squash(pat)))
            .cloned()
    }
}

/// Normalize a digit-only phone string to its national (non-prefixed) form.
///
/// Strips known international dialing prefixes so that the same number
/// can be authored as `+1 800 555 0100`, `0120 000 000`, or `+81 120 000 000`
/// and still match regardless of how a title formats it (E6):
///
/// | Pattern | Action | Rationale |
/// |---|---|---|
/// | 11 digits starting `1` | strip leading `1` | NANP country code |
/// | 12 digits starting `81` | strip `81` (→ 10d) | Japan (+81), then JP rules apply |
/// | 11 digits starting `44` | strip `44` (→ 9d) | UK (+44) |
/// | 11 digits starting `61` | strip `61` (→ 9d) | Australia (+61) |
///
/// JP note: after stripping `81`, 0120-XXXXXX (toll-free) and 0570-XXXXXX
/// (charged-rate) numbers have their leading `0` intact, so a blocklist entry
/// of `0120-111-222` and a title showing `+81-120-111-222` both normalize to
/// `0120111222` and match correctly.
fn normalize_phone_digits(digits: &str) -> String {
    // NANP: 11 digits, leading "1" (not "11" or "12" etc.) → strip CC.
    // Check NANP first; "1-800-…" (11d, starts '1') must not collide with
    // any two-digit CC that also starts with '1'.
    if digits.len() == 11 && digits.starts_with('1') && !digits.starts_with("11") {
        return digits[1..].to_string();
    }
    // Japan: +81 → 11 digits with leading "81" (0120/0570 are 10d national,
    // +81 drops the leading 0, so +81-120-000-000 = "81120000000", 11 digits).
    // Prepend "0" to restore the national trunk prefix.
    if digits.len() == 11 && digits.starts_with("81") {
        return format!("0{}", &digits[2..]);
    }
    // UK: +44 → 11 digits, leading "44" → strip CC (national is 9–10 digits).
    if digits.len() == 11 && digits.starts_with("44") {
        return digits[2..].to_string();
    }
    // Australia: +61 → 11 digits, leading "61" → strip CC.
    if digits.len() == 11 && digits.starts_with("61") {
        return digits[2..].to_string();
    }
    digits.to_string()
}

/// Full-string glob matcher.  `*` matches any sequence of chars (including
/// none); `?` matches exactly one char.  Both `pattern` and `text` are slices
/// of pre-normalized `char` values.
///
/// Algorithm: single-pass with backtrack pointers (`star_pi`, `star_ti`).
/// O(m × n) worst-case (a long `*`-chain against a long text) but both are
/// bounded by window-title lengths in practice (≤ 500 chars), so stack depth
/// and runtime are negligible.
fn glob_match(pattern: &[char], text: &[char]) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    // Position of the last `*` in pattern and the text index when we committed to it.
    let mut star_pi = usize::MAX;
    let mut star_ti = usize::MAX;
    loop {
        if ti < text.len() {
            if pi < pattern.len() && pattern[pi] == '*' {
                star_pi = pi;
                star_ti = ti;
                pi += 1;
                continue;
            }
            if pi < pattern.len() && (pattern[pi] == '?' || pattern[pi] == text[ti]) {
                pi += 1;
                ti += 1;
                continue;
            }
            // Mismatch: backtrack to the last `*` and try matching one more char.
            if star_pi != usize::MAX {
                star_ti += 1;
                ti = star_ti;
                pi = star_pi + 1;
                continue;
            }
            return false;
        }
        // ti == text.len(): consume trailing `*`s then check exhaustion.
        while pi < pattern.len() && pattern[pi] == '*' {
            pi += 1;
        }
        return pi == pattern.len();
    }
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Lower-case and remove separators (space, hyphen, underscore) so
/// product names match regardless of how they're written.
fn squash(s: &str) -> String {
    // Defeat the same evasions as the host pipeline: drop zero-width / BiDi and
    // combining characters, then fold homoglyphs (Cyrillic / Greek / Coptic /
    // Armenian / full-width / … → ASCII via `fold_char`) so a rogue-AV process
    // named with look-alikes ("РСProtector", Cyrillic Р/С) still matches its
    // curated rule. Then lower-case and remove the separators vendors vary
    // (space / hyphen / underscore). The digit→letter typosquat folding used for
    // *hosts* is intentionally NOT applied here: process names legitimately
    // contain digits (win32, mp3, x264, vlc) and folding them (0→o, 1→l, …) would
    // corrupt the comparison for no realistic gain.
    let s = crate::confusables::strip_invisibles(s);
    let s = crate::confusables::strip_combining_marks(&s);
    crate::confusables::fold_confusables(&s)
        .to_ascii_lowercase()
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '_'))
        .collect()
}

/// Extract the host from a URL-ish string. Accepts bare hosts too.
/// `http://a.example/x?y` → `a.example`; `a.example` → `a.example`.
/// Lower-cased and `Option`-wrapped (`None` for an empty host).
#[must_use]
pub(crate) fn host_of(url: &str) -> Option<String> {
    let host = host_str(url.trim()).to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Borrowing host extractor: scheme, path, userinfo, and `:port` all
/// stripped, returning a sub-slice of the input. The single source of
/// truth for "what is the host of this URL" across the crate — shared by
/// [`host_of`] (which additionally lower-cases and `Option`-wraps) and by
/// `lib::url_host` / `lib::signature`. Not lower-cased, so callers that
/// must see the raw host (mixed-script / homoglyph detection on the raw
/// bytes) use this directly. Uses the **first** `://` and stops the
/// authority at the first `/?#`, so a `://` inside a query string can't
/// hijack the host.
#[must_use]
pub(crate) fn host_str(url: &str) -> &str {
    let after = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => url,
    };
    let authority = after.split(['/', '?', '#']).next().unwrap_or(after);
    let no_userinfo = authority.rsplit('@').next().unwrap_or(authority);
    // IPv6 literal authority — "[::1]" or "[::1]:8080" — must not be split
    // on its inner ':'; the host is the bracketed part (brackets kept, so
    // both rule and URL sides extract identically).
    if let Some(rest) = no_userinfo.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            return &no_userinfo[..=close + 1];
        }
    }
    no_userinfo.split(':').next().unwrap_or(no_userinfo)
}

/// Normalize a host rule the same way `host_of` normalizes a URL, so
/// `host: http://Evil.Example/` and `host: evil.example` are equal.
fn normalize_host(raw: &str) -> Option<String> {
    host_of(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_and_title_and_bare() {
        let rs = Ruleset::parse(
            "# a comment\n\
             host: Evil.Example\n\
             title: You Have Won\n\
             bare-host.example\n\
             \n",
        );
        assert_eq!(rs.host_count(), 2); // evil.example + bare-host.example
        assert_eq!(rs.title_count(), 1);
    }

    #[test]
    fn host_match_is_case_insensitive() {
        let rs = Ruleset::from_lines(&["host: evil.example"]);
        assert_eq!(
            rs.match_host("HTTP://Evil.Example/path"),
            Some("evil.example".to_string())
        );
    }

    #[test]
    fn subdomain_matches_registered_host() {
        let rs = Ruleset::from_lines(&["host: evil.example"]);
        assert_eq!(
            rs.match_host("http://ads.tracker.evil.example/x"),
            Some("evil.example".to_string())
        );
    }

    #[test]
    fn unrelated_host_does_not_match() {
        let rs = Ruleset::from_lines(&["host: evil.example"]);
        assert!(rs.match_host("https://good.example/").is_none());
        // Must not match a host that merely *contains* the string.
        assert!(rs.match_host("https://notevil.example/").is_none());
    }

    #[test]
    fn title_substring_match() {
        let rs = Ruleset::from_lines(&["title: you have won"]);
        assert_eq!(
            rs.match_title("CONGRATULATIONS! You Have Won a prize"),
            Some("you have won".to_string())
        );
        assert!(rs.match_title("ordinary window").is_none());
    }

    #[test]
    fn title_pattern_with_letter_adjacent_digit_matches_symmetrically() {
        // Regression: patterns are normalized at parse time the same
        // way titles are, so a digit-in-word pattern ("win32",
        // "office365") still matches a title that literally contains it
        // — the title side gets leet-folded, and now the pattern does
        // too. Without symmetric normalization this silently never fired.
        let rs = Ruleset::from_lines(&["title: win32 error", "title: office365"]);
        assert!(rs.match_title("WIN32 ERROR detected").is_some());
        assert!(rs.match_title("office365 login page").is_some());
    }

    #[test]
    fn title_match_is_robust_to_leet_and_invisibles_on_either_side() {
        // Clean pattern matches a leet + zero-width title.
        let rs = Ruleset::from_lines(&["title: your computer is infected"]);
        assert!(rs
            .match_title("Y\u{200B}our c0mputer is 1nfected")
            .is_some());
        // And a pattern written in leet matches a clean title (symmetry).
        let rs2 = Ruleset::from_lines(&["title: v1rus"]);
        assert!(rs2.match_title("virus found on your pc").is_some());
    }

    #[test]
    fn title_match_is_robust_to_unicode_space_separators() {
        // A multi-word blocklist phrase (ASCII spaces) must still match a title
        // whose word separators are visually-identical Unicode spaces — NBSP,
        // ideographic, narrow-NBSP, em space — a real evasion against phrase
        // matching that leaves the rendered text unchanged.
        let rs = Ruleset::from_lines(&["title: your computer is infected"]);
        assert!(
            rs.match_title("your\u{00A0}computer\u{00A0}is\u{00A0}infected")
                .is_some(),
            "NBSP-separated title must match the ASCII-spaced rule"
        );
        assert!(
            rs.match_title("your\u{3000}computer\u{202F}is\u{2003}infected")
                .is_some(),
            "mixed Unicode-space separators must match"
        );
    }

    #[test]
    fn comment_stripping() {
        let rs = Ruleset::from_lines(&["host: evil.example # inline comment"]);
        assert_eq!(rs.host_count(), 1);
        assert!(rs.match_host("http://evil.example/").is_some());
    }

    #[test]
    fn bare_host_with_port_and_path() {
        let rs = Ruleset::from_lines(&["evil.example"]);
        assert!(rs.match_host("evil.example:8080/foo").is_some());
    }

    #[test]
    fn empty_ruleset_matches_nothing() {
        let rs = Ruleset::default();
        assert!(rs.match_host("http://anything.example/").is_none());
        assert!(rs.match_title("anything at all").is_none());
    }

    #[test]
    fn host_of_handles_userinfo() {
        let rs = Ruleset::from_lines(&["host: evil.example"]);
        assert!(rs.match_host("http://user:pass@evil.example/x").is_some());
    }

    #[test]
    fn typosquat_digit_host_still_matches() {
        // Block rule is the real brand; a digit-typosquat URL must still
        // hit it (micros0ft → microsoft).
        let rs = Ruleset::from_lines(&["host: microsoft-support.example"]);
        let hit = rs.match_host("http://micr0s0ft-support.example/alert");
        assert_eq!(hit.as_deref(), Some("microsoft-support.example"));
    }

    #[test]
    fn homoglyph_host_still_matches() {
        // Cyrillic о in the host shouldn't dodge the blocklist.
        let rs = Ruleset::from_lines(&["host: paypal-secure.example"]);
        // "paypа1-secure" uses Cyrillic а (U+0430) and digit 1.
        let hit = rs.match_host("https://paypа1-secure.example/login");
        assert_eq!(hit.as_deref(), Some("paypal-secure.example"));
    }

    #[test]
    fn combining_mark_host_still_matches() {
        // Regression: combining-mark stripping reached the title pipeline
        // (Round 5) but not the host pipeline. A homograph host annotated with
        // a combining diacritic (U+0337 overlay on the 'l') must not dodge the
        // blocklist now that match_host shares the title pipeline's mark strip.
        let rs = Ruleset::from_lines(&["host: paypal-secure.example"]);
        let hit = rs.match_host("https://paypa\u{0337}l-secure.example/login");
        assert_eq!(hit.as_deref(), Some("paypal-secure.example"));
        // Acute accent (nearly invisible in a domain) is also stripped.
        let hit2 = rs.match_host("https://paypa\u{0301}l-secure.example/login");
        assert_eq!(hit2.as_deref(), Some("paypal-secure.example"));
    }

    #[test]
    fn combining_mark_host_does_not_false_match() {
        // The mark strip must not conjure a match for an unrelated host.
        let rs = Ruleset::from_lines(&["host: paypal-secure.example"]);
        assert!(rs
            .match_host("https://git\u{0337}hub.com/user/repo")
            .is_none());
    }

    #[test]
    fn folded_subdomain_still_matches() {
        // Folding composes with the subdomain-suffix rule.
        // "evi1" → digit 1→l → "evil".
        let rs = Ruleset::from_lines(&["host: evil.example"]);
        assert!(rs.match_host("http://ads.evi1.example/x").is_some());
    }

    #[test]
    fn benign_host_not_falsely_matched() {
        // Folding must not create spurious matches: a normal host that
        // doesn't fold to any rule stays clean.
        let rs = Ruleset::from_lines(&["host: microsoft-support.example"]);
        assert!(rs.match_host("https://github.com/user/repo").is_none());
        assert!(rs.match_host("https://example.org/").is_none());
    }

    #[test]
    fn phone_rule_matches_regardless_of_separators() {
        let rs = Ruleset::from_lines(&["phone: 1-800-555-0100"]);
        assert_eq!(rs.phone_count(), 1);
        // Same number, different formatting in the title.
        assert_eq!(
            rs.match_phone("call (800) 555 0100 now").as_deref(),
            Some("1-800-555-0100")
        );
        // Full-width digits fold to ASCII before matching.
        assert!(rs
            .match_phone("\u{FF11}\u{FF18}\u{FF10}\u{FF10}5550100")
            .is_some());
        // An unrelated number does not match.
        assert!(rs.match_phone("order 12345678 shipped").is_none());
    }

    #[test]
    fn phone_rule_matches_letter_for_digit_homoglyphs() {
        // Round 27: a curated scam number written with letter-O for 0 and
        // letter-l for 1 must still match — match_phone now folds O→0, l→1
        // (parity with the contains_phone_number heuristic path).
        let rs = Ruleset::from_lines(&["phone: 1-800-555-0100"]);
        assert!(
            rs.match_phone("call 1-8OO-555-O1OO immediately").is_some(),
            "letter-O/l substituted known number must match"
        );
        // Middle-dot separators are also transparent (dropped as non-digits).
        assert!(
            rs.match_phone("1\u{00B7}800\u{00B7}555\u{00B7}0100")
                .is_some(),
            "middle-dot-spread known number must match"
        );
    }

    #[test]
    fn short_phone_rule_is_rejected() {
        // < 7 digits would be an over-broad rule; it must be dropped.
        let rs = Ruleset::from_lines(&["phone: 12345"]);
        assert_eq!(rs.phone_count(), 0);
    }

    #[test]
    fn match_process_is_separator_and_case_insensitive() {
        let rs = Ruleset::from_lines(&["process: pc protector plus"]);
        assert_eq!(rs.process_count(), 1);
        // Vendors write the same name with/without separators and casing.
        assert!(rs.match_process("PCProtectorPlus.exe").is_some());
        assert!(rs.match_process("pc-protector-plus").is_some());
        assert!(rs.match_process("PC_Protector_Plus").is_some());
        // An unrelated process does not match.
        assert!(rs.match_process("notepad.exe").is_none());
    }

    #[test]
    fn match_process_folds_homoglyph_process_names() {
        // Round 28: a rogue-AV binary named with Cyrillic look-alikes renders
        // identically to the ASCII name but must still match the curated rule.
        let rs = Ruleset::from_lines(&["process: pc protector plus"]);
        // "РСProtectorPlus" — Cyrillic Р (U+0420) and С (U+0421) for P and C.
        assert!(
            rs.match_process("\u{0420}\u{0421}ProtectorPlus.exe")
                .is_some(),
            "Cyrillic-homoglyph process name must match the ASCII rule"
        );
    }

    #[test]
    fn match_process_preserves_digits() {
        // Digits in legit process names must NOT be folded to letters (unlike
        // the host pipeline), so digit-bearing names are compared faithfully.
        let rs = Ruleset::from_lines(&["process: win32 helper"]);
        assert!(rs.match_process("Win32Helper.exe").is_some());
        // A different digit must not collide (no 3→e / 0→o folding here).
        let rs2 = Ruleset::from_lines(&["process: scan0matic"]);
        assert!(rs2.match_process("scan0matic.exe").is_some());
        assert!(rs2.match_process("scanomatic.exe").is_none());
    }

    #[test]
    fn composite_rule_parses_name_weight_conditions() {
        let rs = Ruleset::from_lines(&[
            "composite: coercive_overlay 90 fullscreen topmost no_close_button blocks_input",
        ]);
        assert_eq!(rs.composite_count(), 1);
        let rule = &rs.composite_rules()[0];
        assert_eq!(rule.name, "coercive_overlay");
        assert_eq!(rule.weight, 90);
        assert_eq!(rule.conditions.len(), 4);
        assert!(rule.conditions.contains(&CompositeCondition::Fullscreen));
        assert!(rule.conditions.contains(&CompositeCondition::Topmost));
        assert!(rule.conditions.contains(&CompositeCondition::NoCloseButton));
        assert!(rule.conditions.contains(&CompositeCondition::BlocksInput));
    }

    #[test]
    fn composite_rule_with_has_signal_conditions() {
        let rs = Ruleset::from_lines(&["composite: phone_alert 60 has_phone_number alert_shaped"]);
        let rule = &rs.composite_rules()[0];
        assert!(rule
            .conditions
            .contains(&CompositeCondition::HasPhoneNumber));
        assert!(rule.conditions.contains(&CompositeCondition::AlertShaped));
    }

    #[test]
    fn composite_rule_unknown_condition_skipped() {
        // Unknown condition names are silently skipped; the rule is kept
        // if it has at least one recognized condition.
        let rs = Ruleset::from_lines(&[
            "composite: partial_rule 50 fullscreen totally_unknown_cond topmost",
        ]);
        assert_eq!(rs.composite_count(), 1);
        assert_eq!(rs.composite_rules()[0].conditions.len(), 2);
    }

    #[test]
    fn composite_rule_all_unknown_conditions_drops_rule() {
        // A rule with zero recognized conditions is dropped (malformed).
        let rs = Ruleset::from_lines(&["composite: bad_rule 50 unknown1 unknown2"]);
        assert_eq!(rs.composite_count(), 0);
    }

    #[test]
    fn composite_rule_missing_weight_drops_rule() {
        // No weight → dropped (malformed line, never abort).
        let rs = Ruleset::from_lines(&["composite: no_weight fullscreen topmost"]);
        // "fullscreen" would be parsed as weight (not a number) → rule dropped.
        assert_eq!(rs.composite_count(), 0);
    }

    #[test]
    fn malformed_composite_does_not_abort_load() {
        // A malformed composite line among valid rules should not abort.
        let rs = Ruleset::from_lines(&[
            "host: evil.example",
            "composite: oops",
            "composite: also_oops 50", // weight but no conditions
            "title: your computer is infected",
        ]);
        assert_eq!(rs.host_count(), 1);
        assert_eq!(rs.title_count(), 1);
        assert_eq!(rs.composite_count(), 0); // both oops rules dropped
    }

    #[test]
    fn ipv6_literal_host_is_not_mangled() {
        // Regression: the ':' inside an IPv6 literal must not split the
        // host into "[" — the bracketed literal is the host. A rule and a
        // URL for the same literal (with/without port) must match.
        assert_eq!(host_str("http://[2001:db8::1]:8080/x"), "[2001:db8::1]");
        assert_eq!(host_str("http://[::1]/path"), "[::1]");
        let rs = Ruleset::from_lines(&["host: [::1]"]);
        assert!(rs.match_host("http://[::1]:8080/alert").is_some());
        // An ordinary host with a port is still parsed correctly.
        assert_eq!(host_str("http://evil.example:443/x"), "evil.example");
    }

    // ── E6: International phone number normalization ─────────────────

    #[test]
    fn normalize_phone_nanp_strips_leading_1() {
        // 11-digit NANP (leading 1) → 10-digit national number.
        assert_eq!(normalize_phone_digits("18005550100"), "8005550100");
        // 10-digit (no country code) → unchanged.
        assert_eq!(normalize_phone_digits("8005550100"), "8005550100");
    }

    #[test]
    fn normalize_phone_japan_strips_country_code() {
        // Japan +81: 0120-000-000 national = "0120000000" (10d).
        // +81 drops the leading 0, so +81-120-000-000 = "81120000000" (11d).
        // normalize_phone_digits prepends "0" after stripping "81" → "0120000000".
        assert_eq!(normalize_phone_digits("81120000000"), "0120000000");
        // 0570 charged-rate number.
        assert_eq!(normalize_phone_digits("81570000000"), "0570000000");
    }

    #[test]
    fn normalize_phone_uk_strips_country_code() {
        // UK +44: 11 digits starting 44 → strip to 9 (national).
        assert_eq!(normalize_phone_digits("44800000000"), "800000000");
    }

    #[test]
    fn normalize_phone_australia_strips_country_code() {
        // Australia +61: 11 digits starting 61 → strip to 9.
        assert_eq!(normalize_phone_digits("61800000000"), "800000000");
    }

    #[test]
    fn normalize_phone_unrecognized_is_unchanged() {
        // A 9-digit number with no recognized prefix → returned as-is.
        assert_eq!(normalize_phone_digits("123456789"), "123456789");
        // An 11-digit number NOT starting with 1, 44, or 61 → unchanged.
        assert_eq!(normalize_phone_digits("55800000000"), "55800000000");
    }

    #[test]
    fn phone_rule_matches_jp_international_format_in_title() {
        // Operator writes the JP toll-free as "0120-111-222" (national);
        // title shows it as "+81 120 111 222" (international). Should match.
        let rs = Ruleset::from_lines(&["phone: 0120-111-222"]);
        // After normalize: rule key = "0120111222", title digits = "81120111222" → strip "81" → "0120111222".
        // match_phone strips all non-digit and then does substring match in folded digits.
        // The title "+81 120 111 222" contains "81120111222" as digits; we need the
        // normalized KEY "0120111222" to be a substring of "81120111222" — it IS.
        assert!(
            rs.match_phone("+81 120 111 222").is_some(),
            "JP international format should match national-format rule"
        );
        // The national format must also still work.
        assert!(rs.match_phone("0120-111-222").is_some());
        assert!(rs.match_phone("0120 111 222").is_some());
    }

    // ── F6: glob title patterns ──────────────────────────────────────

    #[test]
    fn glob_count_reflects_parsed_rules() {
        let rs = Ruleset::from_lines(&[
            "glob: *infected*",
            "glob: WARNING: ?",
            "title: ordinary substring",
        ]);
        assert_eq!(rs.glob_count(), 2);
        assert_eq!(rs.title_count(), 1);
    }

    #[test]
    fn glob_exact_match() {
        let rs = Ruleset::from_lines(&["glob: your computer is infected"]);
        assert_eq!(
            rs.match_title_glob("your computer is infected"),
            Some("your computer is infected".to_string())
        );
        // Must NOT match a title that only contains the phrase (not full-string).
        assert!(rs
            .match_title_glob("WARNING: your computer is infected!")
            .is_none());
    }

    #[test]
    fn glob_star_both_ends_behaves_like_contains() {
        // `glob: *phrase*` is equivalent to `title: phrase`.
        let rs = Ruleset::from_lines(&["glob: *your computer is infected*"]);
        assert!(rs
            .match_title_glob("⚠ YOUR COMPUTER IS INFECTED ⚠")
            .is_some());
        assert!(rs.match_title_glob("your computer is infected").is_some());
        assert!(rs.match_title_glob("call support now").is_none());
    }

    #[test]
    fn glob_question_mark_matches_any_single_char() {
        let rs = Ruleset::from_lines(&["glob: ?irus found"]);
        assert!(rs.match_title_glob("virus found").is_some());
        assert!(rs.match_title_glob("xirus found").is_some());
        // Zero chars for `?` → no match.
        assert!(rs.match_title_glob("irus found").is_none());
        // Two chars for `?` → no match.
        assert!(rs.match_title_glob("xvirus found").is_none());
    }

    #[test]
    fn glob_star_middle_skips_arbitrary_content() {
        let rs = Ruleset::from_lines(&["glob: your*infected"]);
        assert!(rs.match_title_glob("your computer is infected").is_some());
        assert!(rs.match_title_glob("your phone is infected").is_some());
        assert!(rs.match_title_glob("your infected").is_some()); // * = zero chars
        assert!(rs.match_title_glob("your computer").is_none());
    }

    #[test]
    fn glob_empty_pattern_drops_silently() {
        let rs = Ruleset::from_lines(&["glob:   "]);
        assert_eq!(rs.glob_count(), 0);
    }

    #[test]
    fn glob_pattern_normalized_symmetrically() {
        // Pattern with leet: `c0mputer` → normalized to `computer`.
        // Title with zero-width + uppercase: matches.
        let rs = Ruleset::from_lines(&["glob: *c0mputer*infected*"]);
        assert!(rs
            .match_title_glob("your\u{200B}COMPUTER is infected!")
            .is_some());
        // Pattern with Cyrillic confusable in the display text: folds to
        // the same skeleton as the ASCII equivalent.
        let rs2 = Ruleset::from_lines(&["glob: *раypаl*"]);
        assert!(rs2.match_title_glob("verify your paypal account").is_some());
    }

    #[test]
    fn glob_match_returns_display_form() {
        let rs = Ruleset::from_lines(&["glob: *YOUR COMPUTER IS INFECTED*"]);
        // The display is stored as lowercase.
        assert_eq!(
            rs.match_title_glob("your computer is infected"),
            Some("*your computer is infected*".to_string())
        );
    }

    #[test]
    fn glob_empty_ruleset_matches_nothing() {
        let rs = Ruleset::default();
        assert!(rs.match_title_glob("any title at all").is_none());
    }

    // ── C5-3: weight overrides ────────────────────────────────────────

    #[test]
    fn weight_override_parses_and_returns() {
        let rs = Ruleset::from_lines(&[
            "weight: phone_number 99",
            "weight: mixed_script 0",
            "weight: user_initiated -10",
        ]);
        assert_eq!(rs.weight_override_count(), 3);
        assert_eq!(rs.weight_of("phone_number", 35), 99);
        assert_eq!(rs.weight_of("mixed_script", 30), 0);
        assert_eq!(rs.weight_of("user_initiated", -40), -10);
    }

    #[test]
    fn weight_of_falls_back_to_default_when_no_override() {
        let rs = Ruleset::default();
        assert_eq!(rs.weight_of("phone_number", 35), 35);
        assert_eq!(rs.weight_of("nonexistent_signal", 42), 42);
    }

    #[test]
    fn weight_override_is_case_normalised() {
        let rs = Ruleset::from_lines(&["weight: Phone_Number 50"]);
        // Signal names are lower-cased at parse time.
        assert_eq!(rs.weight_of("phone_number", 35), 50);
    }

    #[test]
    fn weight_override_malformed_value_is_silently_dropped() {
        let rs = Ruleset::from_lines(&["weight: phone_number not_a_number"]);
        assert_eq!(rs.weight_override_count(), 0);
        // Falls back to default.
        assert_eq!(rs.weight_of("phone_number", 35), 35);
    }

    #[test]
    fn weight_override_missing_value_is_dropped() {
        let rs = Ruleset::from_lines(&["weight: phone_number"]);
        assert_eq!(rs.weight_override_count(), 0);
    }

    #[test]
    fn weight_override_is_clamped_to_sane_bound() {
        // A fat-fingered or hostile huge weight is clamped to ±MAX_ABS_WEIGHT,
        // so two co-firing overridden signals can never overflow the i32 score
        // accumulation in classify().
        let rs = Ruleset::from_lines(&[
            "weight: fullscreen 2000000000",
            "weight: topmost -2000000000",
        ]);
        assert_eq!(rs.weight_of("fullscreen", 30), MAX_ABS_WEIGHT);
        assert_eq!(rs.weight_of("topmost", 15), -MAX_ABS_WEIGHT);
    }

    #[test]
    fn composite_weight_is_clamped_to_sane_bound() {
        let rs = Ruleset::from_lines(&["composite: huge 2000000000 fullscreen topmost"]);
        let rule = rs
            .composite_rules()
            .iter()
            .find(|r| r.name == "huge")
            .expect("composite rule parsed");
        assert_eq!(rule.weight, MAX_ABS_WEIGHT);
    }

    #[test]
    fn composite_rule_parses_e_series_conditions() {
        // All E-series signal conditions must parse correctly.
        let rs = Ruleset::from_lines(&[
            "composite: crypto_phone_block 50 has_crypto_drain_lure has_phone_number",
            "composite: gov_wallet 60 has_authority_lure has_crypto_drain_lure",
            "composite: scanner_phone 45 has_fake_scanner_cue has_phone_number",
            "composite: prize_check 30 has_prize_lure alert_shaped",
            "composite: download_check 30 has_download_trap_lure unsolicited",
            "composite: cred_harvest 40 has_credential_harvest_cue has_phone_number",
            "composite: sub_check 25 has_subscription_lure has_blocklist_title",
            "composite: share_check 30 has_screen_share_lure has_phone_number",
            "composite: qr_phone 45 has_qr_code_lure has_phone_number",
            "composite: ip_alarm_phone 45 has_ip_alarm_lure has_phone_number",
            "composite: gift_card_phone 50 has_gift_card_demand has_phone_number",
            "composite: refund_phone 45 has_refund_scam_cue has_phone_number",
            "composite: national_id_phone 50 has_national_id_alarm has_phone_number",
            "composite: bank_fraud_phone 50 has_bank_account_alarm has_phone_number",
        ]);
        assert_eq!(rs.composite_count(), 14);
        let names: Vec<&str> = rs
            .composite_rules()
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert!(names.contains(&"crypto_phone_block"));
        assert!(names.contains(&"gov_wallet"));
        // Verify specific condition parsing
        let crypto_rule = rs
            .composite_rules()
            .iter()
            .find(|r| r.name == "crypto_phone_block")
            .unwrap();
        assert!(crypto_rule
            .conditions
            .contains(&CompositeCondition::HasCryptoDrainLure));
        assert!(crypto_rule
            .conditions
            .contains(&CompositeCondition::HasPhoneNumber));
        // E22/E23 conditions parse correctly
        let qr_rule = rs
            .composite_rules()
            .iter()
            .find(|r| r.name == "qr_phone")
            .unwrap();
        assert!(qr_rule
            .conditions
            .contains(&CompositeCondition::HasQrCodeLure));
        let ip_rule = rs
            .composite_rules()
            .iter()
            .find(|r| r.name == "ip_alarm_phone")
            .unwrap();
        assert!(ip_rule
            .conditions
            .contains(&CompositeCondition::HasIpAlarmLure));
        // E26 condition parses correctly
        let gc_rule = rs
            .composite_rules()
            .iter()
            .find(|r| r.name == "gift_card_phone")
            .unwrap();
        assert!(gc_rule
            .conditions
            .contains(&CompositeCondition::HasGiftCardDemand));
        // E27 condition parses correctly
        let refund_rule = rs
            .composite_rules()
            .iter()
            .find(|r| r.name == "refund_phone")
            .unwrap();
        assert!(refund_rule
            .conditions
            .contains(&CompositeCondition::HasRefundScamCue));
        // E28 condition parses correctly
        let national_id_rule = rs
            .composite_rules()
            .iter()
            .find(|r| r.name == "national_id_phone")
            .unwrap();
        assert!(national_id_rule
            .conditions
            .contains(&CompositeCondition::HasNationalIdAlarm));
        // E29 condition parses correctly
        let bank_rule = rs
            .composite_rules()
            .iter()
            .find(|r| r.name == "bank_fraud_phone")
            .unwrap();
        assert!(bank_rule
            .conditions
            .contains(&CompositeCondition::HasBankAccountAlarm));
    }
}
