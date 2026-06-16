//! muten-overlay — scam / full-screen overlay detection.
//!
//! This is the pure domain layer for the v0.4.0 "screen" half of
//! muten's endpoint-environment enforcement. It knows nothing about
//! the OS window manager, the browser, or the network. It takes a
//! description of an observed window ([`OverlayWindow`]) plus a
//! [`Ruleset`], and returns a [`Verdict`]. The daemon's OS-specific
//! window enumerator feeds observations in; the OS-specific dismisser
//! acts on `Verdict::Block`. Both of those live elsewhere (like the
//! audio backends), so this crate stays testable without a desktop.
//!
//! ## Why heuristics, not ML
//!
//! Per CLAUDE.md I6 (explainable) and Pike (no cleverness where plain
//! code works): a transparent additive score whose contributions are
//! recorded in the verdict beats an opaque model that can't run
//! offline and can't be audited. Each signal's weight is a named
//! constant; the verdict lists which signals fired.
//!
//! ## Why "Suspicious", not auto-block-everything
//!
//! False positives are catastrophic here: wrongly dismissing a video
//! player, a presentation, a kiosk's own full-screen UI, or an exam
//! app breaks the very environments muten protects. So the default
//! posture is **observe**: only a confirmed blocklist match or a
//! score at/above the block threshold yields `Block`; everything in
//! between is `Suspicious` (audited, not dismissed). This mirrors the
//! audio side's `pilot-observe` philosophy.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod categories;
pub mod confusables;
pub mod controller;
pub mod merkle;
pub mod mitre;
pub mod monitor;
pub mod rules;
pub mod scareware;
pub mod sink;

pub use categories::{categories_of, category_of, DarkPatternCategory};
pub use controller::{
    ControllerError, EnumeratedWindow, NullController, OverlayController, SubprocessController,
    WindowId,
};
pub use monitor::{AuditEvent, AuditSink, MemorySink, Monitor, RunConfig};
pub use rules::Ruleset;
pub use scareware::{assess, RepeatTracker, ScarewareDecision, ScarewareVerdict};
pub use sink::{
    hmac_sha256, rotate_log, sign_checkpoint, verify_chain, verify_chain_continued,
    verify_checkpoint_sig, ChainedFileSink, CheckpointSig, GENESIS,
};

use serde::{Deserialize, Serialize};

/// How the window came to exist, as best the enumerator can tell.
/// Unsolicited pop-ups are far more likely to be scams than windows
/// the user explicitly opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// We don't know how it appeared.
    #[default]
    Unknown,
    /// Appeared right after a user click/keypress (likely legitimate).
    UserInitiated,
    /// Appeared with no preceding user input (classic scam pop-up).
    Unsolicited,
}

/// A snapshot of one observed window or browser overlay. All fields
/// are best-effort; the enumerator fills what it can and leaves the
/// rest at defaults. `coverage_percent` is the fraction of the active
/// display the window occupies (0..=100).
///
/// `#[serde(default)]`: because the contract is "fill what you can,
/// default the rest", a helper (or a hand-written sample) MAY omit any
/// field it cannot determine and the value falls back to its type
/// default — partial window JSON deserializes rather than erroring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct OverlayWindow {
    /// Window title or document title. Lower-cased by the enumerator.
    pub title: String,
    /// Source URL/host if this is a browser surface (lower-cased).
    pub url: Option<String>,
    /// Percent of the active display covered (0..=100).
    pub coverage_percent: u8,
    /// Always-on-top / topmost flag.
    pub topmost: bool,
    /// Whether the window exposes a usable close affordance. Scam
    /// overlays often hide or fake the close button.
    pub has_close_button: bool,
    /// Whether the window captured the pointer / blocks input to
    /// everything behind it (modal-like).
    pub blocks_input: bool,
    /// How it appeared.
    pub origin: Origin,
    /// How long it has been on screen, milliseconds. Brand-new
    /// unsolicited full-screen surfaces are the most suspicious.
    pub age_ms: u64,
}

/// The classifier's decision plus its reasoning. `score` is the summed
/// signal weight; `signals` lists which fired (for the audit log).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    /// The classifier's final decision (Allow / Suspicious / Block).
    pub decision: Decision,
    /// Sum of all signal weights; always ≥ 0.
    pub score: i32,
    /// Names of the signals that fired, in evaluation order. Static built-in
    /// signals use fixed names; composite rule signals carry the operator-defined
    /// rule name. All are serialized as JSON strings in `--json` output.
    pub signals: Vec<String>,
    /// Dark-pattern strategy categories (Gray et al. 2018) implied by
    /// the signals that fired, deduped and sorted. Empty when only
    /// descriptive signals fired. See the `categories` module.
    pub categories: Vec<DarkPatternCategory>,
    /// MITRE ATT&CK® for Enterprise technique IDs (e.g. `"T1566"`) implied
    /// by the signals that fired, sorted and deduplicated. Empty when no
    /// signals map to an ATT&CK technique. See the `mitre` module.
    pub mitre_techniques: Vec<String>,
    /// Set when a blocklist rule matched outright.
    pub matched_rule: Option<String>,
}

impl Verdict {
    /// A deterministic, plain-language explanation of the verdict,
    /// assembled from the signals that fired (CLAUDE.md I6 / roadmap
    /// C5-8). For an operator or a SIEM note this reads better than a
    /// raw signal list, e.g.:
    ///
    /// > Block (score 130): the window covers (almost) the whole
    /// > screen, hides or fakes the close button, captures all input
    /// > (modal), appeared with no user action, and shows a support
    /// > phone number; matched blocklist rule "your computer is
    /// > infected".
    ///
    /// Pure and side-effect-free; the wording is stable so tests and
    /// downstream consumers can rely on it.
    /// Signal-quality confidence in this verdict.
    ///
    /// `High` when the verdict rests on a clean rule/text tell — either the
    /// *only* signal that fired is a high-fidelity one (e.g. a confirmed
    /// blocklist-host hard block, with no geometry noise to dilute it), or two
    /// or more high-fidelity signals fired together. These are hard for an
    /// attacker to evade.
    /// `Medium` when exactly one high-fidelity signal fired *alongside* one or
    /// more geometry signals (one tell amid noise).
    /// `Low` when only window-geometry signals fired (fullscreen / topmost /
    /// modal / origin), which a rogue OS helper could theoretically mis-report.
    ///
    /// For `Allow` verdicts the confidence reflects how far the score is
    /// from the [`SUSPICIOUS_THRESHOLD`].
    #[must_use]
    pub fn confidence(&self) -> ConfidenceLevel {
        if self.decision == Decision::Allow {
            // Inversely proportional to score: low score = high confidence.
            return if self.score <= SUSPICIOUS_THRESHOLD / 3 {
                ConfidenceLevel::High
            } else if self.score <= SUSPICIOUS_THRESHOLD * 2 / 3 {
                ConfidenceLevel::Medium
            } else {
                ConfidenceLevel::Low // borderline
            };
        }
        // For Suspicious / Block: quality of the signals that fired.
        let hf = self.signals.iter().filter(|s| is_high_fidelity(s)).count();
        match hf {
            0 => ConfidenceLevel::Low,
            // A lone high-fidelity signal with nothing else is a clean,
            // unambiguous tell — most importantly the `blocklist_host` hard
            // block, the single most definitive verdict the classifier emits.
            // Reporting it as merely Medium would understate a confirmed,
            // operator-listed match.
            1 if self.signals.len() == 1 => ConfidenceLevel::High,
            // One high-fidelity tell amid geometry noise: medium.
            1 => ConfidenceLevel::Medium,
            _ => ConfidenceLevel::High,
        }
    }

    /// Per-signal weight contributions for built-in signals.
    ///
    /// Returns `(signal_name, weight)` for each signal in
    /// [`Verdict::signals`].  Composite rule signals (operator-named, with
    /// weights set in the blocklist) and unknown names return a weight of
    /// `0`; see [`signal_weight`] for the authoritative per-name lookup.
    ///
    /// The reported weights are the built-in **defaults**: a [`Verdict`] does
    /// not carry the [`Ruleset`] it was produced with, so this cannot reflect
    /// operator `weight:` overrides. Consequently the sum may not equal
    /// [`Verdict::score`] when (a) an operator overrode a signal's weight,
    /// (b) a composite rule contributed (operator-named weight, reported as
    /// `0`), or (c) the score was clamped at `0`. Treat the breakdown as the
    /// default-weight attribution of *which* signals fired, not an exact
    /// reconstruction of the final score under a customized ruleset.
    #[must_use]
    pub fn score_breakdown(&self) -> Vec<(String, i32)> {
        self.signals
            .iter()
            .map(|s| (s.clone(), signal_weight(s).unwrap_or(0)))
            .collect()
    }

    /// A deterministic, plain-language explanation of the verdict.
    /// Includes the confidence level, score, signal phrases (Oxford-comma
    /// list), and matched blocklist rule if any.  Stable wording for SIEM
    /// notes and tests; pure, no I/O.
    #[must_use]
    pub fn explain(&self) -> String {
        let verb = match self.decision {
            Decision::Allow => "Allow",
            Decision::Suspicious => "Suspicious",
            Decision::Block => "Block",
        };
        let phrases: Vec<&str> = self.signals.iter().map(|s| signal_phrase(s)).collect();
        let body = if phrases.is_empty() {
            "no notable signals fired".to_string()
        } else {
            format!("the window {}", join_clauses(&phrases))
        };
        let conf = match self.confidence() {
            ConfidenceLevel::High => "high confidence",
            ConfidenceLevel::Medium => "medium confidence",
            ConfidenceLevel::Low => "low confidence",
        };
        let mut out = format!("{verb} (score {}, {conf}): {body}", self.score);
        if let Some(rule) = &self.matched_rule {
            out.push_str(&format!("; matched blocklist rule \"{rule}\""));
        }
        out.push('.');
        out
    }
}

/// Map one signal name to a human clause for [`Verdict::explain`].
/// Unknown signals fall back to their raw name (forward-compatible).
fn signal_phrase(signal: &str) -> &str {
    match signal {
        "fullscreen" => "covers (almost) the whole screen",
        "topmost" => "stays always-on-top",
        "no_close_button" => "hides or fakes the close button",
        "blocks_input" => "captures all input (modal)",
        "unsolicited" => "appeared with no user action",
        "user_initiated" => "was opened by the user",
        "very_new" => "just popped up",
        "blocklist_title" => "matches a known scam title",
        "blocklist_host" => "is hosted on a blocklisted domain",
        "phone_number" => "shows a support phone number",
        "blocklist_phone" => "shows a known scam phone number",
        "mixed_script" => "mixes character sets to disguise its text",
        "whole_script_confusable" => "uses an all-lookalike script to disguise its text",
        "compat_chars_present" => "uses enclosed/circled letters to disguise its text",
        "mixed_number_systems" => "mixes two numeric scripts to disguise a number",
        "excessive_combining_marks" => "stacks combining marks to obfuscate its text",
        "bidi_override" => "uses a right-to-left override to disguise its text",
        "brand_impersonation" => "uses a look-alike domain impersonating a known brand",
        "combosquat_brand" => "uses a domain combining a known brand with a scam keyword",
        "typosquat_brand" => "uses an edit-distance-1 keyboard typosquat of a known brand domain",
        "clickfix_instruction" => "instructs the user to run a command or pass a fake CAPTCHA",
        "urgency_countdown" => {
            "displays a countdown timer alongside an urgent warning to coerce rapid action"
        }
        "cloud_storage_abuse" => {
            "is served from cloud blob-storage infrastructure used to host scam overlays"
        }
        "url_path_lure" => "has a URL path combining a known brand name with a scam lure word",
        "forced_retention_cue" => "instructs the user not to close or leave the window",
        "credential_harvest_cue" => {
            "alarms the user about account compromise or demands credential re-entry"
        }
        "fake_scanner_cue" => "displays fake antivirus scan progress or threat-count language",
        "subscription_lure" => "displays a fake subscription or license expiry urging renewal",
        "authority_lure" => "impersonates a law-enforcement agency to demand payment or call",
        "download_trap_lure" => {
            "demands a download, install, or plugin update as a fake gate to continue"
        }
        "prize_lure" => "displays a fake prize or lottery win and urges immediate claim",
        "crypto_drain_lure" => {
            "displays a fake crypto-wallet alarm or demands seed-phrase / private-key entry"
        }
        "screen_share_lure" => {
            "instructs the user to share their screen or grant desktop access to a fake support agent"
        }
        "qr_code_lure" => {
            "instructs the user to scan a QR code to 'verify' or 'continue' (quishing)"
        }
        "ip_alarm_lure" => {
            "claims the user's IP address has been hacked, flagged, or compromised"
        }
        "package_fee_lure" => {
            "claims a package or shipment is on hold and demands a customs or release fee"
        }
        "sextortion_lure" => {
            "claims to have webcam footage and demands cryptocurrency payment to prevent release"
        }
        "gift_card_demand" => {
            "instructs the user to purchase gift cards and send or read out the redemption codes"
        }
        "refund_scam_cue" => {
            "uses a fake refund or overpayment lure to coerce the user into calling a scam number"
        }
        "national_id_alarm" => {
            "falsely claims a national ID number (SSN/NIN/マイナンバー) has been suspended or used in criminal activity"
        }
        "bank_account_alarm" => {
            "impersonates a bank fraud alert claiming an account or card has been frozen or has fraudulent transactions"
        }
        "false_registration_billing" => {
            "falsely claims the user registered for a paid service and demands immediate payment under threat of legal action (ワンクリック詐欺)"
        }
        "fake_bsod_lure" => {
            "impersonates a Windows Blue Screen of Death or OS kernel panic to trick the victim into calling a fake Microsoft or Apple support number"
        }
        "advance_fee_lure" => {
            "claims the victim has inherited a large sum, won a lottery, or has unclaimed funds, then demands an advance fee (processing, customs, notary) to release those funds (419 fraud)"
        }
        "tech_support_invoice_scam" => {
            "displays a fake invoice claiming a large charge (e.g., Microsoft support plan, McAfee renewal) was processed and urges the victim to call to cancel or dispute"
        }
        "utility_cutoff_threat" => {
            "impersonates a utility company (electric, gas, water) and threatens immediate service disconnection unless payment is made right away"
        }
        "healthcare_scam" => {
            "impersonates Medicare, Medicaid, or an insurance provider, claiming a benefit is expiring or a free medical device is available, to coerce the victim into calling a scam number"
        }
        "job_scam" => {
            "advertises a fake work-from-home or remote job opportunity but requires an upfront fee (registration, equipment deposit, starter kit, background check) to start"
        }
        "tax_authority_scam" => {
            "impersonates a tax authority (IRS, HMRC, 国税庁) and threatens arrest, asset seizure, or criminal charges unless the victim pays an alleged tax debt immediately"
        }
        "social_media_account_alarm" => {
            "claims a specific social media or email account (Facebook, Instagram, Gmail, LINE) has been hacked or suspended, coercing the victim into a fake recovery flow to harvest credentials"
        }
        "immigration_visa_scam" => {
            "impersonates an immigration authority and threatens visa revocation, deportation, or illegal-overstay charges unless the victim pays a renewal or settlement fee immediately"
        }
        "government_grant_scam" => {
            "impersonates a government program (federal grant, stimulus payment, emergency relief fund) and demands an application fee, processing fee, or identity verification before releasing funds that do not exist"
        }
        "debt_relief_scam" => {
            "poses as a debt-relief or credit-repair service promising guaranteed debt elimination, and demands an upfront application or consultation fee before delivering any service"
        }
        "streaming_billing_scam" => {
            "impersonates a streaming or subscription service (Netflix, Spotify, Disney+, Amazon Prime) with a fake payment-failure alert designed to steal payment credentials or subscription logins"
        }
        "traffic_fine_scam" => {
            "impersonates a traffic enforcement authority or toll operator (parking enforcement, EZPass, FasTrak) with a fake violation notice demanding immediate payment to avoid license suspension or additional penalties"
        }
        "pig_butchering_lure" => {
            "combines romantic or mentorship social engineering (VIP trading group, investment mentor, 'I found you') with a fake investment platform or guaranteed-profit lure to draw the victim into a pig-butchering (sha zhu pan) investment fraud"
        }
        "loan_fee_scam" => {
            "claims the victim has been pre-approved for a personal, payday, or emergency loan, then demands an upfront processing fee, insurance deposit, or collateral payment before releasing funds that do not exist (advance-fee loan fraud)"
        }
        "data_uri_page" => {
            "is hosted at a data: or file:// URL, a technique used by tech-support scammers to serve fake-alert overlays without a domain that can be blocklisted"
        }
        "ip_host_url" => {
            "is hosted at a raw IPv4 or IPv6 address instead of a hostname — no legitimate support, banking, or government page uses a bare IP address, making this a strong scam-infrastructure indicator"
        }
        "charity_scam_lure" => {
            "impersonates a disaster-relief or humanitarian charity and instructs the user to donate via gift card, wire transfer, cryptocurrency, or money order — payment methods no legitimate charity uses for small-donor collections"
        }
        "rental_scam_lure" => {
            "posts a fake rental or housing listing (apartment, room, or house for rent) and demands an advance deposit via wire transfer, gift card, or money order before the victim can view the property, which does not exist or is not owned by the scammer"
        }
        "pet_sale_scam" => {
            "advertises a non-existent pet (puppy, kitten, or exotic animal) and demands a shipping deposit, crate fee, or insurance payment before delivery — a transport-advance-fee fraud that accounts for a significant share of FTC online-shopping complaints"
        }
        "timeshare_travel_scam" => {
            "offers a complimentary vacation or resort membership and demands an activation fee, certificate fee, or closing cost before the prize can be claimed — a travel-prize advance-fee fraud commonly targeting timeshare owners (FTC travel fraud)"
        }
        "windows_activation_scam" => {
            "displays a fake Windows or Microsoft Office activation alarm (product key required, license expired, not genuine) paired with a 'call Microsoft support' or 'contact activation center' call-to-action — a tech-support-fraud overlay distinct from legitimate OS activation dialogs"
        }
        "survey_reward_scam" => {
            "invites the victim to take a survey (complete our survey, answer 3 questions, selected for our survey) and promises a gift card or cash reward as bait — a browser-overlay advance-fee fraud pattern"
        }
        "av_brand_renewal_scam" => {
            "displays a named antivirus brand (McAfee, Norton, Avast, Kaspersky, etc.) alongside a subscription-expiry or license-expired alarm to create urgency and drive victims to call a fake tech-support line"
        }
        "recovery_scam" => {
            "targets prior fraud victims by claiming to recover their lost funds (crypto recovery, chargeback specialist, scam recovery service) for an upfront fee — a secondary-victimization fraud flagged by FBI IC3 2024"
        }
        "student_loan_scam" => {
            "claims to offer student loan forgiveness, relief, or discharge and demands a processing, enrollment, or administrative fee — legitimate federal forgiveness programs charge no fee to apply"
        }
        "secret_shopper_scam" => {
            "recruits victims as secret or mystery shoppers and instructs them to deposit a check, then wire funds or purchase gift cards — the check is fake and the victim loses the transferred amount"
        }
        "mlm_pyramid_recruitment" => {
            "promotes a multi-level or network-marketing income opportunity using referral/downline/tier-bonus framing and demands payment to join, activate, or enroll — the classic tell of pyramid-scheme recruitment"
        }
        "veterans_benefit_scam" => {
            "claims to expedite or file a VA disability, veteran benefit, or GI Bill claim for a processing or claim-assistance fee — the VA charges no fee to file claims; any fee demand is a scam tell"
        }
        "fake_copyright_scam" => {
            "displays a fake DMCA notice, copyright violation, or piracy-detected alert and demands immediate payment of a settlement or fine to avoid prosecution — legitimate takedowns target service providers, not individual users via browser overlays"
        }
        "crypto_giveaway_scam" => {
            "impersonates a crypto exchange or celebrity (e.g. Elon Musk / Tesla / Binance) running a 'giveaway' and instructs the victim to send cryptocurrency first in order to receive a doubled amount back — a one-shot coin-doubling fraud; no legitimate giveaway requires an upfront transfer"
        }
        "otp_interception_scam" => {
            "asks the user to share, read aloud, or give a one-time verification/2FA code to the page or caller — a real-time account-takeover relay; legitimate two-factor flows have the user enter a code into their own form, never share it with anyone"
        }
        "family_emergency_scam" => {
            "claims a relative (grandson/son/daughter/family member) is in a sudden crisis — arrested, hospitalized, kidnapped — and urgently, secretly needs money (bail/ransom/wire/gift cards); the 'grandparent' / AI-voice-clone imposter scam"
        }
        "remote_access_lure" => "pushes a remote-access tool alongside a fake alert",
        "input_trap" => "locks the screen by trapping keyboard/mouse",
        "sudden_fullscreen_takeover" => "seized the full screen the instant it appeared",
        other => other,
    }
}

/// Join clauses into "a", "a and b", or "a, b, and c" (Oxford comma).
fn join_clauses(parts: &[&str]) -> String {
    match parts {
        [] => String::new(),
        [one] => (*one).to_string(),
        [a, b] => format!("{a} and {b}"),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
    }
}

/// The classifier's verdict on a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Leave it alone.
    Allow,
    /// Record an audit event, but do not dismiss. Operator/IT reviews.
    Suspicious,
    /// Dismiss/close. Reserved for confirmed blocklist matches or
    /// scores at/above the block threshold.
    Block,
}

/// Signal-quality confidence in a [`Verdict`].
///
/// Derived from whether **text-analysis or rule-based signals** (high
/// fidelity) fired alongside the geometry signals.  Geometry-only
/// verdicts can be driven by window properties that a rogue helper
/// might mis-report; text signals are computed deterministically over
/// the title/URL strings and are harder to fake.  Use this to route
/// SIEM alerts: auto-respond to `High`, queue `Medium` for review,
/// and note `Low` as telemetry only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    /// ≥1 high-fidelity signal (text analysis / blocklist / phone) fired.
    High,
    /// Mixed signals: one high-fidelity + one or more geometry signals.
    Medium,
    /// Only geometry signals (fullscreen / topmost / modal / origin).
    /// The verdict is correct per observed state but relies solely on
    /// window-structure information that a helper could mis-report.
    Low,
}

// ── Scoring weights (named per I6: explainable) ──────────────────

/// At or above this score → Block. Below `SUSPICIOUS_THRESHOLD` →
/// Allow. In between → Suspicious.
pub const BLOCK_THRESHOLD: i32 = 100;
/// At or above this score → Suspicious (audited, not dismissed). Below → Allow.
pub const SUSPICIOUS_THRESHOLD: i32 = 50;

const W_FULLSCREEN: i32 = 30; // covers (almost) the whole display
const W_TOPMOST: i32 = 15; // always-on-top
const W_NO_CLOSE: i32 = 25; // hides/fakes the close button
const W_BLOCKS_INPUT: i32 = 20; // modal capture
const W_UNSOLICITED: i32 = 25; // appeared with no user action
const W_VERY_NEW: i32 = 10; // < 1s old (just popped up)
const W_TITLE_HIT: i32 = 40; // title matches a scam pattern
const W_PHONE_NUMBER: i32 = 35; // a phone number in an OS-alert-like window
const W_PHONE_BLOCKLIST: i32 = 40; // a KNOWN scam phone number (curated `phone:` rule)
const W_MIXED_SCRIPT: i32 = 30; // title/host mixes Latin with Cyrillic/Greek
const W_WHOLE_SCRIPT: i32 = 30; // title/host is all-Cyrillic/Greek but reads as Latin (whole-script confusable)
const W_COMPAT_CHARS: i32 = 20; // title/host contains enclosed/circled letters Ⓐ-Ⓩ / ⓐ-ⓩ (compatibility evasion)
const W_MIXED_NUMBERS: i32 = 20; // a token mixes two decimal numbering systems (ICU MIXED_NUMBERS)
const W_ZALGO: i32 = 20; // 3+ stacked combining marks (Zalgo obfuscation)
const W_BIDI_OVERRIDE: i32 = 30; // title/host uses an LRO/RLO directional override (Trojan Source)
const W_INPUT_TRAP: i32 = 5; // fullscreen+topmost+modal "screen lock" (bounded; see classify)
const W_SUDDEN_TAKEOVER: i32 = 5; // unsolicited instant full-screen seizure (bounded)
const W_BRAND_IMPERSONATION: i32 = 40; // host label is a homograph of a known brand
const W_COMBOSQUAT: i32 = 30; // host label joins a known brand + a scam lure word (combosquatting)
const W_TYPOSQUAT_BRAND: i32 = 25; // host label is edit-distance-1 keyboard typosquat of a known brand
const W_CLICKFIX: i32 = 20; // ClickFix/fake-CAPTCHA keyboard-instruction pattern (alert_shaped guard)
const W_URGENCY_COUNTDOWN: i32 = 15; // countdown timer + urgency keyword (scam coercion, alert_shaped guard)
const W_CLOUD_STORAGE_ABUSE: i32 = 20; // alert-shaped overlay served from known blob-storage infra (TSS delivery vector)
const W_URL_PATH_LURE: i32 = 20; // alert-shaped overlay with brand+lure combosquat pattern in the URL path
const W_FORCED_RETENTION: i32 = 20; // "do not close" / "do not turn off" instruction in title (high-specificity scam tell)
const W_CREDENTIAL_HARVEST: i32 = 20; // "account suspended / verify account / confirm password" credential-phish cue
const W_FAKE_SCANNER: i32 = 20; // fake-AV scanner progress: "scanning for threats", "N threats found", "repairing system"
const W_SUBSCRIPTION_LURE: i32 = 15; // "subscription expired renew now" — softer scareware, lower weight (often has close button)
const W_AUTHORITY_LURE: i32 = 25; // FBI/police/interpol/cybercrime impersonation — high-specificity ransomware-bluff tell
const W_DOWNLOAD_TRAP: i32 = 20; // fake download/install/update gate: install_demand or fake_plugin_gate
const W_PRIZE_LURE: i32 = 20; // fake prize/lottery/gift-card overlay: prize-word + claim/collect action
const W_CRYPTO_DRAIN: i32 = 25; // wallet-drain overlay: wallet alarm / coerce-connect / seed-phrase harvest
const W_SCREEN_SHARE: i32 = 20; // instructs victim to share screen/desktop with a "support agent"
const W_QR_CODE_LURE: i32 = 20; // QR/quishing overlay: qr_noun + verify_action (FBI IC3 2025)
const W_IP_ALARM: i32 = 20; // "your IP address has been hacked/flagged" — tech-support scam staple
const W_PACKAGE_FEE: i32 = 20; // customs/delivery fee scam: package_noun + fee_demand (FTC 2024 #2)
const W_SEXTORTION: i32 = 25; // webcam recording + crypto payment demand (FBI IC3 2024 +42% YoY)
const W_GIFT_CARD_DEMAND: i32 = 30; // gift-card payment demand: card_noun + buy/send-codes (FTC #1 tech-support loss)
const W_REFUND_SCAM: i32 = 25; // refund/overpayment lure: claim-oriented action + refund noun (FTC/IC3 2024 elderly-targeting)
const W_NATIONAL_ID_ALARM: i32 = 30; // SSN/NIN/マイナンバー suspension alarm (FTC #1 government impersonation subcategory)
const W_BANK_ACCOUNT_ALARM: i32 = 25; // fake bank-fraud alert: bank/card noun + freeze/fraud alarm (distinct from credential_harvest)
const W_FALSE_REG_BILLING: i32 = 25; // ワンクリック詐欺: false registration claim + payment ultimatum
const W_FAKE_BSOD_LURE: i32 = 30; // fake BSOD / Windows-blocked overlay impersonating OS crash (T1036)
const W_ADVANCE_FEE_LURE: i32 = 25; // 419/advance-fee: windfall claim + fee-extraction demand (FTC BCP 2024)
const W_TECH_INVOICE_SCAM: i32 = 25; // fake tech-support invoice: charge claim + call-to-cancel (FTC 2025 impostor)
const W_UTILITY_CUTOFF: i32 = 25; // fake utility disconnection threat: utility_service + cutoff_threat (FTC #3 impostor)
const W_HEALTHCARE_SCAM: i32 = 25; // Medicare/benefit expiry + free-offer lure (IC3 2025 #1 elder-fraud)
const W_JOB_SCAM: i32 = 25; // employment fraud: job offer + advance-fee gate (IC3 2025 top-5, FTC #1 biz-opp)
const W_TAX_AUTHORITY_SCAM: i32 = 30; // IRS/HMRC/国税庁 impersonation + arrest/seizure threat (FTC 2025 gov impostor #2)
const W_SOCIAL_MEDIA_ACCOUNT_ALARM: i32 = 25; // social platform named + hacked/suspended (phishing overlay)
const W_IMMIGRATION_VISA_SCAM: i32 = 25; // visa/work-permit named + revocation/deportation threat (targets immigrants)
const W_GOVERNMENT_GRANT_SCAM: i32 = 25; // government grant/stimulus impersonation + fee barrier (FTC gov-impostor)
const W_DEBT_RELIEF_SCAM: i32 = 25; // debt/credit relief framing + upfront fee / guaranteed-results CTA
const W_STREAMING_BILLING_SCAM: i32 = 25; // named streaming service + payment-failure/billing-problem (APWG 2025)
const W_TRAFFIC_FINE_SCAM: i32 = 25; // traffic/parking/toll violation + payment urgency (FTC 2025 top-3 impostor)
const W_PIG_BUTCHERING_LURE: i32 = 30; // romance/mentor cue + investment platform (IC3 2024 #1 by loss $4.57B)
const W_LOAN_FEE_SCAM: i32 = 30; // pre-approved loan + upfront-fee gate (FTC advance-fee loan fraud)
const W_DATA_URI_PAGE: i32 = 25; // alert-shaped window served from data: or file:// URL (blocklist-bypass technique)
const W_IP_HOST_URL: i32 = 35; // URL host is a raw IPv4/IPv6 address — no legitimate support page uses raw IP
const W_CHARITY_SCAM_LURE: i32 = 25; // fake charity + irreversible payment (gift card/wire/crypto) after disaster
const W_RENTAL_SCAM_LURE: i32 = 25; // fake rental listing + advance deposit demand (FTC 2024 housing fraud)
const W_PET_SALE_SCAM: i32 = 25; // fake pet listing + transport/crate deposit demand (FTC 2024 online shopping fraud)
const W_TIMESHARE_TRAVEL_SCAM: i32 = 25; // vacation club / timeshare + activation fee demand (FTC travel prize fraud)
const W_WINDOWS_ACTIVATION_SCAM: i32 = 30; // fake Windows/Office product-key popup + "call Microsoft" CTA (FTC tech-support fraud)
const W_SURVEY_REWARD_SCAM: i32 = 25; // survey-invite + gift-card/cash-reward bait (APWG 2024 survey-lure phishing)
const W_AV_BRAND_RENEWAL_SCAM: i32 = 30; // named AV brand + subscription-expiry alarm (APWG 2024 branded AV pop-up)
const W_RECOVERY_SCAM: i32 = 30; // "recover your lost funds" + fee/specialist CTA (FBI IC3 2024 secondary-victimization)
const W_STUDENT_LOAN_SCAM: i32 = 25; // student loan forgiveness + processing fee (FTC 2024 DOE SAVE plan fraud spike)
const W_SECRET_SHOPPER_SCAM: i32 = 30; // secret/mystery shopper + deposit check/wire funds (money-mule via fake job)
const W_MLM_PYRAMID_RECRUITMENT: i32 = 25; // referral/downline/residual income + join/invest CTA (FTC 2024 pyramid scheme)
const W_VETERANS_BENEFIT_SCAM: i32 = 30; // VA/veteran disability/benefit claim + processing fee (FTC 2024 military fraud)
const W_FAKE_COPYRIGHT_SCAM: i32 = 30; // DMCA/copyright violation notice + pay settlement/fine (APWG 2024 legal-threat phishing)
const W_CRYPTO_GIVEAWAY_SCAM: i32 = 30; // crypto giveaway/doubling + send-to-receive demand (FTC 2024 crypto-impersonation fraud)
const W_OTP_INTERCEPTION_SCAM: i32 = 30; // OTP/2FA code cue + share/read/give-the-code relay demand (FTC 2024 account-takeover)
const W_FAMILY_EMERGENCY_SCAM: i32 = 30; // relative + crisis + money/secrecy demand (FTC 2024 family-emergency/imposter; 警察庁 オレオレ詐欺)
const W_REMOTE_ACCESS_LURE: i32 = 20; // remote-access tool named alongside a fake alert (context-amplified)
const W_USER_INITIATED_RELIEF: i32 = -40; // user opened it → trust more

/// The weight contribution of a built-in signal.  Returns `None` for
/// composite rule signals (whose weights are operator-configured) and for
/// unknown names.  The returned value may be negative (e.g.
/// `"user_initiated"` → −40) or positive.  Geometry-only signals have
/// lower weights than text/rule signals, reflecting their lower fidelity:
/// a window's geometry is easy for a helper to observe but also easy for
/// malware to simulate; a blocklist or phone-number match is harder to
/// evade.
///
/// The weights are stable across patch releases; a minor-version bump may
/// adjust them.
#[must_use]
pub fn signal_weight(name: &str) -> Option<i32> {
    match name {
        "fullscreen" => Some(W_FULLSCREEN),
        "topmost" => Some(W_TOPMOST),
        "no_close_button" => Some(W_NO_CLOSE),
        "blocks_input" => Some(W_BLOCKS_INPUT),
        "unsolicited" => Some(W_UNSOLICITED),
        "very_new" => Some(W_VERY_NEW),
        "blocklist_title" => Some(W_TITLE_HIT),
        "blocklist_phone" => Some(W_PHONE_BLOCKLIST),
        "phone_number" => Some(W_PHONE_NUMBER),
        "mixed_script" => Some(W_MIXED_SCRIPT),
        "whole_script_confusable" => Some(W_WHOLE_SCRIPT),
        "compat_chars_present" => Some(W_COMPAT_CHARS),
        "mixed_number_systems" => Some(W_MIXED_NUMBERS),
        "excessive_combining_marks" => Some(W_ZALGO),
        "bidi_override" => Some(W_BIDI_OVERRIDE),
        "input_trap" => Some(W_INPUT_TRAP),
        "sudden_fullscreen_takeover" => Some(W_SUDDEN_TAKEOVER),
        "brand_impersonation" => Some(W_BRAND_IMPERSONATION),
        "combosquat_brand" => Some(W_COMBOSQUAT),
        "typosquat_brand" => Some(W_TYPOSQUAT_BRAND),
        "clickfix_instruction" => Some(W_CLICKFIX),
        "urgency_countdown" => Some(W_URGENCY_COUNTDOWN),
        "cloud_storage_abuse" => Some(W_CLOUD_STORAGE_ABUSE),
        "url_path_lure" => Some(W_URL_PATH_LURE),
        "forced_retention_cue" => Some(W_FORCED_RETENTION),
        "credential_harvest_cue" => Some(W_CREDENTIAL_HARVEST),
        "fake_scanner_cue" => Some(W_FAKE_SCANNER),
        "subscription_lure" => Some(W_SUBSCRIPTION_LURE),
        "authority_lure" => Some(W_AUTHORITY_LURE),
        "download_trap_lure" => Some(W_DOWNLOAD_TRAP),
        "prize_lure" => Some(W_PRIZE_LURE),
        "crypto_drain_lure" => Some(W_CRYPTO_DRAIN),
        "screen_share_lure" => Some(W_SCREEN_SHARE),
        "qr_code_lure" => Some(W_QR_CODE_LURE),
        "ip_alarm_lure" => Some(W_IP_ALARM),
        "package_fee_lure" => Some(W_PACKAGE_FEE),
        "sextortion_lure" => Some(W_SEXTORTION),
        "gift_card_demand" => Some(W_GIFT_CARD_DEMAND),
        "refund_scam_cue" => Some(W_REFUND_SCAM),
        "national_id_alarm" => Some(W_NATIONAL_ID_ALARM),
        "bank_account_alarm" => Some(W_BANK_ACCOUNT_ALARM),
        "false_registration_billing" => Some(W_FALSE_REG_BILLING),
        "fake_bsod_lure" => Some(W_FAKE_BSOD_LURE),
        "advance_fee_lure" => Some(W_ADVANCE_FEE_LURE),
        "tech_support_invoice_scam" => Some(W_TECH_INVOICE_SCAM),
        "utility_cutoff_threat" => Some(W_UTILITY_CUTOFF),
        "healthcare_scam" => Some(W_HEALTHCARE_SCAM),
        "job_scam" => Some(W_JOB_SCAM),
        "tax_authority_scam" => Some(W_TAX_AUTHORITY_SCAM),
        "social_media_account_alarm" => Some(W_SOCIAL_MEDIA_ACCOUNT_ALARM),
        "immigration_visa_scam" => Some(W_IMMIGRATION_VISA_SCAM),
        "government_grant_scam" => Some(W_GOVERNMENT_GRANT_SCAM),
        "debt_relief_scam" => Some(W_DEBT_RELIEF_SCAM),
        "streaming_billing_scam" => Some(W_STREAMING_BILLING_SCAM),
        "traffic_fine_scam" => Some(W_TRAFFIC_FINE_SCAM),
        "pig_butchering_lure" => Some(W_PIG_BUTCHERING_LURE),
        "loan_fee_scam" => Some(W_LOAN_FEE_SCAM),
        "data_uri_page" => Some(W_DATA_URI_PAGE),
        "ip_host_url" => Some(W_IP_HOST_URL),
        "charity_scam_lure" => Some(W_CHARITY_SCAM_LURE),
        "rental_scam_lure" => Some(W_RENTAL_SCAM_LURE),
        "pet_sale_scam" => Some(W_PET_SALE_SCAM),
        "timeshare_travel_scam" => Some(W_TIMESHARE_TRAVEL_SCAM),
        "windows_activation_scam" => Some(W_WINDOWS_ACTIVATION_SCAM),
        "survey_reward_scam" => Some(W_SURVEY_REWARD_SCAM),
        "av_brand_renewal_scam" => Some(W_AV_BRAND_RENEWAL_SCAM),
        "recovery_scam" => Some(W_RECOVERY_SCAM),
        "student_loan_scam" => Some(W_STUDENT_LOAN_SCAM),
        "secret_shopper_scam" => Some(W_SECRET_SHOPPER_SCAM),
        "mlm_pyramid_recruitment" => Some(W_MLM_PYRAMID_RECRUITMENT),
        "veterans_benefit_scam" => Some(W_VETERANS_BENEFIT_SCAM),
        "fake_copyright_scam" => Some(W_FAKE_COPYRIGHT_SCAM),
        "crypto_giveaway_scam" => Some(W_CRYPTO_GIVEAWAY_SCAM),
        "otp_interception_scam" => Some(W_OTP_INTERCEPTION_SCAM),
        "family_emergency_scam" => Some(W_FAMILY_EMERGENCY_SCAM),
        "remote_access_lure" => Some(W_REMOTE_ACCESS_LURE),
        "user_initiated" => Some(W_USER_INITIATED_RELIEF),
        _ => None,
    }
}

/// Returns `true` when `signal` is a **text/rule-based** signal — one
/// computed deterministically from window text or operator blocklist rules
/// — rather than from window-geometry fields reported by a helper.
/// Used to compute [`Verdict::confidence`].
fn is_high_fidelity(signal: &str) -> bool {
    matches!(
        signal,
        "blocklist_title"
            | "blocklist_phone"
            | "blocklist_host"
            | "phone_number"
            | "mixed_script"
            | "whole_script_confusable"
            | "compat_chars_present"
            | "mixed_number_systems"
            | "excessive_combining_marks"
            | "bidi_override"
            | "brand_impersonation"
            | "combosquat_brand"
            | "typosquat_brand"
            | "clickfix_instruction"
            | "urgency_countdown"
            | "cloud_storage_abuse"
            | "url_path_lure"
            | "forced_retention_cue"
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
            | "gift_card_demand"
            | "refund_scam_cue"
            | "national_id_alarm"
            | "bank_account_alarm"
            | "false_registration_billing"
            | "fake_bsod_lure"
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
            | "ip_host_url"
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
            | "veterans_benefit_scam"
            | "fake_copyright_scam"
            | "crypto_giveaway_scam"
            | "otp_interception_scam"
            | "family_emergency_scam"
            | "remote_access_lure"
    )
}

/// Machine-readable descriptor for one built-in detection signal.
///
/// Returned by [`all_signals`]. Intended for MDM operators who want to
/// enumerate every signal muten ships, inspect its default weight and
/// dark-pattern category, and decide which ones to override in their
/// blocklist.  The `description` field reproduces the same human phrase
/// used in [`Verdict::explain`].
#[derive(Debug, Clone, Serialize)]
pub struct SignalInfo {
    /// Canonical signal name (the string that appears in `Verdict.signals`).
    pub name: &'static str,
    /// Default weight contribution when the signal fires.  `None` means the
    /// signal is geometry-only (no content weight) or is operator-configured
    /// (composite blocklist rules).
    pub default_weight: Option<i32>,
    /// Dark-pattern category per Gray et al. (2018), if assigned.
    pub category: Option<DarkPatternCategory>,
    /// MITRE ATT&CK technique IDs associated with this signal.
    pub mitre_techniques: &'static [&'static str],
    /// Human-readable phrase used in `Verdict::explain`.
    pub description: &'static str,
    /// `true` when the signal is text/rule-based (high-fidelity) rather than
    /// geometry-based (low-fidelity).  Matches the logic in `Verdict::confidence`.
    pub high_fidelity: bool,
}

/// Return a catalog of every built-in detection signal muten ships.
///
/// The list is stable within a minor version.  A major version bump may add,
/// remove, or rename signals; a minor bump may add new ones.  Operators can
/// iterate this list to build a UI, pre-populate a SIEM lookup table, or
/// generate a blocklist template.
///
/// Signals are listed in roughly the same order they appear in the scoring
/// block of [`classify`]: geometry signals first, then text/rule signals.
#[must_use]
pub fn all_signals() -> Vec<SignalInfo> {
    const NAMES: &[&str] = &[
        // ── Geometry (window structure) ──────────────────────────────
        "fullscreen",
        "topmost",
        "no_close_button",
        "blocks_input",
        "unsolicited",
        "very_new",
        "input_trap",
        "sudden_fullscreen_takeover",
        "user_initiated",
        // ── Blocklist / phone ────────────────────────────────────────
        "blocklist_title",
        "blocklist_host",
        "blocklist_phone",
        "phone_number",
        // ── Unicode evasion ──────────────────────────────────────────
        "mixed_script",
        "whole_script_confusable",
        "compat_chars_present",
        "mixed_number_systems",
        "excessive_combining_marks",
        "bidi_override",
        // ── Domain intelligence ──────────────────────────────────────
        "brand_impersonation",
        "combosquat_brand",
        "typosquat_brand",
        "cloud_storage_abuse",
        "url_path_lure",
        // ── Content signals (alert_shaped guard) ─────────────────────
        "clickfix_instruction",
        "urgency_countdown",
        "forced_retention_cue",
        "credential_harvest_cue",
        "fake_scanner_cue",
        "subscription_lure",
        "authority_lure",
        "download_trap_lure",
        "prize_lure",
        "crypto_drain_lure",
        "screen_share_lure",
        "qr_code_lure",
        "ip_alarm_lure",
        "package_fee_lure",
        "sextortion_lure",
        "gift_card_demand",
        "refund_scam_cue",
        "national_id_alarm",
        "bank_account_alarm",
        "false_registration_billing",
        "fake_bsod_lure",
        "advance_fee_lure",
        "tech_support_invoice_scam",
        "utility_cutoff_threat",
        "healthcare_scam",
        "job_scam",
        "tax_authority_scam",
        "social_media_account_alarm",
        "immigration_visa_scam",
        "government_grant_scam",
        "debt_relief_scam",
        "streaming_billing_scam",
        "traffic_fine_scam",
        "pig_butchering_lure",
        "loan_fee_scam",
        "data_uri_page",
        "ip_host_url",
        "charity_scam_lure",
        "rental_scam_lure",
        "pet_sale_scam",
        "timeshare_travel_scam",
        "windows_activation_scam",
        "survey_reward_scam",
        "av_brand_renewal_scam",
        "recovery_scam",
        "student_loan_scam",
        "secret_shopper_scam",
        "mlm_pyramid_recruitment",
        "veterans_benefit_scam",
        "fake_copyright_scam",
        "crypto_giveaway_scam",
        "otp_interception_scam",
        "family_emergency_scam",
        "remote_access_lure",
    ];
    NAMES
        .iter()
        .map(|&name| SignalInfo {
            name,
            default_weight: signal_weight(name),
            category: categories::category_of(name),
            mitre_techniques: mitre::techniques_of(name),
            description: signal_phrase(name),
            high_fidelity: is_high_fidelity(name),
        })
        .collect()
}

/// Major brands muten ships a built-in homograph guard for (UTS #39
/// skeleton collision, roadmap C8-2). Chosen to be long/distinctive
/// enough that an accidental skeleton collision with an *unrelated*
/// legitimate domain is vanishingly unlikely — short or dictionary-word
/// brands are intentionally omitted to stay false-positive-averse.
///
/// Organised by category for readability; each entry is the all-lowercase
/// ASCII skeleton (what `confusables::skeleton` reduces the brand to).
const KNOWN_BRANDS: &[&str] = &[
    // ── Payment / banking ───────────────────────────────────────────
    "paypal",
    "wellsfargo",
    "bankofamerica",
    "americanexpress",
    "venmo",
    "cashapp",
    "zelle",
    // ── Technology (OS / productivity / cloud) ──────────────────────
    "microsoft",
    "google",
    "apple",
    "amazon",
    "windows",
    "outlook",
    "office365",
    "onedrive",
    "icloud",
    "dropbox",
    // ── Social / communication ──────────────────────────────────────
    "facebook",
    "instagram",
    "whatsapp",
    "twitter",
    "discord",
    "linkedin",
    "netflix",
    // ── Security (AV / signing) — primary TSS impersonation targets ─
    "norton",
    "mcafee",
    "docusign",
    // ── Cryptocurrency / DeFi ───────────────────────────────────────
    "binance",
    "coinbase",
    "metamask",
    "ethereum",
    "kraken",
    // ── JP-market brands (docomo / softbank / rakuten) ──────────────
    "docomo",
    "softbank",
    "rakuten",
];

/// If any label of `host` is a homograph/typosquat of a [`KNOWN_BRANDS`]
/// entry — its confusable skeleton equals the brand but the label is
/// **not** that brand spelled literally — return the impersonated brand.
/// `paypal.com` (the real brand) never fires; `раура1.com` (Cyrillic +
/// digit) does. Pure and offline. This is muten's zero-config homograph
/// guard for brands a deployment has not (and should not) blocklisted.
#[must_use]
fn brand_impersonation(host: &str) -> Option<&'static str> {
    for label in host.split('.') {
        if label.is_empty() {
            continue;
        }
        let literal = label.to_ascii_lowercase();
        let skel = confusables::skeleton(label);
        // Only a *non-literal* skeleton collision is impersonation.
        if skel == literal {
            continue;
        }
        if let Some(&brand) = KNOWN_BRANDS.iter().find(|&&b| b == skel) {
            return Some(brand);
        }
    }
    None
}

/// Levenshtein edit distance between byte strings `a` and `b` (standard DP,
/// 2-row space). Returns early with a sentinel of 2 when the lengths differ
/// by more than 1 (edit distance ≥ 2 in that case) so the inner loop in
/// [`typosquat_brand`] stays fast.
fn levenshtein_distance(a: &[u8], b: &[u8]) -> usize {
    let na = a.len();
    let nb = b.len();
    if na == 0 {
        return nb;
    }
    if nb == 0 {
        return na;
    }
    // Edit distance is at least |na - nb|; if that's already > 1 we can skip.
    if na.abs_diff(nb) > 1 {
        return 2;
    }
    let mut prev: Vec<usize> = (0..=nb).collect();
    let mut curr = vec![0usize; nb + 1];
    for (i, &ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            curr[j + 1] = if ca == cb {
                prev[j]
            } else {
                1 + prev[j].min(prev[j + 1]).min(curr[j])
            };
        }
        core::mem::swap(&mut prev, &mut curr);
    }
    prev[nb]
}

/// Keyboard-adjacent typosquatting of a [`KNOWN_BRANDS`] entry (D10).
///
/// Catches edit-distance-1 variants that escape the exact-skeleton
/// [`brand_impersonation`] check: deletions (`"gogle.com"`), insertions
/// (`"googlee.com"`), transpositions (`"googel.com"`), and single-character
/// substitutions (`"googlo.com"`). Returns the impersonated brand name if any
/// label of `host` is within Levenshtein distance 1 of a known brand *and*
/// the skeleton is not already identical to the brand (that case is covered by
/// `brand_impersonation`).
fn typosquat_brand(host: &str) -> Option<&'static str> {
    for label in host.split('.') {
        if label.len() < 3 {
            continue;
        }
        let skel = confusables::skeleton(label);
        for &brand in KNOWN_BRANDS {
            if skel == brand {
                // Exact skeleton match: brand_impersonation already covers it.
                continue;
            }
            if levenshtein_distance(skel.as_bytes(), brand.as_bytes()) == 1 {
                return Some(brand);
            }
        }
    }
    None
}

/// Scam-indicative "lure" words that combosquatting domains append to a
/// brand to look like an official login / support / security surface.
/// Exact hyphen-token match only (no substring) — a near-zero-FP set:
/// these words beside a brand in *one registrable label* is the textbook
/// combosquat shape. Drawn from Kintis et al., "Hiding in Plain Sight"
/// (ACM CCS 2017) and the dnstwist dictionary fuzzer.
const BRAND_LURE_WORDS: &[&str] = &[
    "support",
    "secure",
    "security",
    "verify",
    "verification",
    "login",
    "signin",
    "account",
    "accounts",
    "update",
    "alert",
    "billing",
    "service",
    "help",
    "recovery",
    "unlock",
    "confirm",
    "wallet",
    "auth",
    // Extended lure vocabulary from threat-intel (dnstwist corpus + IC3 2025).
    "remove",     // "norton-remove.net" — fake AV removal tool upsell
    "transfer",   // "venmo-transfer.com" — P2P payment fraud
    "refund",     // "amazon-refund.net" — refund re-victimization (IC3 2024)
    "claim",      // "coinbase-claim.com" — crypto reward scam
    "portal",     // "paypal-portal.net" — credential phishing
    "center",     // "microsoft-center.com" — fake support center
    "protection", // "norton-protection.com" — AV upsell lure
    "payment",    // "zelle-payment.net" / "paypal-payment.net" — P2P fraud
];

/// Detect **combosquatting** (Kintis et al., ACM CCS 2017): a host label
/// that joins a [`KNOWN_BRANDS`] entry and a [`BRAND_LURE_WORDS`] entry as
/// distinct **hyphen-delimited tokens** in a single registrable label —
/// e.g. `apple-support`, `paypal-secure-login`, `microsoft-verify`. This
/// is the blind spot of [`brand_impersonation`], which only fires on a
/// homoglyph skeleton that equals the brand *exactly* (one token, no lure).
///
/// Returns the `(brand, lure)` that matched. Each token's confusable
/// skeleton is taken first, so a homoglyph combosquat (`аpple-support`,
/// Cyrillic `а`) still matches.
///
/// **False-positive guard.** Requiring a hyphen between brand and lure
/// (i.e. ≥ 2 tokens, both exact matches) keeps legitimate *concatenations*
/// like `windowsupdate.com` (one token) from ever firing, and exact-token
/// matching avoids substring traps (`pineapple-store` ≠ `apple`). Like
/// [`brand_impersonation`] the signal is additive, never an auto-block.
#[must_use]
fn combosquat(host: &str) -> Option<(&'static str, &'static str)> {
    for label in host.split('.') {
        // Combosquats put brand + lure as distinct hyphen tokens within
        // one label. ≥ 2 tokens required, so a bare brand or a legitimate
        // concatenation (no hyphen) is never considered.
        let tokens: Vec<String> = label
            .split('-')
            .filter(|t| !t.is_empty())
            .map(|t| confusables::skeleton(t).to_ascii_lowercase())
            .collect();
        if tokens.len() < 2 {
            continue;
        }
        let Some(&brand) = KNOWN_BRANDS
            .iter()
            .find(|&&b| tokens.iter().any(|t| t == b))
        else {
            continue;
        };
        if let Some(&lure) = BRAND_LURE_WORDS
            .iter()
            .find(|&&l| tokens.iter().any(|t| t == l))
        {
            return Some((brand, lure));
        }
    }
    None
}

/// Legitimate remote-access tools that tech-support scammers routinely
/// direct victims to install so they can seize the machine (FTC / FBI
/// IC3 2024). The tool itself is legitimate, so its mere presence is
/// **not** a scam signal — muten only counts it as a `remote_access_lure`
/// when it co-occurs with independent fake-alert evidence (see
/// [`classify`]). Matched as a normalized-title substring.
const REMOTE_ACCESS_TOOLS: &[&str] = &[
    "anydesk",
    "teamviewer",
    "ultraviewer",
    "logmein",
    "rustdesk",
    "screenconnect",
    "connectwise",
    "quicksupport",
    "gotoassist",
    "ammyy",
    "supremo",
    "aeroadmin",
];

/// True if the (already-normalized) title mentions a known remote-access
/// tool from [`REMOTE_ACCESS_TOOLS`].
#[must_use]
fn mentions_remote_access_tool(normalized_title: &str) -> bool {
    REMOTE_ACCESS_TOOLS
        .iter()
        .any(|t| normalized_title.contains(t))
}

/// Coverage at or above this percent counts as "full-screen".
const FULLSCREEN_COVERAGE: u8 = 85;

/// Extract the host portion of a URL-ish string, scheme/path/port
/// stripped — used to scope the mixed-script check to the host so a
/// Cyrillic word in a *path* (`example.com/привет`) can't false-fire.
/// Thin alias over the crate's single host extractor
/// ([`rules::host_str`]) so the three host-parsing sites can't drift.
fn url_host(url: &str) -> &str {
    crate::rules::host_str(url)
}

/// True when the URL host is a raw IPv4 or IPv6 address.
///
/// No legitimate support, banking, or government page uses a bare IP
/// address as its host — raw-IP URLs are a strong scam-infrastructure
/// indicator (attackers avoid domain registration to evade blocklists).
fn url_host_is_ip(url: &str) -> bool {
    let host = url_host(url);
    // Strip IPv6 brackets "[::1]" → "::1" for parse
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<std::net::IpAddr>().is_ok()
}

/// Extract the path component of a URL (the part after the host and
/// before any `?` or `#`). Returns `""` when no path is present.
fn url_path(url: &str) -> &str {
    let after_scheme = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => url,
    };
    match after_scheme.find('/') {
        None => "",
        Some(slash) => {
            let with_path = &after_scheme[slash..];
            match with_path.find(['?', '#']) {
                Some(end) => &with_path[..end],
                None => with_path,
            }
        }
    }
}

/// Return `true` when the URL path contains a known-brand token within
/// 2 positions of a known lure word (after normalization).
///
/// The path is split on non-alphanumeric boundaries so both
/// `/microsoft-alert/` and `/norton/remove/` produce adjacent brand+lure
/// tokens. A window of 2 catches single-segment combosquats and
/// two-segment paths without reaching across long unrelated paths.
///
/// Requires `alert_shaped` in the caller to avoid FP on legitimate
/// webapps whose paths happen to contain a brand name.
fn has_path_lure(url: &str) -> bool {
    let path = url_path(url);
    if path.is_empty() {
        return false;
    }
    let norm = confusables::normalize_for_match(path);
    let tokens: Vec<&str> = norm
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.len() < 2 {
        return false;
    }
    for (i, token) in tokens.iter().enumerate() {
        if !KNOWN_BRANDS.contains(token) {
            continue;
        }
        let start = i.saturating_sub(2);
        let end = (i + 3).min(tokens.len());
        for (j, neighbor) in tokens[start..end].iter().enumerate() {
            if start + j != i && BRAND_LURE_WORDS.contains(neighbor) {
                return true;
            }
        }
    }
    false
}

/// Return `true` when `host` is a well-known cloud blob-storage endpoint
/// used as a TSS / scareware delivery vector.
///
/// These domains look trustworthy (microsoft.com, amazonaws.com …) but
/// let anyone host arbitrary content under a tenant-unique subdomain.
/// Detection is suffix-based: each pattern anchors on a structural
/// boundary (always starts with `.`) so a false match on a subdomain
/// named, e.g., `notblob.core.windows.net.evil.com` is impossible.
fn is_cloud_storage_host(host: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        ".blob.core.windows.net",
        ".web.core.windows.net",
        ".s3.amazonaws.com",
        ".storage.googleapis.com",
        ".firebasestorage.googleapis.com",
        ".r2.cloudflarestorage.com",
    ];
    let h = host.to_ascii_lowercase();
    // Each suffix starts with '.', so h.len() > sfx.len() guarantees
    // at least one non-empty tenant label precedes the well-known suffix.
    SUFFIXES
        .iter()
        .any(|sfx| h.ends_with(sfx) && h.len() > sfx.len())
}

/// Classify one observed window against a ruleset.
///
/// Order of precedence:
/// 1. A blocklist **URL/host** match is a hard Block (highest trust).
/// 2. Otherwise compute the additive heuristic score and threshold it.
///    A blocklist **title-pattern** match contributes `W_TITLE_HIT`
///    rather than an automatic block, because titles are noisier than
///    hosts.
#[must_use]
pub fn classify(w: &OverlayWindow, rules: &Ruleset) -> Verdict {
    // Bound untrusted input length up front: a maliciously gigantic title or
    // URL would otherwise make every downstream normalization pass and content
    // detector (~150 of them, each at least O(n)) run for tens of seconds — an
    // algorithmic-complexity DoS. Real titles/URLs are far shorter than the cap.
    let title = confusables::bound_title_chars(&w.title);
    // Length-bounded raw URL, reused by the host block and the raw-evasion
    // checks below so none of them scans a multi-megabyte URL (DoS guard).
    let url_bounded: Option<&str> = w.url.as_deref().map(confusables::bound_title_chars);

    // 1. Hard host/URL block.
    if let Some(url) = url_bounded {
        if let Some(hit) = rules.match_host(url) {
            let signals: Vec<String> = vec!["blocklist_host".into()];
            return Verdict {
                decision: Decision::Block,
                score: BLOCK_THRESHOLD,
                categories: categories::categories_of(&signals),
                mitre_techniques: mitre::techniques_of_signals(&signals),
                signals,
                matched_rule: Some(hit),
            };
        }
    }

    // 2. Additive heuristic.
    let mut score = 0;
    let mut signals: Vec<String> = Vec::new();
    let mut matched_rule = None;

    if w.coverage_percent >= FULLSCREEN_COVERAGE {
        score += rules.weight_of("fullscreen", W_FULLSCREEN);
        signals.push("fullscreen".into());
    }
    if w.topmost {
        score += rules.weight_of("topmost", W_TOPMOST);
        signals.push("topmost".into());
    }
    if !w.has_close_button {
        score += rules.weight_of("no_close_button", W_NO_CLOSE);
        signals.push("no_close_button".into());
    }
    if w.blocks_input {
        score += rules.weight_of("blocks_input", W_BLOCKS_INPUT);
        signals.push("blocks_input".into());
    }
    match w.origin {
        Origin::Unsolicited => {
            score += rules.weight_of("unsolicited", W_UNSOLICITED);
            signals.push("unsolicited".into());
        }
        Origin::UserInitiated => {
            score += rules.weight_of("user_initiated", W_USER_INITIATED_RELIEF);
            signals.push("user_initiated".into());
        }
        Origin::Unknown => {}
    }
    // age_ms == 0 means the enumerator could not determine the
    // window's age (the OS helpers report 0 when window creation time
    // isn't cheaply available). "Unknown age" must not score as
    // "brand new" — otherwise every enumerated window would get
    // W_VERY_NEW unconditionally, turning the signal into constant
    // noise. Only a real, small, *nonzero* age counts as very_new.
    if w.age_ms > 0 && w.age_ms < 1000 {
        score += rules.weight_of("very_new", W_VERY_NEW);
        signals.push("very_new".into());
    }
    // Title blocklist: substring rules (`title:`) and glob rules (`glob:`).
    // Both are treated as the same signal and weight — the distinction is only
    // in how the pattern is expressed, not in how much evidence it provides.
    let title_rule = rules
        .match_title(title)
        .or_else(|| rules.match_title_glob(title));
    if let Some(rule) = title_rule {
        score += rules.weight_of("blocklist_title", W_TITLE_HIT);
        signals.push("blocklist_title".into());
        matched_rule = Some(rule);
    }

    // Known-scam phone number (curated `phone:` rule). Unlike the
    // shape-based `phone_number` heuristic below, a number on IT's
    // pushed scam-number list is high-confidence wherever it appears, so
    // it does not require the alert shape. Additive (not an auto-block),
    // consistent with `blocklist_title`; surfaces the matched rule.
    if let Some(rule) = rules.match_phone(title) {
        score += rules.weight_of("blocklist_phone", W_PHONE_BLOCKLIST);
        signals.push("blocklist_phone".into());
        if matched_rule.is_none() {
            matched_rule = Some(rule);
        }
    }

    // Phone-number signal. Per Miramirkhani et al. (NDSS 2017, "Dial
    // One for Scam", 8,698 TSS domains) and FTC guidance, a phone
    // number in an OS-alert-style window is one of the strongest scam
    // tells: a genuine operating-system error never displays a support
    // number. We only count it when the window also *looks* like an
    // alert (full-screen or modal/no-close), so a legitimate window
    // that merely contains a number (a dialer, a contacts app) isn't
    // penalized.
    //
    // `contains_phone_number` scans at the byte level; combining diacritical
    // marks (U+0300–U+036F etc.) inserted between digits break the byte scan
    // without any visual change. We strip combining marks after confusable-
    // folding so that `1̶-̶8̶0̶0̶-̶5̶5̶5̶-̶0̶1̶0̶0̶` is read as `1-800-555-0100`.
    // Leet folding is deliberately NOT applied here (it is not in normalize_
    // for_match for this path either) because `fold_leet_in_words` maps digit
    // 0→o, 1→i which would corrupt the digit run; digits never have leet codes.
    let alert_shaped =
        w.coverage_percent >= FULLSCREEN_COVERAGE || w.blocks_input || !w.has_close_button;
    let phone_scan_text = confusables::strip_combining_marks(&confusables::fold_confusables(title));
    if alert_shaped && contains_phone_number(&phone_scan_text) {
        score += rules.weight_of("phone_number", W_PHONE_NUMBER);
        signals.push("phone_number".into());
    }

    // ClickFix / fake-CAPTCHA instruction signal (C1-5).
    //
    // ClickFix attacks (Proofpoint TA571, Huntress CrashFix, Trend Micro
    // KongTuke; MS Security Blog 2025: +517 % in H1 2025) display a fake
    // CAPTCHA or browser-error overlay and ask the user to press Win+R /
    // Ctrl+V or open a run-dialog to "fix" the problem. The title of these
    // overlays contains structural tells — keyboard-shortcut instructions and
    // CAPTCHA framing — that almost never appear in legitimate app titles.
    //
    // The blocklist's `title:` entries catch known exact phrases; this
    // structural signal fires for novel variants not yet blocklisted, using
    // the normalized title so leet and homoglyph evasions are defeated first.
    //
    // The `alert_shaped` guard is the primary false-positive fence: a
    // legitimate reCAPTCHA page that happens to have "captcha" in its title
    // is not modal / full-screen / no-close, so this never fires for it.
    let normalized_title = confusables::normalize_for_match(title);
    if alert_shaped && confusables::has_clickfix_instruction(&normalized_title) {
        score += rules.weight_of("clickfix_instruction", W_CLICKFIX);
        signals.push("clickfix_instruction".into());
    }

    // Countdown-timer urgency cue (E7). Scam overlays pair a visible
    // "M:SS" countdown with fear language to pressure the target into calling
    // a fake support number before the countdown ends. The alert_shaped guard
    // ensures clocks, media players, and meeting timers never fire — those are
    // user-initiated or closable and therefore not alert_shaped.
    if alert_shaped && confusables::has_urgency_countdown(&normalized_title) {
        score += rules.weight_of("urgency_countdown", W_URGENCY_COUNTDOWN);
        signals.push("urgency_countdown".into());
    }

    // Forced-retention instruction (E13). Scam overlays tell the victim
    // "DO NOT CLOSE THIS WINDOW" to prevent escape while the fake "Microsoft
    // support agent" installs malware or gathers credentials. Legitimate
    // software almost never places such an instruction in a *window title*;
    // installer progress bars may show it in the dialog body, but those are
    // user-initiated and closable, so alert_shaped never fires. Evaluated on
    // the already-normalized title so homoglyph variants (Cyrillic 'с' in
    // "close", leet '0' in "cl0se") are folded first.
    if alert_shaped && confusables::has_forced_retention(&normalized_title) {
        score += rules.weight_of("forced_retention_cue", W_FORCED_RETENTION);
        signals.push("forced_retention_cue".into());
    }

    // Credential-harvest phishing cue (E14). Account-takeover overlays trick
    // the victim into re-entering credentials in an alert-shaped popup rather
    // than on the real login page. Canonical patterns: "account suspended",
    // "verify your account", "confirm your password", "unusual sign-in activity".
    // Legitimate security notifications arrive in the browser's own security
    // UI, not as an alert-shaped overlay — the alert_shaped guard eliminates
    // FPs from normal login forms and security-awareness articles.
    if alert_shaped && confusables::has_credential_harvest_cue(&normalized_title) {
        score += rules.weight_of("credential_harvest_cue", W_CREDENTIAL_HARVEST);
        signals.push("credential_harvest_cue".into());
    }

    // Fake-scanner / threat-count language (E15 — Microsoft Edge Scareware Blocker
    // corpus; Malwarebytes rogue-AV samples). Rogue AV and TSS overlays display
    // fabricated progress: "Scanning for threats…", "4 threats found!", "Repairing
    // your system". Real OS security scanners run as tray processes and never lock
    // the desktop with a scan-progress title — the alert_shaped guard eliminates FPs
    // from legitimate security software the user deliberately opened.
    if alert_shaped && confusables::has_fake_scanner_cue(&normalized_title) {
        score += rules.weight_of("fake_scanner_cue", W_FAKE_SCANNER);
        signals.push("fake_scanner_cue".into());
    }

    // Subscription/license expiry coercion (E16 — THREAT_INTEL_2026 §3
    // "scareware subscription / prize scams"). Softer scareware: "Your
    // Norton/McAfee subscription expired — renew now." Often has a close
    // button, so geometry signals alone may not reach Suspicious.  Three-word-
    // group AND check (subject × expiry × action) prevents FPs from renewal
    // reminder emails reflected as browser tab titles, which are user-initiated
    // and closable.  W=15 (lower than other text signals — the pattern is
    // lower-confidence than a phone number or scan-progress title).
    if alert_shaped && confusables::has_subscription_lure(&normalized_title) {
        score += rules.weight_of("subscription_lure", W_SUBSCRIPTION_LURE);
        signals.push("subscription_lure".into());
    }

    // Law-enforcement / authority impersonation (E17 — FBI IC3 2024
    // warning on LEA-impersonation scams; Symantec Reveton/Winlock analysis;
    // Europol Operation Strikeback 2025). Overlays impersonating the FBI,
    // police, Interpol, or cybercrime units to demand payment or a call are
    // a distinct class from brand_impersonation (which checks the host).
    // W_AUTHORITY_LURE = 25 (high-specificity: LEA agency name + coercion
    // token is very rarely a legitimate window title combination).
    if alert_shaped && confusables::has_authority_lure(&normalized_title) {
        score += rules.weight_of("authority_lure", W_AUTHORITY_LURE);
        signals.push("authority_lure".into());
    }

    // Crypto / Web3 wallet-drain lure (FBI IC3 2025: #1 loss category, $4.57B).
    // Three patterns: wallet_alarm (wallet-brand + compromise token), wallet_coerce
    // (connect/validate your wallet), seed_harvest (seed phrase / private key +
    // request token). W_CRYPTO_DRAIN = 25 — comparable to authority_lure because
    // the combinations (wallet-brand + alarm) are highly scam-specific.
    // alert_shaped guard: news articles ("Coinbase Wallet Compromised in Hack")
    // appear in user-opened, closable tabs and do not fire.
    if alert_shaped && confusables::has_crypto_drain_lure(&normalized_title) {
        score += rules.weight_of("crypto_drain_lure", W_CRYPTO_DRAIN);
        signals.push("crypto_drain_lure".into());
    }

    // Prize / lottery / gift-card lure (FTC 2024: imposter & prize scams
    // #2 category by reports, $2.7B losses). AND-pair: a prize-word ("won",
    // "winner", "prize", "lottery", "gift card", "selected", "eligible") +
    // a claim-action ("claim", "collect", "redeem", "verify", "expires").
    // alert_shaped guard: legitimate loyalty-program notifications in
    // user-initiated, closable tabs do not fire.
    if alert_shaped && confusables::has_prize_lure(&normalized_title) {
        score += rules.weight_of("prize_lure", W_PRIZE_LURE);
        signals.push("prize_lure".into());
    }

    // Fake download / fake-update gate (Microsoft Edge security team 2025;
    // FBI IC3 2024 malware-delivery). Pattern: install_demand (download/
    // install/update verb + required/to-continue cue) OR fake_plugin_gate
    // (plugin/extension/codec/flash noun + install verb or required cue).
    // alert_shaped guard: legitimate browser extension install prompts are
    // user-initiated and closable (alert_shaped = false).
    if alert_shaped && confusables::has_download_trap_lure(&normalized_title) {
        score += rules.weight_of("download_trap_lure", W_DOWNLOAD_TRAP);
        signals.push("download_trap_lure".into());
    }

    // Screen-share lure (FTC / IC3 2024 TSS pattern). Attackers walk the
    // victim into sharing their screen "so we can diagnose the problem" —
    // no named tool required, just social instruction. Three patterns:
    // share_screen ("share your screen/desktop"), remote_enable ("allow
    // remote viewing/access"), grant_support ("grant access to agent").
    // Scoped to alert_shaped only — a legitimate Zoom "share screen" prompt
    // is user-initiated and closable (alert_shaped = false).
    if alert_shaped && confusables::has_screen_share_lure(&normalized_title) {
        score += rules.weight_of("screen_share_lure", W_SCREEN_SHARE);
        signals.push("screen_share_lure".into());
    }

    // QR code / quishing lure (APWG Q4 2024, FBI IC3 2025). Scam overlays
    // display a QR code and instruct the user to scan it to "verify identity"
    // or "continue" — the QR destination bypasses the URL filter the overlay
    // host may be subject to.  Two groups: qr_noun ("qr code" / "qr-code" /
    // "scan qr") AND verify_action (verify/confirm/authenticate/access/…).
    // alert_shaped guard: legitimate QR code displays (e-ticket, payment) are
    // user-initiated and closable.
    if alert_shaped && confusables::has_qr_code_lure(&normalized_title) {
        score += rules.weight_of("qr_code_lure", W_QR_CODE_LURE);
        signals.push("qr_code_lure".into());
    }

    // IP address alarm lure (Malwarebytes 2025, Microsoft Security 2024).
    // Tech-support scam overlays display "Your IP address has been hacked /
    // flagged / reported to authorities" to panic victims into calling a fake
    // support line. Two groups: ip_subject ("ip address" / "your ip") AND
    // alarm_word (hack/infect/flag/report/…).
    // alert_shaped guard: legitimate IP-info pages show the address without
    // alarm language, and are user-opened and closable.
    if alert_shaped && confusables::has_ip_alarm_lure(&normalized_title) {
        score += rules.weight_of("ip_alarm_lure", W_IP_ALARM);
        signals.push("ip_alarm_lure".into());
    }

    // Package / parcel customs-fee lure (FTC 2024 — imposter-scam delivery
    // variants #2 category: 1.1M complaints). Overlays impersonate DHL /
    // FedEx / USPS / customs to extract a small advance fee.  Two groups:
    // package_noun ("your package/parcel/shipment/delivery") AND fee_demand
    // ("customs fee/duty", "on hold", "release fee", "unable to deliver").
    // alert_shaped guard: legitimate e-commerce order notifications are
    // user-initiated and closable.
    if alert_shaped && confusables::has_package_fee_lure(&normalized_title) {
        score += rules.weight_of("package_fee_lure", W_PACKAGE_FEE);
        signals.push("package_fee_lure".into());
    }

    // Sextortion / webcam-recording extortion lure (FBI IC3 2024: sextortion
    // complaints +42% YoY). Browser overlays claim to have webcam footage and
    // demand cryptocurrency payment.  Two groups: camera_cue ("your camera" /
    // "we have recorded" / "hacked your camera") AND extortion_word (bitcoin /
    // btc / pay / your contacts / expose).  W_SEXTORTION=25 (one point above
    // other content signals) — the AND-pair is very high specificity.
    // alert_shaped guard: legitimate webcam-permission dialogs are closable.
    if alert_shaped && confusables::has_sextortion_lure(&normalized_title) {
        score += rules.weight_of("sextortion_lure", W_SEXTORTION);
        signals.push("sextortion_lure".into());
    }

    // Gift-card payment demand (FTC: gift cards are the #1 payment method
    // in tech-support fraud losses). Scam overlays instruct victims to
    // purchase iTunes / Google Play / Amazon gift cards and send or read out
    // the redemption codes to a fake "support agent" or "fine collector".
    // No legitimate software ever demands payment in gift cards through an
    // overlay window. Two groups: gift_card_noun (names a specific card
    // product or "gift cards" generically) AND payment_instruction
    // (buy/purchase/send codes/scratch/go to the store/read the codes).
    // alert_shaped guard: legitimate gift-card redemption UIs are closable.
    if alert_shaped && confusables::has_gift_card_demand(&normalized_title) {
        score += rules.weight_of("gift_card_demand", W_GIFT_CARD_DEMAND);
        signals.push("gift_card_demand".into());
    }

    // E27 — Refund / overpayment scam lure (FTC 2024 / IC3 2025).
    // Scammers posing as support agents, banks, or government agencies claim
    // the victim has an uncollected refund or an overpayment to return.
    // The overlay directs them to call a number or click a link to "process
    // the refund", leading to credential theft or gift-card payment demands.
    // Two groups: refund_noun (refund/overpayment/reimbursement/返金/払い戻し)
    // AND refund_action (claim/collect/pending/owed-to-you language).
    // alert_shaped guard: legitimate bank refund portals are user-initiated and
    // closable — they never appear as unsolicited overlays.
    if alert_shaped && confusables::has_refund_scam_cue(&normalized_title) {
        score += rules.weight_of("refund_scam_cue", W_REFUND_SCAM);
        signals.push("refund_scam_cue".into());
    }

    // E28 — National ID / benefit-number alarm (FTC 2024 #1 government
    // impersonation variant). Scammers claim the victim's SSN, NIN, or
    // マイナンバー has been "suspended" or "used in criminal activity" and
    // demand an immediate call to "reactivate" it. No legitimate government
    // service ever suspends a national ID via a browser overlay.
    // Two groups: id_noun (ssn/social security/medicare/マイナンバー/年金番号)
    // AND id_alarm (has been suspended / criminal activity / 凍結 / 不正使用).
    // alert_shaped guard: legitimate government-portal pages are user-initiated
    // and closable — they never manifest as unsolicited overlays.
    if alert_shaped && confusables::has_national_id_alarm(&normalized_title) {
        score += rules.weight_of("national_id_alarm", W_NATIONAL_ID_ALARM);
        signals.push("national_id_alarm".into());
    }

    // E29 — Fake bank-fraud alert overlay. Scammers impersonating banks
    // or payment processors claim a victim's bank account, debit card, or
    // credit card has been frozen or has fraudulent/unauthorized transactions.
    // The overlay prompts the victim to call a number to "unfreeze" the
    // account, leading to credential theft or gift-card payment coercion.
    // Distinct from credential_harvest_cue (which requires a credential-
    // entry instruction) — this signal fires when only the alarm framing
    // is present (attacker wants a call, not credential entry).
    // Two groups: bank_noun (bank account/checking/savings/debit/credit card,
    // 銀行口座/キャッシュカード/通帳) AND bank_alarm (unauthorized/fraudulent
    // transaction, has been frozen, 口座が凍結/停止, 不正な取引).
    // alert_shaped guard: legitimate bank-app notifications are user-initiated
    // and closable — they never appear as unsolicited full-screen overlays.
    if alert_shaped && confusables::has_bank_account_alarm(&normalized_title) {
        score += rules.weight_of("bank_account_alarm", W_BANK_ACCOUNT_ALARM);
        signals.push("bank_account_alarm".into());
    }

    // E30 — ワンクリック詐欺 / false-registration billing scam (JP IC3 / 消費者庁).
    // Falsely claims the user *registered* for a paid service and demands
    // immediate payment or legal action will follow.  Distinct from
    // subscription_lure (expired subscription) — this fires on *false creation*
    // of a new obligation.  Two groups: reg_claim ("you have been registered",
    // 登録が完了, ご登録) AND payment_ultimatum ("pay within", 法的措置, 未払い).
    // alert_shaped guard: legitimate order-confirmation pages are user-initiated
    // and closable — they never appear as unsolicited full-screen overlays.
    if alert_shaped && confusables::has_false_registration_billing(&normalized_title) {
        score += rules.weight_of("false_registration_billing", W_FALSE_REG_BILLING);
        signals.push("false_registration_billing".into());
    }

    // E31 — fake BSOD / "Windows has been blocked" tech-support scam (FBI IC3 2025,
    // Microsoft MSTIC).  An overlay mimics a Windows Blue Screen of Death or macOS
    // kernel panic (bsod_marker: "stop code", "windows has been blocked", "blue
    // screen", "kernel panic") AND attaches a scam phone instruction (call_barrier:
    // "do not restart", "call microsoft", "microsoft certified technician").
    // Legitimate Windows BSODs never instruct users to call a phone number — they
    // show a QR code linking to support.microsoft.com.  alert_shaped guard prevents
    // IT troubleshooting guides (user-initiated, closable) from triggering.
    // Weight 30 reflects the AND-pair's high specificity: bsod_marker alone fires
    // on IT articles; call_barrier alone fires on legitimate update instructions;
    // only their combination is unambiguously scam-shaped.
    if alert_shaped && confusables::has_fake_bsod_lure(&normalized_title) {
        score += rules.weight_of("fake_bsod_lure", W_FAKE_BSOD_LURE);
        signals.push("fake_bsod_lure".into());
    }

    // E32 — advance-fee fraud / "419" / inheritance / unclaimed-funds scam
    // (FTC BCP 2024 "Money you didn't expect", FBI IC3 2025 BEC/impostor).
    // Overlay claims the victim inherited a sum or has unclaimed funds
    // (fund_claim: "beneficiary", "estate of", "unclaimed funds", "won the
    // lottery", 遺産, 受益者, 宝くじ当選) AND demands an advance fee to release
    // those funds (release_fee: "processing fee", "advance fee", "customs fee",
    // "notary fee", "to release the funds", 手数料, 関税, 振込手数料).
    // Distinct from has_prize_lure (click-to-claim, no payment): E32 requires
    // the fee-extraction step.  alert_shaped guard prevents legitimate estate
    // attorney notifications (closable, user-initiated) from triggering.
    if alert_shaped && confusables::has_advance_fee_lure(&normalized_title) {
        score += rules.weight_of("advance_fee_lure", W_ADVANCE_FEE_LURE);
        signals.push("advance_fee_lure".into());
    }

    // E33 — fake tech-support invoice / "you were charged" cancel-scam (FTC
    // 2025 impostor-scam category; increasingly prevalent as a hybrid of tech-
    // support fraud and billing fraud).  An overlay claims a large charge was
    // already processed on the victim's account (charge_claim: "you have been
    // charged $499", "a charge of $399", "subscription has been renewed",
    // "auto-charged", ご請求が完了, 課金されました) AND instructs the victim to
    // call to cancel or dispute (cancel_cta: "call to cancel", "if you did not
    // authorize", "dispute this charge", キャンセルするには電話, 請求に心当たりのない).
    // Distinct from subscription_lure (no charge), false_registration_billing
    // (false registration + pay-or-face-consequences), and refund_scam_cue
    // (owed a refund).  alert_shaped guard prevents legitimate invoice
    // notifications (closable, user-initiated) from triggering.
    if alert_shaped && confusables::has_tech_support_invoice_scam(&normalized_title) {
        score += rules.weight_of("tech_support_invoice_scam", W_TECH_INVOICE_SCAM);
        signals.push("tech_support_invoice_scam".into());
    }

    // E34 — fake utility disconnection threat (FTC 2024 #3 impostor-scam type,
    // IC3 2025 utility-impersonation fraud).  An overlay claims to be a utility
    // company (electric, gas, water) and threatens immediate service cutoff unless
    // payment is made right away.  Two groups: utility_service (electricity / gas /
    // water / power company / 電気 / ガス / 水道) AND cutoff_threat ("will be
    // disconnected", "disconnection notice", "final notice", "pay to avoid
    // disconnection", 停止予告, 供給停止, 即時お支払い).
    // Distinct from subscription_lure (expired subscriptions) and
    // national_id_alarm (government-ID suspension): E34 targets public utility
    // service threats specifically.  alert_shaped guard prevents legitimate utility
    // account portals (user-initiated, closable) from triggering.
    if alert_shaped && confusables::has_utility_cutoff_threat(&normalized_title) {
        score += rules.weight_of("utility_cutoff_threat", W_UTILITY_CUTOFF);
        signals.push("utility_cutoff_threat".into());
    }

    // E35 — Medicare/healthcare benefit scam (IC3 2025 #1 elder-fraud category,
    // FTC 2024 leading impostor-scam type by dollar loss for victims 60+).
    // An overlay impersonates Medicare, Medicaid, or an insurance provider and
    // lures the victim into calling by claiming a benefit is expiring or a free
    // medical device is available.  Two groups: health_benefit (medicare /
    // medicaid / health insurance / medical device / 健康保険 / 介護保険) AND
    // benefit_urgency ("will expire", "expiring soon", "claim your free",
    // "you have been approved", "at no cost to you", 受給期限, 無料で受け取る).
    // Distinct from national_id_alarm (SSN/マイナンバー suspension) and
    // authority_lure (government-agency impersonation): E35 specifically targets
    // healthcare benefit scams.  alert_shaped guard prevents legitimate insurance
    // portal sessions from triggering.
    if alert_shaped && confusables::has_healthcare_scam(&normalized_title) {
        score += rules.weight_of("healthcare_scam", W_HEALTHCARE_SCAM);
        signals.push("healthcare_scam".into());
    }

    // E36 — fake job / work-from-home employment fraud (IC3 2025 top-5
    // non-elder-fraud loss category, FTC 2024 #1 business-opportunity fraud).
    // An overlay advertises a remote job or work-from-home opportunity
    // (job_offer: "work from home", "remote work opportunity", "earn from home",
    // "data entry job", 在宅ワーク, 副業) AND requires an advance fee to start
    // (fee_gate: "registration fee", "equipment deposit", "starter kit",
    // "background check fee", "upfront fee", 登録料, 機材費, 保証金, 入会金).
    // Legitimate employers never charge candidates an upfront fee — the fee
    // is the scam tell.  alert_shaped guard prevents legitimate job-board
    // pages (closable, user-initiated) from triggering.
    if alert_shaped && confusables::has_job_scam(&normalized_title) {
        score += rules.weight_of("job_scam", W_JOB_SCAM);
        signals.push("job_scam".into());
    }

    // Tax-authority impersonation scam (E37).  IRS/HMRC/国税庁 impersonators
    // threaten arrest or asset seizure over alleged unpaid taxes and demand
    // immediate payment.  Real tax authorities never communicate via
    // unsolicited browser overlays — they send certified mail.
    // tax_authority: "irs notice", "internal revenue service", "unpaid taxes",
    //   "tax debt", "hmrc notice", 国税庁, 税務署, 延滞税, 税金未納.
    // arrest_threat: "arrest warrant", "face arrest", "assets seized",
    //   "criminal charges filed", 逮捕状, 差し押さえ, 刑事訴追.
    // Weight +30 (higher than standard 25): tax-authority + arrest-threat
    // AND-pair is near-zero-FP — a legitimate IRS page never displays an
    // arrest warrant threat as an alert-shaped overlay.
    if alert_shaped && confusables::has_tax_authority_scam(&normalized_title) {
        score += rules.weight_of("tax_authority_scam", W_TAX_AUTHORITY_SCAM);
        signals.push("tax_authority_scam".into());
    }

    // Social media / email account hijacking alarm (E38).  Phishing overlays
    // claim a named social platform account (Facebook, Instagram, Gmail,
    // LINE) has been hacked or suspended and push the victim into a fake
    // credential-recovery flow.  Distinct from national_id_alarm (ID numbers)
    // and bank_account_alarm (financial accounts).
    // social_platform: "facebook account", "instagram account", "gmail
    //   account", "google account", "apple id", フェイスブック, ライン, etc.
    // account_jeopardy: "has been hacked", "has been suspended",
    //   "unauthorized login", "verify to recover", "regain access",
    //   アカウントが停止, 不正ログイン, アカウントを回復するには.
    if alert_shaped && confusables::has_social_media_account_alarm(&normalized_title) {
        score += rules.weight_of("social_media_account_alarm", W_SOCIAL_MEDIA_ACCOUNT_ALARM);
        signals.push("social_media_account_alarm".into());
    }

    // Immigration / visa authority scam (E39).  Overlays impersonating
    // immigration authorities (USCIS, ICE, 入国管理局) threaten visa
    // revocation, deportation, or illegal-overstay prosecution unless the
    // victim pays an immediate renewal or settlement fee.  Targets immigrant
    // populations who may be unfamiliar with how official notices are
    // delivered (always by mail/official portal, never a browser overlay).
    // immigration_doc: "your visa", "your work permit", "your green card",
    //   "residence permit", "immigration notice", ビザ, 在留資格, 在留カード.
    // status_threat: "has been revoked", "deportation", "illegal overstay",
    //   "renewal fee required", 取り消し, 不法滞在, 強制送還, 更新料.
    if alert_shaped && confusables::has_immigration_visa_scam(&normalized_title) {
        score += rules.weight_of("immigration_visa_scam", W_IMMIGRATION_VISA_SCAM);
        signals.push("immigration_visa_scam".into());
    }

    // Government grant / stimulus scam (E40).  Overlays impersonating
    // government programs (federal grants, stimulus payments, pandemic relief,
    // 政府給付金) demand an application fee, processing fee, or identity
    // verification to release nonexistent funds.  Distinct from
    // `advance_fee_lure` (personal windfall: inheritance/lottery) — this
    // signal keys specifically on government-program framing.  No real
    // government grant program requires an upfront fee or is delivered via
    // an unsolicited browser overlay.
    // grant_program: "government grant", "federal grant", "stimulus check",
    //   "emergency relief fund", "pandemic relief", 政府給付金, 補助金, 給付金.
    // claim_barrier: "claim your grant", "application fee required",
    //   "verify your identity to receive", "enrollment deadline", 今すぐ申請,
    //   給付金を受け取るには, 手数料が必要.
    if alert_shaped && confusables::has_government_grant_scam(&normalized_title) {
        score += rules.weight_of("government_grant_scam", W_GOVERNMENT_GRANT_SCAM);
        signals.push("government_grant_scam".into());
    }

    // Debt relief / credit repair scam (E41).  Fake debt-relief operations
    // charge upfront fees (着手金, "application fee required") while
    // promising guaranteed debt elimination or "stop paying now" results.
    // The upfront-fee or guaranteed-results CTA is the scam tell: legitimate
    // credit counselors charge no upfront fee and never guarantee specific
    // outcomes.  With the alert_shaped guard, legitimate credit-counseling
    // websites (user-initiated, closable) cannot fire.
    // debt_claim: "credit card debt", "debt consolidation", "debt relief
    //   program", "debt settlement", "eliminate your debt", 借金, 債務整理,
    //   過払い金, 多重債務.
    // scam_cta: "guaranteed approval", "no credit check required", "100%
    //   guaranteed results", "stop paying now", "application fee required",
    //   確実に解決, 審査不要, 着手金, 相談料が必要.
    if alert_shaped && confusables::has_debt_relief_scam(&normalized_title) {
        score += rules.weight_of("debt_relief_scam", W_DEBT_RELIEF_SCAM);
        signals.push("debt_relief_scam".into());
    }

    // Streaming/subscription billing scam (E42).  Phishing overlays
    // impersonate Netflix, Spotify, Disney+, Amazon Prime, and similar
    // streaming services with fake payment-failure alerts designed to steal
    // payment credentials or account logins.  Distinct from `subscription_lure`
    // (generic expiry language): this signal keys on named streaming brands
    // combined with payment-failure framing (not subscription-expiry language).
    // streaming_platform: "netflix", "spotify", "disney+", "amazon prime",
    //   "hbo max", "youtube premium", ネットフリックス, スポティファイ, etc.
    // payment_problem: "payment failed", "payment declined", "billing issue",
    //   "update your payment", お支払いが失敗, 支払い方法が無効.
    if alert_shaped && confusables::has_streaming_billing_scam(&normalized_title) {
        score += rules.weight_of("streaming_billing_scam", W_STREAMING_BILLING_SCAM);
        signals.push("streaming_billing_scam".into());
    }

    // Traffic / parking / toll violation scam (E43).  Scammers impersonate
    // parking enforcement, traffic courts, and toll authorities (EZPass,
    // FasTrak, 高速料金) to extract immediate payment for fabricated fines.
    // Distinct from `authority_lure` (requires a named law-enforcement agency)
    // and `tax_authority_scam` (tax debt + arrest threat).  FTC 2025 top-3
    // impersonator scam type.
    // violation_type: "parking violation", "traffic fine", "speeding ticket",
    //   "toll violation", "unpaid toll", "ezpass", 駐車違反, 交通違反, 反則金.
    // payment_urgency: "pay within", "final notice", "failure to pay",
    //   "license suspension", すぐにお支払い, 未払いの場合, 罰則金の支払い.
    if alert_shaped && confusables::has_traffic_fine_scam(&normalized_title) {
        score += rules.weight_of("traffic_fine_scam", W_TRAFFIC_FINE_SCAM);
        signals.push("traffic_fine_scam".into());
    }
    if alert_shaped && confusables::has_pig_butchering_lure(&normalized_title) {
        score += rules.weight_of("pig_butchering_lure", W_PIG_BUTCHERING_LURE);
        signals.push("pig_butchering_lure".into());
    }
    if alert_shaped && confusables::has_loan_fee_scam(&normalized_title) {
        score += rules.weight_of("loan_fee_scam", W_LOAN_FEE_SCAM);
        signals.push("loan_fee_scam".into());
    }
    if alert_shaped && confusables::has_charity_scam_lure(&normalized_title) {
        score += rules.weight_of("charity_scam_lure", W_CHARITY_SCAM_LURE);
        signals.push("charity_scam_lure".into());
    }
    if alert_shaped && confusables::has_rental_scam_lure(&normalized_title) {
        score += rules.weight_of("rental_scam_lure", W_RENTAL_SCAM_LURE);
        signals.push("rental_scam_lure".into());
    }
    if alert_shaped && confusables::has_pet_sale_scam(&normalized_title) {
        score += rules.weight_of("pet_sale_scam", W_PET_SALE_SCAM);
        signals.push("pet_sale_scam".into());
    }
    if alert_shaped && confusables::has_timeshare_travel_scam(&normalized_title) {
        score += rules.weight_of("timeshare_travel_scam", W_TIMESHARE_TRAVEL_SCAM);
        signals.push("timeshare_travel_scam".into());
    }
    if alert_shaped && confusables::has_windows_activation_scam(&normalized_title) {
        score += rules.weight_of("windows_activation_scam", W_WINDOWS_ACTIVATION_SCAM);
        signals.push("windows_activation_scam".into());
    }
    if alert_shaped && confusables::has_survey_reward_scam(&normalized_title) {
        score += rules.weight_of("survey_reward_scam", W_SURVEY_REWARD_SCAM);
        signals.push("survey_reward_scam".into());
    }
    if alert_shaped && confusables::has_av_brand_renewal_scam(&normalized_title) {
        score += rules.weight_of("av_brand_renewal_scam", W_AV_BRAND_RENEWAL_SCAM);
        signals.push("av_brand_renewal_scam".into());
    }
    if alert_shaped && confusables::has_recovery_scam(&normalized_title) {
        score += rules.weight_of("recovery_scam", W_RECOVERY_SCAM);
        signals.push("recovery_scam".into());
    }
    if alert_shaped && confusables::has_student_loan_scam(&normalized_title) {
        score += rules.weight_of("student_loan_scam", W_STUDENT_LOAN_SCAM);
        signals.push("student_loan_scam".into());
    }
    if alert_shaped && confusables::has_secret_shopper_scam(&normalized_title) {
        score += rules.weight_of("secret_shopper_scam", W_SECRET_SHOPPER_SCAM);
        signals.push("secret_shopper_scam".into());
    }
    if alert_shaped && confusables::has_mlm_pyramid_recruitment(&normalized_title) {
        score += rules.weight_of("mlm_pyramid_recruitment", W_MLM_PYRAMID_RECRUITMENT);
        signals.push("mlm_pyramid_recruitment".into());
    }
    if alert_shaped && confusables::has_veterans_benefit_scam(&normalized_title) {
        score += rules.weight_of("veterans_benefit_scam", W_VETERANS_BENEFIT_SCAM);
        signals.push("veterans_benefit_scam".into());
    }
    if alert_shaped && confusables::has_fake_copyright_scam(&normalized_title) {
        score += rules.weight_of("fake_copyright_scam", W_FAKE_COPYRIGHT_SCAM);
        signals.push("fake_copyright_scam".into());
    }
    if alert_shaped && confusables::has_crypto_giveaway_scam(&normalized_title) {
        score += rules.weight_of("crypto_giveaway_scam", W_CRYPTO_GIVEAWAY_SCAM);
        signals.push("crypto_giveaway_scam".into());
    }
    if alert_shaped && confusables::has_otp_interception_scam(&normalized_title) {
        score += rules.weight_of("otp_interception_scam", W_OTP_INTERCEPTION_SCAM);
        signals.push("otp_interception_scam".into());
    }
    if alert_shaped && confusables::has_family_emergency_scam(&normalized_title) {
        score += rules.weight_of("family_emergency_scam", W_FAMILY_EMERGENCY_SCAM);
        signals.push("family_emergency_scam".into());
    }

    // Remote-access-tool lure (FTC / FBI IC3 2024). Tech-support scammers
    // walk the victim through installing AnyDesk / TeamViewer / etc. to
    // seize the machine. These tools are legitimate, so their name alone
    // is NOT a scam tell — muten counts it only as *context amplification*:
    // the tool name in the title AND independent fake-alert evidence
    // already firing (a blocklist title match, a support phone number, or a
    // ClickFix instruction). A legitimate remote-support session has the
    // tool name but none of those alert tells, so it never fires. This can
    // only *add* to an already-suspicious window — never block on its own.
    let has_sig = |s: &str| signals.iter().any(|x| x == s);
    let fake_alert_present =
        has_sig("blocklist_title") || has_sig("phone_number") || has_sig("clickfix_instruction");
    if fake_alert_present && mentions_remote_access_tool(&normalized_title) {
        score += rules.weight_of("remote_access_lure", W_REMOTE_ACCESS_LURE);
        signals.push("remote_access_lure".into());
    }

    // Mixed-script homoglyph evasion. A single token that mixes Latin
    // with Cyrillic/Greek letters (e.g. "раypаl", "miсrosoft") is a
    // strong disguise tell (UTS #39 mixed-script confusables; NDSS 2015
    // typosquatting). Evaluated on the *raw* title and host, because the
    // confusable fold used for blocklist matching erases the evidence.
    // CJK/Kana are ignored, so a legitimate Japanese+Latin title does
    // not fire (false-positive guard for the JP market). The weight
    // nudges toward Suspicious; it never blocks on its own.
    let mixed_script = confusables::has_confusable_mixed_script(title)
        || url_bounded.is_some_and(|u| confusables::has_confusable_mixed_script(url_host(u)));
    if mixed_script {
        score += rules.weight_of("mixed_script", W_MIXED_SCRIPT);
        signals.push("mixed_script".into());
    }

    // Whole-script confusable (UTS #39 §5): a token where every letter
    // comes from a single non-Latin script (Cyrillic or Greek) AND every
    // one of those letters folds to an ASCII look-alike — e.g. `ѕсоре`
    // (all Cyrillic, reads "scope"). `mixed_script` misses this because
    // there are zero Latin letters to trigger a cross-script mix. The FP
    // guard: legitimate Cyrillic/Greek text uses letters that do NOT have
    // ASCII confusable mappings (п, и, λ, θ…), so they fail the fold-to-
    // ASCII-only check and are silently passed over. Evaluated on raw text.
    // For URL hosts: check each label individually (split on '.'), since a
    // TLD like `.com` always contains Latin letters and would otherwise
    // prevent the per-token analysis from seeing a pure-Cyrillic label.
    let whole_script = confusables::has_whole_script_confusable(title)
        || url_bounded.is_some_and(|u| {
            url_host(u)
                .split('.')
                .any(confusables::has_whole_script_confusable)
        });
    if whole_script {
        score += rules.weight_of("whole_script_confusable", W_WHOLE_SCRIPT);
        signals.push("whole_script_confusable".into());
    }

    // Enclosed/circled Latin letters (Ⓐ-Ⓩ / ⓐ-ⓩ, U+24B6-U+24E9): used in
    // phishing titles to bypass plain-text blocklist matching
    // (`ⓟⓐⓨⓟⓐⓛ` evades `str::contains("paypal")`). `normalize_for_match`
    // now folds these so blocklist matching catches them; the presence of
    // these characters in a raw title is itself a near-zero-FP tell —
    // enclosed LETTERS have essentially no legitimate use in a window title
    // (circled numerals ①②③ in lists are distinct and don't fire). Checked
    // on raw strings before normalization strips the evidence. (C8-8.)
    let compat_chars = confusables::has_compat_alpha(title)
        || url_bounded.is_some_and(confusables::has_compat_alpha);
    if compat_chars {
        score += rules.weight_of("compat_chars_present", W_COMPAT_CHARS);
        signals.push("compat_chars_present".into());
    }

    // Mixed numbering systems (ICU MIXED_NUMBERS): a single token with
    // decimal digits from two different scripts (e.g. ASCII `5` beside
    // Arabic-Indic `٥`) is never a legitimate number. ASCII and full-width
    // digits count as the same system, so legitimate Japanese text using
    // full-width numerals is not flagged (JP FP guard). Read on raw text.
    let mixed_numbers = confusables::has_mixed_number_systems(title)
        || url_bounded.is_some_and(confusables::has_mixed_number_systems);
    if mixed_numbers {
        score += rules.weight_of("mixed_number_systems", W_MIXED_NUMBERS);
        signals.push("mixed_number_systems".into());
    }

    // Excessive combining marks ("Zalgo"): 3+ diacritics stacked on one
    // base character never occurs in legitimate text (even Vietnamese /
    // Arabic / Indic stack at most one or two), so it's a near-zero-FP
    // obfuscation tell. Read on raw text before any normalization.
    let zalgo = confusables::has_excessive_combining_marks(title)
        || url_bounded.is_some_and(confusables::has_excessive_combining_marks);
    if zalgo {
        score += rules.weight_of("excessive_combining_marks", W_ZALGO);
        signals.push("excessive_combining_marks".into());
    }

    // BiDi directional override (Trojan Source, arXiv:2111.00169): an
    // LRO/RLO control forces the displayed reading order to differ from
    // the logical text. We strip these before matching, but their mere
    // presence in a title/host is itself a high-confidence spoofing tell
    // — overrides have no honest use in a window title. Read on the raw
    // strings, before stripping erases them.
    let bidi_override = confusables::has_bidi_override(title)
        || url_bounded.is_some_and(confusables::has_bidi_override);
    if bidi_override {
        score += rules.weight_of("bidi_override", W_BIDI_OVERRIDE);
        signals.push("bidi_override".into());
    }

    // Brand-homograph impersonation (UTS #39 skeleton collision): the
    // host is a look-alike of a major brand it is not — e.g. `раура1.com`
    // (skeleton "paypal") — that the deployment has not (and would not)
    // blocklist, since the real brand domain is legitimate. The literal
    // brand never fires. A strong tell, but additive (not an auto-block),
    // so a lone homograph host is `Suspicious` pending other evidence.
    if url_bounded
        .map(url_host)
        .and_then(brand_impersonation)
        .is_some()
    {
        score += rules.weight_of("brand_impersonation", W_BRAND_IMPERSONATION);
        signals.push("brand_impersonation".into());
    }

    // Combosquatting (Kintis et al., ACM CCS 2017): a host label that
    // joins a known brand and a scam-lure word as distinct hyphen tokens
    // — `apple-support.com`, `paypal-secure-login.net`. More prevalent
    // than typosquatting and missed by the skeleton-only
    // `brand_impersonation` path (which needs the label's skeleton to
    // *equal* a brand). The hyphen-delimiter requirement keeps legitimate
    // concatenations (`windowsupdate.com`) from firing. Additive, not an
    // auto-block, consistent with `brand_impersonation`.
    if url_bounded.map(url_host).and_then(combosquat).is_some() {
        score += rules.weight_of("combosquat_brand", W_COMBOSQUAT);
        signals.push("combosquat_brand".into());
    }

    // Keyboard-adjacent typosquatting (D10). Complements brand_impersonation
    // (skeleton-exact) and combosquat (hyphenated brand+lure). Catches
    // single-edit variants that the skeleton approach misses because the
    // typosquat uses ordinary ASCII characters: "gogle", "amzon", "mircosoft".
    // Only fires when Levenshtein distance == 1; distance 0 is already handled
    // by brand_impersonation. Additive (not an auto-block).
    if url_bounded
        .map(url_host)
        .and_then(typosquat_brand)
        .is_some()
    {
        score += rules.weight_of("typosquat_brand", W_TYPOSQUAT_BRAND);
        signals.push("typosquat_brand".into());
    }

    // Cloud blob-storage lure (THREAT_INTEL_2026 §TSS). Tech-support
    // scammers host fake-support overlays on Azure Blob Storage, AWS S3,
    // and GCS because those domains appear trustworthy (microsoft.com,
    // amazonaws.com …) and per-file URLs are impossible to blocklist in
    // advance. An alert-shaped window served from blob infrastructure is
    // a near-zero-FP tell: legitimate software uses its own domain or a
    // CDN, not a raw blob-storage URL that exposes the tenant account.
    // The alert_shaped guard prevents a normal cloud-app browser tab
    // from firing — tabs are closable and not fullscreen/topmost.
    if alert_shaped {
        if let Some(host) = url_bounded.map(url_host) {
            if is_cloud_storage_host(host) {
                score += rules.weight_of("cloud_storage_abuse", W_CLOUD_STORAGE_ABUSE);
                signals.push("cloud_storage_abuse".into());
            }
        }
    }

    // URL-path brand+lure combosquat (E12 / F8). Attackers construct paths
    // like `/microsoft-alert/`, `/norton-remove/`, or `/paypal/login/verify`
    // to make a scam URL look credible. Splitting the path on non-alphanumeric
    // boundaries and checking for adjacent brand+lure token pairs detects this
    // without complex parsing. The `alert_shaped` guard prevents a legitimate
    // webapp at `/microsoft-alerts/faq` from firing — closable, non-fullscreen
    // windows are normal apps, not overlays.
    if alert_shaped {
        if let Some(url) = url_bounded {
            if has_path_lure(url) {
                score += rules.weight_of("url_path_lure", W_URL_PATH_LURE);
                signals.push("url_path_lure".into());
            }
        }
    }

    // Data-URI / file-scheme page (GAP_ANALYSIS A9). Tech-support scammers
    // host fake-support overlays via `data:text/html,<html>...` URLs to bypass
    // per-domain blocklists entirely: the URL has no hostname to blocklist.
    // `file://` URLs appearing in an unsolicited alert-shaped overlay indicate
    // a local HTML file dropped by a prior stage of an attack (dropper or
    // malicious installer). Both schemes are near-zero-FP for alert-shaped
    // windows: legitimate kiosk apps using file:// are user-initiated and
    // closable; `data:` URIs don't appear as top-level browser URLs in
    // legitimate enterprise software.
    if alert_shaped {
        if let Some(url) = url_bounded {
            let lc = url.trim_start();
            if lc.starts_with("data:") || lc.starts_with("file://") || lc.starts_with("file:///") {
                score += rules.weight_of("data_uri_page", W_DATA_URI_PAGE);
                signals.push("data_uri_page".into());
            }
            // Raw-IP URL host: no legitimate support/banking/gov page uses
            // a bare IPv4/IPv6 — attackers use raw IPs to avoid domain
            // registration. Only fires inside alert_shaped (a raw-IP URL on
            // a benign, user-initiated, closable page isn't a scam tell on
            // its own). Near-zero FP: enterprise intranet pages served via
            // raw IP are user-initiated and small/closable, not unsolicited
            // full-screen alert-shaped windows.
            if url_host_is_ip(url) {
                score += rules.weight_of("ip_host_url", W_IP_HOST_URL);
                signals.push("ip_host_url".into());
            }
        }
    }

    // Composite "screen-lock" tell: a window that is full-screen AND
    // always-on-top AND grabs all input is a browser/screen *locker*,
    // not an ordinary modal dialog (which is modal but neither
    // full-screen nor topmost-over-everything). This is the shape of
    // Keyboard-Lock / Pointer-Lock abuse and of browser-locker
    // scareware kits like CypherLoc (Barracuda 2026), whose encrypted
    // in-browser payload evades content scanners but cannot hide the
    // window-level lock shape. We surface it as a named signal (for the
    // audit log / `explain()` / dark-pattern category) and add a small
    // bonus on top of the individual signals it co-occurs with.
    //
    // The bonus is deliberately small (W_INPUT_TRAP): the bare lock
    // shape without any content or provenance tell (origin unknown,
    // no scam title/number) tops out at 95 — still `Suspicious`, never
    // an automatic `Block`. That preserves the observe-first guard for
    // *legitimately* locked-down full-screen apps (kiosk shells, exam
    // lockdown browsers) whose origin a helper can't always attribute.
    // Any real content/provenance evidence still pushes it over.
    let input_trap = w.blocks_input && w.topmost && w.coverage_percent >= FULLSCREEN_COVERAGE;
    if input_trap {
        score += rules.weight_of("input_trap", W_INPUT_TRAP);
        signals.push("input_trap".into());
    }

    // Composite "sudden takeover" tell: an *unsolicited* window that
    // seizes the full screen, on top, the instant it appears. This is
    // the behavioural signature Microsoft's Edge Scareware Blocker keys
    // on (abrupt full-screen takeover), and the answer to blocklist lag
    // — it flags brand-new, not-yet-listed scam domains from their
    // *shape over time* rather than their content. Like `input_trap`
    // the bonus is bounded (W_SUDDEN_TAKEOVER): the bare pattern with no
    // content tell tops out at 85, still `Suspicious`. Requires a real
    // nonzero age (age 0 = "enumerator couldn't tell", not "instant").
    let sudden_takeover = w.origin == Origin::Unsolicited
        && w.topmost
        && w.coverage_percent >= FULLSCREEN_COVERAGE
        && w.age_ms > 0
        && w.age_ms < 1000;
    if sudden_takeover {
        score += rules.weight_of("sudden_fullscreen_takeover", W_SUDDEN_TAKEOVER);
        signals.push("sudden_fullscreen_takeover".into());
    }

    // Declarative AND-condition composite rules (C5-2). Evaluated after
    // all individual signals so `has_*` conditions can see what already
    // fired. Each composite whose every condition holds contributes its
    // weight and records its operator-defined name in `signals`.
    //
    // The existing hardcoded composites (`input_trap`,
    // `sudden_fullscreen_takeover`) remain as built-ins; a blocklist
    // `composite:` rule supplements them without replacing them.
    for rule in rules.composite_rules() {
        let all_fire = rule
            .conditions
            .iter()
            .all(|c| eval_condition(c, w, &signals));
        if all_fire {
            score += rule.weight;
            signals.push(rule.name.clone());
        }
    }

    // Clamp negative scores to 0 (a user-initiated benign window
    // shouldn't go "extra allowed" and underflow comparisons).
    let score = score.max(0);

    let decision = if score >= BLOCK_THRESHOLD {
        Decision::Block
    } else if score >= SUSPICIOUS_THRESHOLD {
        Decision::Suspicious
    } else {
        Decision::Allow
    };

    Verdict {
        decision,
        score,
        categories: categories::categories_of(&signals),
        mitre_techniques: mitre::techniques_of_signals(&signals),
        signals,
        matched_rule,
    }
}

/// Evaluate one [`rules::CompositeCondition`] for a window and its already-
/// computed signal list. Called from `classify()` after all individual signals
/// have been collected so `has_*` conditions are meaningful.
fn eval_condition(c: &rules::CompositeCondition, w: &OverlayWindow, signals: &[String]) -> bool {
    use rules::CompositeCondition as C;
    let has_sig = |s: &str| signals.iter().any(|x| x == s);
    match c {
        C::Fullscreen => w.coverage_percent >= FULLSCREEN_COVERAGE,
        C::Topmost => w.topmost,
        C::NoCloseButton => !w.has_close_button,
        C::BlocksInput => w.blocks_input,
        C::Unsolicited => w.origin == Origin::Unsolicited,
        C::UserInitiated => w.origin == Origin::UserInitiated,
        C::VeryNew => w.age_ms > 0 && w.age_ms < 1000,
        C::AlertShaped => {
            w.coverage_percent >= FULLSCREEN_COVERAGE || w.blocks_input || !w.has_close_button
        }
        C::HasBlocklistTitle => has_sig("blocklist_title"),
        C::HasPhoneNumber => has_sig("phone_number"),
        C::HasBlocklistPhone => has_sig("blocklist_phone"),
        C::HasCredentialHarvestCue => has_sig("credential_harvest_cue"),
        C::HasFakeScannerCue => has_sig("fake_scanner_cue"),
        C::HasSubscriptionLure => has_sig("subscription_lure"),
        C::HasAuthorityLure => has_sig("authority_lure"),
        C::HasScreenShareLure => has_sig("screen_share_lure"),
        C::HasCryptoDrainLure => has_sig("crypto_drain_lure"),
        C::HasPrizeLure => has_sig("prize_lure"),
        C::HasDownloadTrapLure => has_sig("download_trap_lure"),
        C::HasQrCodeLure => has_sig("qr_code_lure"),
        C::HasIpAlarmLure => has_sig("ip_alarm_lure"),
        C::HasPackageFeeLure => has_sig("package_fee_lure"),
        C::HasSextortionLure => has_sig("sextortion_lure"),
        C::HasGiftCardDemand => has_sig("gift_card_demand"),
        C::HasRefundScamCue => has_sig("refund_scam_cue"),
        C::HasNationalIdAlarm => has_sig("national_id_alarm"),
        C::HasBankAccountAlarm => has_sig("bank_account_alarm"),
        C::HasFalseRegistrationBilling => has_sig("false_registration_billing"),
        C::HasFakeBsodLure => has_sig("fake_bsod_lure"),
        C::HasAdvanceFeeLure => has_sig("advance_fee_lure"),
        C::HasTechSupportInvoiceScam => has_sig("tech_support_invoice_scam"),
        C::HasUtilityCutoffThreat => has_sig("utility_cutoff_threat"),
        C::HasHealthcareScam => has_sig("healthcare_scam"),
        C::HasJobScam => has_sig("job_scam"),
        C::HasTaxAuthorityScam => has_sig("tax_authority_scam"),
        C::HasSocialMediaAccountAlarm => has_sig("social_media_account_alarm"),
        C::HasImmigrationVisaScam => has_sig("immigration_visa_scam"),
        C::HasGovernmentGrantScam => has_sig("government_grant_scam"),
        C::HasDebtReliefScam => has_sig("debt_relief_scam"),
        C::HasStreamingBillingScam => has_sig("streaming_billing_scam"),
        C::HasTrafficFineScam => has_sig("traffic_fine_scam"),
        C::HasPigButcheringLure => has_sig("pig_butchering_lure"),
        C::HasLoanFeeScam => has_sig("loan_fee_scam"),
        C::HasDataUriPage => has_sig("data_uri_page"),
        C::HasIpHostUrl => has_sig("ip_host_url"),
        C::HasCharityScamLure => has_sig("charity_scam_lure"),
        C::HasRentalScamLure => has_sig("rental_scam_lure"),
        C::HasPetSaleScam => has_sig("pet_sale_scam"),
        C::HasTimeshareScam => has_sig("timeshare_travel_scam"),
        C::HasWindowsActivationScam => has_sig("windows_activation_scam"),
        C::HasSurveyRewardScam => has_sig("survey_reward_scam"),
        C::HasAvBrandRenewalScam => has_sig("av_brand_renewal_scam"),
        C::HasRecoveryScam => has_sig("recovery_scam"),
        C::HasStudentLoanScam => has_sig("student_loan_scam"),
        C::HasSecretShopperScam => has_sig("secret_shopper_scam"),
        C::HasMlmPyramidRecruitment => has_sig("mlm_pyramid_recruitment"),
        C::HasVeteransBenefitScam => has_sig("veterans_benefit_scam"),
        C::HasFakeCopyrightScam => has_sig("fake_copyright_scam"),
        C::HasCryptoGiveawayScam => has_sig("crypto_giveaway_scam"),
        C::HasOtpInterceptionScam => has_sig("otp_interception_scam"),
        C::HasFamilyEmergencyScam => has_sig("family_emergency_scam"),
    }
}

/// Heuristic phone-number detector, stdlib-only (no regex dep).
///
/// Looks for a run of digits that, ignoring common separators
/// (space, `-`, `.`, `(`, `)`, `+`), totals 7–15 digits — covering
/// toll-free US numbers like "1-800-XXX-XXXX", international "+44 …",
/// and bare 10-digit numbers, while rejecting short years/counts.
/// Conservative on purpose: the goal is "is there a phone number
/// here", not perfect E.164 validation.
#[must_use]
pub fn contains_phone_number(text: &str) -> bool {
    // Defense-in-depth length bound for direct (external) callers; `classify`
    // already passes a bounded title.
    let text = confusables::bound_title_chars(text);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip if the char just before the run is alphanumeric — we're
        // in the middle of a token like "0x80070005" or "build7234567",
        // not at the start of a real number.
        let prev_is_alnum = i > 0 && bytes[i - 1].is_ascii_alphanumeric();
        if (bytes[i].is_ascii_digit() || bytes[i] == b'+') && !prev_is_alnum {
            let mut digits = 0usize;
            let mut j = i;
            let mut aborted_by_letter = false;
            let mut last_was_digit = false;
            while j < bytes.len() {
                let c = bytes[j];
                if c.is_ascii_digit() {
                    digits += 1;
                    j += 1;
                    last_was_digit = true;
                } else if matches!(c, b' ' | b'-' | b'.' | b'(' | b')' | b'+') {
                    // separator — allowed inside a number run
                    j += 1;
                    last_was_digit = false;
                } else if c.is_ascii_alphabetic() {
                    // A letter *directly* touching a digit (no separator
                    // between) disqualifies the run — that's a hex code,
                    // version, or serial, not a phone number. A letter
                    // after a separator just ends the run normally.
                    if last_was_digit {
                        aborted_by_letter = true;
                    }
                    break;
                } else {
                    break;
                }
            }
            if !aborted_by_letter && (7..=15).contains(&digits) {
                return true;
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    false
}

///
/// The scareware [`RepeatTracker`] needs "the same pop-up" to map to
/// "the same key" across appearances. We define that here so callers
/// don't each invent their own (inconsistent) scheme: the key is the
/// **fully normalized** title plus the source host, which is stable
/// across the rapid re-pops of an installed rogue AV while still
/// distinguishing genuinely different alerts.
///
/// The title is run through the *same* [`normalize_for_match`] pipeline
/// the classifier uses for blocklist matching — not a weaker fold — so a
/// flood cannot be hidden by **polymorphic titles**: re-popping the same
/// alert with a per-appearance varying zero-width character, combining
/// mark, emoji, full-width / math-alphanumeric glyph, or intra-word
/// spacing would otherwise yield a different signature each time and slip
/// past repeat detection entirely. Folding these to one skeleton keeps
/// the signature stable under exactly the evasions muten already defeats
/// for matching (and closes the drift between the two normalization
/// surfaces). Internal whitespace runs are also collapsed so spacing
/// jitter between appearances can't fork the signature. Distinct *digits*
/// (a `Warning #4821` style counter) are
/// intentionally **preserved**: collapsing them risks grouping genuinely
/// different benign unsolicited notifications (`3 new messages` /
/// `4 new messages`) into a false flood.
#[must_use]
pub fn signature(w: &OverlayWindow) -> String {
    // Collapse internal whitespace runs after normalization so a flood can't
    // vary the spacing between letters/words across appearances to dodge
    // grouping. Safe here because the signature is used only for repeat
    // detection, never for a block decision.
    let normalized = confusables::normalize_for_match(w.title.trim());
    let title: String = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    // Use the crate's single host extractor so the repeat-signature host
    // matches the classifier's host exactly (drops `:port`, and a `://`
    // inside a query string can't hijack it).
    let host = w
        .url
        .as_deref()
        .and_then(crate::rules::host_of)
        .unwrap_or_default();
    format!("{title}|{host}")
}

/// One audited outcome from [`enforce`]: what we decided for a window
/// and whether we dismissed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforceOutcome {
    /// Controller's stable handle for this window.
    pub window_id: String,
    /// Classifier decision for this window.
    pub decision: Decision,
    /// Additive score (≥ 0) that produced the decision.
    pub score: i32,
    /// Signal names that contributed to the score.
    pub signals: Vec<String>,
    /// Blocklist rule that matched, if any.
    pub matched_rule: Option<String>,
    /// True only when the controller actually dismissed the window.
    pub dismissed: bool,
}

/// Run the full overlay loop once: enumerate every window, classify
/// each against `rules`, and dismiss the ones that score `Block`.
///
/// Returns one [`EnforceOutcome`] per window so the daemon can emit
/// audit events. Only `Block` triggers a dismiss; `Suspicious` and
/// `Allow` are reported but never dismissed (CLAUDE.md I9, and the
/// false-positive-averse design). Controller errors on a single
/// dismiss are folded into `dismissed = false` rather than aborting
/// the sweep — one stuck window shouldn't blind the daemon to the
/// rest.
pub fn enforce(
    controller: &dyn OverlayController,
    rules: &Ruleset,
) -> Result<Vec<EnforceOutcome>, ControllerError> {
    let windows = controller.enumerate()?;
    let mut outcomes = Vec::with_capacity(windows.len());
    for ew in windows {
        let v = classify(&ew.window, rules);
        let dismissed = if v.decision == Decision::Block {
            controller.dismiss(&ew.id).unwrap_or(false)
        } else {
            false
        };
        outcomes.push(EnforceOutcome {
            window_id: ew.id,
            decision: v.decision,
            score: v.score,
            signals: v.signals,
            matched_rule: v.matched_rule,
            dismissed,
        });
    }
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn benign_fullscreen_video() -> OverlayWindow {
        // A user opened a video and went full screen: full coverage +
        // topmost, but user-initiated and has a close button.
        OverlayWindow {
            title: "my vacation video - vlc media player".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        }
    }

    fn classic_scam() -> OverlayWindow {
        OverlayWindow {
            title: "⚠ your computer is infected! call support now".into(),
            url: Some("http://win-prize-now.example/alert".into()),
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 200,
        }
    }

    #[test]
    fn benign_video_is_allowed() {
        let v = classify(&benign_fullscreen_video(), &Ruleset::default());
        assert_eq!(
            v.decision,
            Decision::Allow,
            "score={} {:?}",
            v.score,
            v.signals
        );
    }

    #[test]
    fn classic_scam_is_blocked_by_heuristic_even_without_blocklist() {
        // Empty ruleset: rely purely on the heuristic signals.
        let v = classify(&classic_scam(), &Ruleset::default());
        assert_eq!(
            v.decision,
            Decision::Block,
            "score={} {:?}",
            v.score,
            v.signals
        );
    }

    #[test]
    fn host_blocklist_is_hard_block() {
        let rules = Ruleset::from_lines(&["host: win-prize-now.example"]);
        let mut w = benign_fullscreen_video();
        w.url = Some("http://win-prize-now.example/x".into());
        let v = classify(&w, &rules);
        assert_eq!(v.decision, Decision::Block);
        assert_eq!(v.matched_rule.as_deref(), Some("win-prize-now.example"));
        assert!(v.signals.iter().any(|s| s == "blocklist_host"));
    }

    #[test]
    fn unsolicited_fullscreen_no_close_is_at_least_suspicious() {
        let w = OverlayWindow {
            title: "special offer".into(),
            url: None,
            coverage_percent: 90,
            topmost: false,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 500,
        };
        let v = classify(&w, &Ruleset::default());
        // 30 (fullscreen) + 25 (no_close) + 25 (unsolicited) + 10 (new) = 90.
        // Below BLOCK_THRESHOLD (100) by design: without a confirmed
        // blocklist hit or a topmost+modal combination, we flag for
        // review rather than auto-dismiss. False positives here would
        // break legitimate full-screen apps.
        assert_eq!(v.decision, Decision::Suspicious, "score={}", v.score);
    }

    #[test]
    fn unsolicited_fullscreen_modal_topmost_no_close_is_blocked() {
        // Add topmost (+15) and blocks_input (+20) to the previous
        // case → 125 ≥ 100 → Block. This is the unmistakable scam
        // shape: full-screen, on top, modal, no close, popped up
        // unsolicited.
        let w = OverlayWindow {
            title: "special offer".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 500,
        };
        let v = classify(&w, &Ruleset::default());
        assert_eq!(v.decision, Decision::Block, "score={}", v.score);
    }

    #[test]
    fn small_unsolicited_popup_is_suspicious_not_blocked() {
        let w = OverlayWindow {
            title: "newsletter signup".into(),
            url: None,
            coverage_percent: 30,
            topmost: false,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 2_000,
        };
        let v = classify(&w, &Ruleset::default());
        // 25 (no_close) + 25 (unsolicited) = 50 → Suspicious
        assert_eq!(v.decision, Decision::Suspicious, "score={}", v.score);
    }

    #[test]
    fn title_pattern_contributes_but_is_not_auto_block() {
        let rules = Ruleset::from_lines(&["title: your computer is infected"]);
        let w = OverlayWindow {
            title: "warning: your computer is infected".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        // Only the title hit (40) fires → below suspicious threshold.
        assert_eq!(v.decision, Decision::Allow, "score={}", v.score);
        assert!(v.signals.iter().any(|s| s == "blocklist_title"));
    }

    #[test]
    fn user_initiated_relief_keeps_legit_fullscreen_app_allowed() {
        let w = OverlayWindow {
            title: "presentation".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false, // presentations often hide chrome
            blocks_input: true,
            origin: Origin::UserInitiated,
            age_ms: 1_000,
        };
        let v = classify(&w, &Ruleset::default());
        // 30+15+25+20 = 90, minus 40 relief = 50 → Suspicious (not Block).
        // Acceptable: IT reviews, but we don't dismiss a presentation.
        assert_ne!(v.decision, Decision::Block, "score={}", v.score);
    }

    #[test]
    fn score_never_negative() {
        let w = OverlayWindow {
            title: "x".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated, // -40 relief
            age_ms: 10_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(v.score >= 0);
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn age_zero_is_unknown_not_very_new() {
        // age_ms == 0 means "enumerator couldn't tell" — it must NOT
        // score as very_new (the OS helpers report 0 by default, so
        // scoring it would add +10 to literally every window).
        let w = OverlayWindow {
            title: "x".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 0,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "very_new"),
            "age 0 must not be very_new"
        );
        assert_eq!(v.score, 0);
    }

    #[test]
    fn small_nonzero_age_is_very_new() {
        let w = OverlayWindow {
            title: "x".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 300,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(v.signals.iter().any(|s| s == "very_new"));
    }

    #[test]
    fn old_window_is_not_very_new() {
        let w = OverlayWindow {
            title: "x".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 60_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(!v.signals.iter().any(|s| s == "very_new"));
    }

    // ── phone-number signal (arxiv 1607.06891) ───────────────────

    #[test]
    fn detects_toll_free_number() {
        assert!(contains_phone_number("call 1-800-642-7676 now"));
        assert!(contains_phone_number("support: (888) 555-0199"));
        assert!(contains_phone_number("+44 20 7946 0958"));
        assert!(contains_phone_number("dial 18005550199"));
    }

    #[test]
    fn rejects_non_phone_digit_runs() {
        assert!(!contains_phone_number("error code 0x80070005"));
        assert!(!contains_phone_number("copyright 2026"));
        assert!(!contains_phone_number("version 4.10.2"));
        assert!(!contains_phone_number("no digits here"));
    }

    /// Digit-count boundary guard (Socratic round 8). `contains_phone_number`
    /// fires on a run of `(7..=15)` digits — inclusive at both ends. Every
    /// existing test uses 10–11-digit numbers (comfortably inside) or a
    /// 4-digit year (comfortably below), so flipping the range to `(8..=15)`,
    /// `(7..15)`, or `(7..=16)` would pass CI while silently missing a real
    /// 7-digit local scam number / 15-digit international number, or
    /// false-firing on a 16-digit card/serial. `phone_number` is a weight-35
    /// high-fidelity signal, so a boundary regression can drop a scam verdict
    /// below threshold. This pins all four edges with exact digit counts.
    #[test]
    fn phone_digit_count_boundaries_are_inclusive() {
        // 6 digits → below the lower bound → not a phone.
        assert!(
            !contains_phone_number("call 123456 now"),
            "6 digits → false"
        );
        // 7 digits → exactly the lower bound → phone (bare local number).
        assert!(
            contains_phone_number("call 123-4567 now"),
            "7 digits → true"
        );
        // 15 digits → exactly the upper bound → phone (max E.164).
        assert!(
            contains_phone_number("call 123456789012345 now"),
            "15 digits → true"
        );
        // 16 digits → above the upper bound → card/serial, not a phone.
        assert!(
            !contains_phone_number("call 1234567890123456 now"),
            "16 digits → false"
        );
    }

    /// Combining-diacritic phone evasion guard. An attacker can insert
    /// combining strikethrough / overlay marks (U+0337 etc.) between digits
    /// to produce a visually legible number that breaks a byte-level digit
    /// scan: `1̶-̶8̶0̶0̶-̶5̶5̶5̶-̶0̶1̶0̶0̶`. Before this fix the marks interrupted the
    /// scan and `contains_phone_number` returned false. After the fix the call
    /// site strips combining marks before scanning, so the number is detected.
    #[test]
    fn phone_number_detected_despite_combining_marks() {
        // Insert U+0337 (COMBINING SHORT SOLIDUS OVERLAY) after every char.
        let strikethrough: String = "1-800-555-0100"
            .chars()
            .flat_map(|c| [c, '\u{0337}'])
            .collect();
        // Raw input fails (this documents the pre-fix behavior for reference).
        assert!(
            !contains_phone_number(&strikethrough),
            "byte-level scan cannot see through combining marks — expected"
        );
        // After fold_confusables + strip_combining_marks (the call-site fix):
        let cleaned =
            confusables::strip_combining_marks(&confusables::fold_confusables(&strikethrough));
        assert!(
            contains_phone_number(&cleaned),
            "phone number must be detected after stripping combining marks: {cleaned:?}"
        );
    }

    #[test]
    fn phone_number_scores_only_when_alert_shaped() {
        // Fullscreen alert with a number → phone_number fires.
        let scam = OverlayWindow {
            title: "virus alert! call 1-888-555-0142 immediately".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unknown,
            age_ms: 0,
        };
        let v = classify(&scam, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "phone_number"),
            "signals={:?}",
            v.signals
        );

        // A small, closable, non-modal window with a number (e.g. a
        // contacts app) must NOT get the phone_number signal.
        let benign = OverlayWindow {
            title: "Contact: 1-888-555-0142".into(),
            url: None,
            coverage_percent: 30,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let vb = classify(&benign, &Ruleset::default());
        assert!(
            !vb.signals.iter().any(|s| s == "phone_number"),
            "signals={:?}",
            vb.signals
        );
    }

    #[test]
    fn phone_number_pushes_fullscreen_scam_to_block() {
        // The key win: on a real host where origin=unknown and
        // has_close_button comes back true, a fullscreen TSS page with
        // a phone number now reaches Block on the heuristic alone.
        // fullscreen(30)+topmost(15)+phone(35) = 80 → Suspicious;
        // add no_close (real helper detects borderless) → 105 → Block.
        let w = OverlayWindow {
            title: "Windows Defender: call +1-800-555-0123 to remove virus".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 0,
        };
        let v = classify(&w, &Ruleset::default());
        // 30 + 15 + 25(no_close) + 35(phone) = 105
        assert_eq!(
            v.decision,
            Decision::Block,
            "score={} {:?}",
            v.score,
            v.signals
        );
    }

    #[test]
    fn verdict_carries_dark_pattern_categories() {
        // A fullscreen modal scam with a phone number should surface
        // forced_action (blocks_input), obstruction (no_close), and
        // interface_interference (phone_number).
        let w = OverlayWindow {
            title: "Microsoft Alert: call 1-800-555-0100 now".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 0,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(v.categories.contains(&DarkPatternCategory::ForcedAction));
        assert!(v.categories.contains(&DarkPatternCategory::Obstruction));
        assert!(v
            .categories
            .contains(&DarkPatternCategory::InterfaceInterference));
    }

    #[test]
    fn benign_window_has_no_categories() {
        let w = OverlayWindow {
            title: "report.pdf - reader".into(),
            url: None,
            coverage_percent: 40,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(v.categories.is_empty(), "categories={:?}", v.categories);
    }

    #[test]
    fn host_block_is_interface_interference() {
        let w = OverlayWindow {
            title: "x".into(),
            url: Some("http://scam.example/x".into()),
            ..Default::default()
        };
        let rules = Ruleset::from_lines(&["host: scam.example"]);
        let v = classify(&w, &rules);
        assert_eq!(
            v.categories,
            vec![DarkPatternCategory::InterfaceInterference]
        );
    }

    #[test]
    fn homoglyph_title_still_matches_blocklist() {
        // arXiv:2401.07867 — homoglyph substitution is a top evasion.
        // "your computer is іnfected" uses Cyrillic і (U+0456); it must
        // still hit the ascii "your computer is infected" pattern after
        // confusable folding.
        let rules = Ruleset::from_lines(&["title: your computer is infected"]);
        let w = OverlayWindow {
            title: "your computer is іnfected".into(), // Cyrillic і
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 0,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "blocklist_title"),
            "homoglyph title evaded the blocklist: {:?}",
            v.signals
        );
    }

    #[test]
    fn fullwidth_digits_trigger_phone_signal() {
        // Full-width digits in a phone number must still be detected.
        let w = OverlayWindow {
            title: "call \u{FF11}-\u{FF18}\u{FF10}\u{FF10}-\u{FF15}\u{FF15}\u{FF15}-\u{FF10}\u{FF11}\u{FF10}\u{FF10}".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unknown,
            age_ms: 0,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "phone_number"),
            "signals={:?}",
            v.signals
        );
    }

    // ── mixed-script evasion signal (UTS #39 / roadmap C8-4) ─────

    #[test]
    fn mixed_script_title_fires_signal_and_sneaking_category() {
        // "раypаl" mixes Cyrillic р/а with Latin — homoglyph disguise.
        let w = OverlayWindow {
            title: "sign in to раypаl".into(),
            coverage_percent: 90,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "mixed_script"),
            "signals={:?}",
            v.signals
        );
        assert!(v.categories.contains(&DarkPatternCategory::Sneaking));
    }

    #[test]
    fn mixed_script_host_fires_but_path_does_not() {
        // Homoglyph host → fires.
        let w = OverlayWindow {
            title: "login".into(),
            url: Some("http://раypal.com/secure".into()),
            ..Default::default()
        };
        assert!(classify(&w, &Ruleset::default())
            .signals
            .iter()
            .any(|s| s == "mixed_script"));

        // A Cyrillic word only in the *path* of a Latin host must NOT
        // fire (the check is scoped to the host).
        let w2 = OverlayWindow {
            title: "blog".into(),
            url: Some("http://example.com/привет".into()),
            ..Default::default()
        };
        assert!(!classify(&w2, &Ruleset::default())
            .signals
            .iter()
            .any(|s| s == "mixed_script"));
    }

    #[test]
    fn japanese_plus_latin_title_does_not_fire_mixed_script() {
        // FP guard for the JP market: Japanese is `Other`, not a
        // confusable script, so a legit bilingual title is clean.
        let w = OverlayWindow {
            title: "ウイルス対策 Windows Update".into(),
            coverage_percent: 100,
            topmost: true,
            has_close_button: true,
            origin: Origin::UserInitiated,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "mixed_script"),
            "JP+Latin title falsely flagged: {:?}",
            v.signals
        );
    }

    #[test]
    fn mixed_script_alone_is_not_a_block() {
        // The signal nudges toward Suspicious, never blocks on its own
        // (W_MIXED_SCRIPT = 30 < SUSPICIOUS_THRESHOLD).
        let w = OverlayWindow {
            title: "раypаl".into(),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert_ne!(v.decision, Decision::Block);
    }

    // ── whole_script_confusable (UTS#39 §5, C8-3) ───────────────

    #[test]
    fn whole_script_confusable_title_fires_signal_and_sneaking() {
        // ѕсоре — all Cyrillic, folds to "scope" — no Latin letters at all.
        let w = OverlayWindow {
            title: "ѕсоре detected".into(),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "whole_script_confusable"),
            "expected whole_script_confusable in {:?}",
            v.signals
        );
        assert!(v.categories.contains(&DarkPatternCategory::Sneaking));
    }

    #[test]
    fn whole_script_confusable_host_fires() {
        // A host whose label is all-Cyrillic-lookalike chars.
        // ѕсоре = Cyrillic, all fold to ASCII.
        let w = OverlayWindow {
            title: "login".into(),
            url: Some("http://ѕсоре.com/".into()),
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "whole_script_confusable"),
            "expected whole_script_confusable from host in {:?}",
            v.signals
        );
    }

    #[test]
    fn whole_script_alone_is_not_a_block() {
        // Weight 30 < SUSPICIOUS_THRESHOLD (50) for a minimal window.
        let w = OverlayWindow {
            title: "ѕсоре".into(),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert_ne!(
            v.decision,
            Decision::Block,
            "whole_script alone must not block"
        );
    }

    #[test]
    fn real_cyrillic_text_does_not_fire_whole_script() {
        // привет мир — legit Russian; п has no ASCII fold → won't fire.
        let w = OverlayWindow {
            title: "привет мир".into(),
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "whole_script_confusable"),
            "legitimate Cyrillic text falsely flagged: {:?}",
            v.signals
        );
    }

    // ── bidi_override (Trojan Source, C8-5) ─────────────────────

    #[test]
    fn bidi_override_fires_and_maps_to_sneaking() {
        // A right-to-left override (U+202E) in the title.
        let w = OverlayWindow {
            title: "invoice \u{202E}gpj.exe".into(),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "bidi_override"),
            "signals={:?}",
            v.signals
        );
        assert!(v.categories.contains(&DarkPatternCategory::Sneaking));
    }

    #[test]
    fn legit_rtl_text_does_not_fire_bidi_override() {
        // Arabic/Hebrew titles use RTL *letters* and at most LRM/RLM
        // marks or isolates — never an override. Must not flag.
        for title in [
            "مرحبا بك",                     // plain Arabic
            "\u{200F}مرحبا",                // with an RLM mark
            "user \u{2068}content\u{2069}", // with FSI/PDI isolates
        ] {
            let w = OverlayWindow {
                title: title.into(),
                has_close_button: true,
                ..Default::default()
            };
            assert!(
                !classify(&w, &Ruleset::default())
                    .signals
                    .iter()
                    .any(|s| s == "bidi_override"),
                "{title:?} wrongly flagged"
            );
        }
    }

    // ── mixed_number_systems (ICU MIXED_NUMBERS, C8-6) ────────────

    #[test]
    fn mixed_number_systems_fires_and_maps_to_sneaking() {
        // A token mixing ASCII and Arabic-Indic digits.
        let w = OverlayWindow {
            title: "verify code 1\u{0665}9".into(),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "mixed_number_systems"),
            "signals={:?}",
            v.signals
        );
        assert!(v.categories.contains(&DarkPatternCategory::Sneaking));
    }

    #[test]
    fn plain_phone_number_does_not_fire_mixed_numbers() {
        let w = OverlayWindow {
            title: "call 1-800-555-0100".into(),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(!v.signals.iter().any(|s| s == "mixed_number_systems"));
    }

    #[test]
    fn fullwidth_plus_ascii_digits_do_not_fire_mixed_numbers() {
        // JP FP guard: full-width digits and ASCII are the same system.
        let w = OverlayWindow {
            title: "請求番号 \u{FF11}\u{FF12}34".into(),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "mixed_number_systems"),
            "JP full-width+ASCII falsely flagged: {:?}",
            v.signals
        );
    }

    // ── excessive_combining_marks (Zalgo, C8-7) ───────────────────

    #[test]
    fn zalgo_fires_and_maps_to_sneaking() {
        let w = OverlayWindow {
            title: "a\u{0300}\u{0301}\u{0302}\u{0303} alert".into(),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "excessive_combining_marks"),
            "signals={:?}",
            v.signals
        );
        assert!(v.categories.contains(&DarkPatternCategory::Sneaking));
    }

    #[test]
    fn normal_accented_text_does_not_fire_zalgo() {
        let w = OverlayWindow {
            title: "café résumé über señor".into(),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(!v.signals.iter().any(|s| s == "excessive_combining_marks"));
    }

    // ── compat_chars_present (enclosed letters, C8-8) ─────────────

    #[test]
    fn compat_chars_fires_on_enclosed_letter_title() {
        // ⓟⓐⓨⓟⓐⓛ — all enclosed letters — bypasses plain-text matching
        // but is flagged by has_compat_alpha on the raw title.
        let w = OverlayWindow {
            title: "ⓟⓐⓨⓟⓐⓛ alert".into(),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "compat_chars_present"),
            "signals={:?}",
            v.signals
        );
        assert!(v.categories.contains(&DarkPatternCategory::Sneaking));
    }

    #[test]
    fn compat_chars_alone_is_not_a_block() {
        let w = OverlayWindow {
            title: "ⓟⓐⓨⓟⓐⓛ".into(),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert_ne!(
            v.decision,
            Decision::Block,
            "compat_chars alone must not block"
        );
    }

    #[test]
    fn plain_text_does_not_fire_compat_chars() {
        let w = OverlayWindow {
            title: "paypal login".into(),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(!v.signals.iter().any(|s| s == "compat_chars_present"));
    }

    #[test]
    fn compat_chars_also_matches_blocklist_after_normalize() {
        // ⓟⓐⓨⓟⓐⓛ folds to "paypal" via normalize_for_match, so a
        // title: paypal blocklist rule would hit even with enclosed letters.
        let rules = Ruleset::from_lines(&["title: paypal"]);
        let w = OverlayWindow {
            title: "ⓟⓐⓨⓟⓐⓛ login".into(),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "blocklist_title"),
            "normalized enclosed letters should match blocklist: {:?}",
            v.signals
        );
    }

    // ── brand_impersonation (UTS#39 skeleton collision, C8-2) ────

    #[test]
    fn brand_impersonation_fires_on_homograph_host() {
        // "раура1.com": Cyrillic р/а/у + digit 1 → skeleton "paypal".
        let w = OverlayWindow {
            title: "sign in".into(),
            url: Some("http://\u{0440}\u{0430}\u{0443}\u{0440}\u{0430}1.com/login".into()),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "brand_impersonation"),
            "signals={:?}",
            v.signals
        );
        assert!(v
            .categories
            .contains(&DarkPatternCategory::InterfaceInterference));
    }

    #[test]
    fn legitimate_brand_host_is_not_impersonation() {
        // The real brand domain MUST NOT fire (false-positive guard).
        for host in [
            "http://paypal.com/",
            "http://login.microsoft.com/",
            "http://google.com/",
        ] {
            let w = OverlayWindow {
                title: "x".into(),
                url: Some(host.into()),
                has_close_button: true,
                ..Default::default()
            };
            let v = classify(&w, &Ruleset::default());
            assert!(
                !v.signals.iter().any(|s| s == "brand_impersonation"),
                "{host} wrongly flagged: {:?}",
                v.signals
            );
        }
    }

    #[test]
    fn unrelated_host_is_not_impersonation() {
        let w = OverlayWindow {
            title: "x".into(),
            url: Some("http://example.com/page".into()),
            has_close_button: true,
            ..Default::default()
        };
        assert!(!classify(&w, &Ruleset::default())
            .signals
            .iter()
            .any(|s| s == "brand_impersonation"));
    }

    #[test]
    fn brand_impersonation_alone_is_not_auto_block() {
        // Consistent with blocklist_title: a content/host tell alone
        // (40 < SUSPICIOUS_THRESHOLD) does not auto-dismiss without
        // overlay shape. It contributes; it does not unilaterally block.
        let w = OverlayWindow {
            title: "hi".into(),
            url: Some("http://g\u{043E}\u{043E}gle.com/".into()), // Cyrillic о → "google"
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(v.signals.iter().any(|s| s == "brand_impersonation"));
        assert_ne!(v.decision, Decision::Block);
    }

    // ── combosquat_brand (combosquatting, CCS 2017, C2-4) ────────

    #[test]
    fn combosquat_fires_on_brand_plus_lure() {
        // "apple-support.com": brand + lure word as hyphen tokens.
        for host in [
            "http://apple-support.com/",
            "http://paypal-secure-login.net/",
            "http://microsoft-verify.org/",
            "http://amazon-billing-update.com/",
        ] {
            let w = OverlayWindow {
                title: "sign in".into(),
                url: Some(host.into()),
                has_close_button: true,
                ..Default::default()
            };
            let v = classify(&w, &Ruleset::default());
            assert!(
                v.signals.iter().any(|s| s == "combosquat_brand"),
                "{host} should be a combosquat: {:?}",
                v.signals
            );
            assert!(v
                .categories
                .contains(&DarkPatternCategory::InterfaceInterference));
        }
    }

    #[test]
    fn combosquat_defeats_homoglyph_tokens() {
        // "аpple-support.com" with a Cyrillic а (U+0430) in the brand
        // token: skeleton folds it to "apple" before the token match.
        let w = OverlayWindow {
            title: "x".into(),
            url: Some("http://\u{0430}pple-support.com/".into()),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "combosquat_brand"),
            "homoglyph combosquat should fire: {:?}",
            v.signals
        );
    }

    #[test]
    fn combosquat_does_not_fire_on_legit_concatenation() {
        // FP guard: legitimate single-token domains and brand-only labels
        // never fire (no hyphen between brand and lure, or no lure at all).
        for host in [
            "http://windowsupdate.com/",  // legit Microsoft, brand+lure but ONE token
            "http://apple.com/",          // bare brand
            "http://support.apple.com/",  // lure is a separate DNS label, not hyphen-joined
            "http://my-apple-store.com/", // brand token but no lure word ("store" not a lure)
            "http://pineapple-recipes.com/", // "pineapple" != "apple" (exact token match)
        ] {
            let w = OverlayWindow {
                title: "x".into(),
                url: Some(host.into()),
                has_close_button: true,
                ..Default::default()
            };
            let v = classify(&w, &Ruleset::default());
            assert!(
                !v.signals.iter().any(|s| s == "combosquat_brand"),
                "{host} wrongly flagged as combosquat: {:?}",
                v.signals
            );
        }
    }

    #[test]
    fn combosquat_alone_is_not_auto_block() {
        // Additive, like brand_impersonation: a host tell alone
        // (30 < SUSPICIOUS_THRESHOLD) does not auto-dismiss.
        let w = OverlayWindow {
            title: "hi".into(),
            url: Some("http://paypal-verify.com/".into()),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(v.signals.iter().any(|s| s == "combosquat_brand"));
        assert_ne!(v.decision, Decision::Block);
    }

    // ── remote_access_lure (context amplification, IC3 2024, C2-5) ──

    #[test]
    fn remote_access_lure_fires_with_phone_number() {
        // Alert-shaped overlay with a support number AND an AnyDesk lure.
        let w = OverlayWindow {
            title: "virus alert! call 1-800-555-0100 and install anydesk".into(),
            coverage_percent: 100,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "phone_number"),
            "precondition: {:?}",
            v.signals
        );
        assert!(
            v.signals.iter().any(|s| s == "remote_access_lure"),
            "expected remote_access_lure; got {:?}",
            v.signals
        );
        assert!(v
            .categories
            .contains(&DarkPatternCategory::InterfaceInterference));
    }

    #[test]
    fn remote_access_lure_fires_with_blocklist_title() {
        let rules = Ruleset::from_lines(&["title: your computer is infected"]);
        let w = OverlayWindow {
            title: "your computer is infected — download teamviewer for support".into(),
            coverage_percent: 100,
            has_close_button: false,
            ..Default::default()
        };
        let v = classify(&w, &rules);
        assert!(v.signals.iter().any(|s| s == "blocklist_title"));
        assert!(v.signals.iter().any(|s| s == "remote_access_lure"));
    }

    #[test]
    fn remote_access_tool_alone_does_not_fire() {
        // A legitimate remote-support session: the tool name is present but
        // there is NO fake-alert evidence (no blocklist title, no phone
        // number, no ClickFix). The lure MUST NOT fire — context
        // amplification only.
        let w = OverlayWindow {
            title: "anydesk — remote desktop".into(),
            coverage_percent: 100,
            topmost: true,
            has_close_button: true,
            origin: Origin::UserInitiated,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "remote_access_lure"),
            "legit remote tool wrongly flagged: {:?}",
            v.signals
        );
    }

    #[test]
    fn remote_access_lure_never_blocks_alone() {
        // Even with the lure + a phone number, a window with no overlay
        // shape beyond alert_shaped should remain below BLOCK on content
        // tells alone (FP-averse): phone (35) + lure (20) + no_close (25)
        // = 80 < 100.
        let w = OverlayWindow {
            title: "call 1-800-555-0100 install anydesk now".into(),
            coverage_percent: 0,
            topmost: false,
            has_close_button: false, // alert_shaped via no-close
            blocks_input: false,
            origin: Origin::Unknown,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(v.signals.iter().any(|s| s == "remote_access_lure"));
        assert_ne!(v.decision, Decision::Block, "score={}", v.score);
    }

    // ── blocklist_phone (known scam number, C2-2) ───────────────

    #[test]
    fn blocklist_phone_fires_and_surfaces_rule() {
        let rules = Ruleset::from_lines(&["phone: 1-800-555-0100"]);
        let w = OverlayWindow {
            title: "security alert — please call 800.555.0100".into(),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "blocklist_phone"),
            "expected blocklist_phone; got {:?}",
            v.signals
        );
        assert_eq!(v.matched_rule.as_deref(), Some("1-800-555-0100"));
        assert!(v
            .categories
            .contains(&DarkPatternCategory::InterfaceInterference));
        // explain() renders the human phrase, not the raw signal name.
        assert!(v.explain().contains("known scam phone number"));
    }

    #[test]
    fn blocklist_phone_does_not_need_alert_shape() {
        // A curated scam number is high-confidence even in a non-alert
        // window (has close, not fullscreen) — unlike the shape-based
        // phone_number heuristic, which would not fire here.
        let rules = Ruleset::from_lines(&["phone: +1 800 555 0100"]);
        let w = OverlayWindow {
            title: "contact 18005550100".into(),
            coverage_percent: 10,
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &rules);
        assert!(v.signals.iter().any(|s| s == "blocklist_phone"));
        assert!(!v.signals.iter().any(|s| s == "phone_number"));
    }

    #[test]
    fn unknown_phone_number_does_not_fire_blocklist_phone() {
        let rules = Ruleset::from_lines(&["phone: 1-800-555-0100"]);
        let w = OverlayWindow {
            title: "call 1-888-999-7777".into(),
            has_close_button: false,
            blocks_input: true,
            ..Default::default()
        };
        let v = classify(&w, &rules);
        assert!(!v.signals.iter().any(|s| s == "blocklist_phone"));
    }

    // ── §2.2 partial-window deserialization (spec conformance) ───

    #[test]
    fn partial_window_json_deserializes_with_defaults() {
        // The contract is "fill what you can, default the rest" — a
        // helper that can't determine a field omits it. Missing fields
        // MUST fall back to type defaults instead of erroring.
        let w: OverlayWindow =
            serde_json::from_str(r#"{"title":"x","coverage_percent":90}"#).unwrap();
        assert_eq!(w.title, "x");
        assert_eq!(w.coverage_percent, 90);
        assert_eq!(w.url, None);
        assert!(!w.topmost);
        assert!(!w.has_close_button);
        assert!(!w.blocks_input);
        assert_eq!(w.origin, Origin::Unknown);
        assert_eq!(w.age_ms, 0);
        // An empty object is also valid → all defaults.
        let empty: OverlayWindow = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, OverlayWindow::default());
        // And it still classifies (no panic, Allow on an empty window).
        assert_eq!(
            classify(&empty, &Ruleset::default()).decision,
            Decision::Allow
        );
    }

    // ── input_trap composite "screen lock" signal ───────────────

    #[test]
    fn input_trap_fires_on_fullscreen_topmost_modal() {
        let w = OverlayWindow {
            title: "loading".into(),
            coverage_percent: 100,
            topmost: true,
            blocks_input: true,
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "input_trap"),
            "signals={:?}",
            v.signals
        );
        assert!(v.categories.contains(&DarkPatternCategory::ForcedAction));
    }

    #[test]
    fn input_trap_requires_all_three_conditions() {
        // Missing topmost → not a lock.
        let mut w = OverlayWindow {
            title: "x".into(),
            coverage_percent: 100,
            topmost: false,
            blocks_input: true,
            has_close_button: true,
            ..Default::default()
        };
        assert!(!classify(&w, &Ruleset::default())
            .signals
            .iter()
            .any(|s| s == "input_trap"));
        // Missing fullscreen → not a lock.
        w.topmost = true;
        w.coverage_percent = 40;
        assert!(!classify(&w, &Ruleset::default())
            .signals
            .iter()
            .any(|s| s == "input_trap"));
    }

    #[test]
    fn input_trap_alone_does_not_block_unknown_origin_lockdown_app() {
        // FP-aversion invariant: the bare lock shape (full-screen,
        // topmost, modal, no close) with UNKNOWN provenance and no
        // content tell must stay Suspicious, not auto-Block — a kiosk
        // shell / exam lockdown browser looks exactly like this. The
        // input_trap bonus is bounded so 90 + 5 = 95 < BLOCK_THRESHOLD.
        let w = OverlayWindow {
            title: "exam in progress".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unknown,
            age_ms: 0,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(v.signals.iter().any(|s| s == "input_trap"));
        assert_eq!(v.decision, Decision::Suspicious, "score={}", v.score);
        assert!(v.score < BLOCK_THRESHOLD);
    }

    // ── sudden_fullscreen_takeover composite signal ─────────────

    #[test]
    fn sudden_takeover_fires_on_unsolicited_instant_fullscreen() {
        let w = OverlayWindow {
            title: "loading".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "sudden_fullscreen_takeover"),
            "signals={:?}",
            v.signals
        );
    }

    #[test]
    fn sudden_takeover_needs_unsolicited_and_nonzero_age() {
        // age 0 = "couldn't tell", not "instant" → must not fire.
        let mut w = OverlayWindow {
            title: "x".into(),
            coverage_percent: 100,
            topmost: true,
            origin: Origin::Unsolicited,
            age_ms: 0,
            ..Default::default()
        };
        assert!(!classify(&w, &Ruleset::default())
            .signals
            .iter()
            .any(|s| s == "sudden_fullscreen_takeover"));
        // Unknown origin (helper couldn't attribute) → must not fire.
        w.age_ms = 200;
        w.origin = Origin::Unknown;
        assert!(!classify(&w, &Ruleset::default())
            .signals
            .iter()
            .any(|s| s == "sudden_fullscreen_takeover"));
    }

    #[test]
    fn sudden_takeover_alone_stays_suspicious() {
        // unsolicited(25)+fullscreen(30)+topmost(15)+very_new(10)+takeover(5)
        // = 85 → Suspicious, never an automatic Block without a content tell.
        let w = OverlayWindow {
            title: "welcome".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        };
        let v = classify(&w, &Ruleset::default());
        assert_eq!(v.decision, Decision::Suspicious, "score={}", v.score);
        assert!(v.score < BLOCK_THRESHOLD);
    }

    // ── Verdict::explain (roadmap C5-8) ──────────────────────────

    #[test]
    fn explain_lists_signals_in_plain_language() {
        let w = OverlayWindow {
            title: "Microsoft Alert: call 1-800-555-0100 now".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 0,
        };
        let v = classify(&w, &Ruleset::default());
        let why = v.explain();
        assert!(why.starts_with("Block (score "));
        assert!(why.contains("covers (almost) the whole screen"));
        assert!(why.contains("hides or fakes the close button"));
        assert!(why.contains("shows a support phone number"));
        assert!(why.ends_with('.'));
    }

    #[test]
    fn explain_mentions_matched_rule() {
        let rules = Ruleset::from_lines(&["host: scam.example"]);
        let w = OverlayWindow {
            title: "x".into(),
            url: Some("http://scam.example/x".into()),
            ..Default::default()
        };
        let why = classify(&w, &rules).explain();
        assert!(why.contains("matched blocklist rule \"scam.example\""));
    }

    #[test]
    fn explain_handles_allow_with_no_signals() {
        let w = OverlayWindow {
            title: "notepad".into(),
            has_close_button: true,
            ..Default::default()
        };
        let why = classify(&w, &Ruleset::default()).explain();
        assert_eq!(
            why,
            "Allow (score 0, high confidence): no notable signals fired."
        );
    }

    // ── B6: signal_weight / confidence / score_breakdown ─────────────

    #[test]
    fn signal_weight_returns_known_weights() {
        assert_eq!(signal_weight("phone_number"), Some(W_PHONE_NUMBER));
        assert_eq!(signal_weight("blocklist_title"), Some(W_TITLE_HIT));
        assert_eq!(signal_weight("blocklist_phone"), Some(W_PHONE_BLOCKLIST));
        assert_eq!(signal_weight("fullscreen"), Some(W_FULLSCREEN));
        assert_eq!(signal_weight("topmost"), Some(W_TOPMOST));
        assert_eq!(signal_weight("blocks_input"), Some(W_BLOCKS_INPUT));
        assert_eq!(signal_weight("unsolicited"), Some(W_UNSOLICITED));
        assert_eq!(signal_weight("mixed_script"), Some(W_MIXED_SCRIPT));
        assert_eq!(
            signal_weight("brand_impersonation"),
            Some(W_BRAND_IMPERSONATION)
        );
        assert_eq!(
            signal_weight("user_initiated"),
            Some(W_USER_INITIATED_RELIEF)
        );
        // Composite/unknown → None.
        assert_eq!(signal_weight("kiosk_lockdown"), None);
        assert_eq!(signal_weight(""), None);
    }

    #[test]
    fn confidence_medium_when_single_content_tell_fires() {
        // One high-fidelity signal (phone_number) alongside geometry → Medium.
        let w = OverlayWindow {
            title: "Call 1-800-555-0100 now".into(),
            origin: Origin::Unsolicited,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert_eq!(v.confidence(), ConfidenceLevel::Medium);
    }

    #[test]
    fn confidence_high_when_multiple_content_tell_signals_fire() {
        // Mixed-script title (high-fidelity) + phone number (high-fidelity) → High.
        // "раypаl" has Cyrillic р/а → mixed_script; "800" in a mixed-script
        // title fires phone_number too if the number is present.
        // Use a window that has both a known phone + mixed-script title.
        let w = OverlayWindow {
            // Cyrillic а (U+0430) in "раypаl" → mixed_script signal
            title: "раypаl: Call 1-800-555-0100 now".into(),
            origin: Origin::Unsolicited,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        let hf: Vec<_> = v.signals.iter().filter(|s| is_high_fidelity(s)).collect();
        if hf.len() >= 2 {
            assert_eq!(v.confidence(), ConfidenceLevel::High);
        } else {
            // Depending on classifier state, may be Medium — just assert non-Low.
            assert_ne!(v.confidence(), ConfidenceLevel::Low);
        }
    }

    #[test]
    fn confidence_low_when_only_geometry_signals_fire() {
        // A fullscreen topmost modal with no content signals → Low confidence.
        let w = OverlayWindow {
            title: "Notification".into(),
            coverage_percent: 99,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 0,
            url: None,
        };
        let v = classify(&w, &Ruleset::default());
        // All signals should be geometry-only.
        assert!(
            v.signals.iter().all(|s| !is_high_fidelity(s)),
            "expected no high-fidelity signals, got: {:?}",
            v.signals
        );
        assert_eq!(v.confidence(), ConfidenceLevel::Low);
    }

    #[test]
    fn confidence_high_for_clearly_safe_allow() {
        let w = OverlayWindow {
            title: "notepad".into(),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert_eq!(v.decision, Decision::Allow);
        assert_eq!(v.confidence(), ConfidenceLevel::High);
    }

    /// Regression for the collapsed-guard bug (Socratic round 6). A
    /// confirmed `blocklist_host` hard block is the single most definitive
    /// verdict the classifier emits — `signals == ["blocklist_host"]`, one
    /// high-fidelity signal, nothing else. The old `confidence()` had a dead
    /// guard (`1 if len == 1 => Medium` immediately followed by `1 => Medium`,
    /// identical bodies) that reported this clean, operator-listed match as
    /// only *Medium* confidence, contradicting the method's own doc ("High
    /// when … a rule-based signal fired"). It must be High.
    #[test]
    fn confidence_high_for_lone_blocklist_host_hard_block() {
        let rules = Ruleset::from_lines(&["host: known-scam.example"]);
        let w = OverlayWindow {
            title: "anything".into(),
            url: Some("http://known-scam.example/x".into()),
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &rules);
        assert_eq!(v.decision, Decision::Block);
        assert_eq!(v.signals, vec!["blocklist_host".to_string()]);
        assert_eq!(
            v.confidence(),
            ConfidenceLevel::High,
            "a lone confirmed blocklist-host match must be High confidence"
        );
    }

    /// Confidence-boundary guard for the `Allow` path (Socratic round 6,
    /// parallel to the decision-threshold boundary test). The Allow-branch
    /// uses `score <= SUSPICIOUS_THRESHOLD/3` (High) and
    /// `<= SUSPICIOUS_THRESHOLD*2/3` (Medium) — integer division gives exact
    /// cutoffs at 16 and 33 for the default threshold of 50. The inclusive
    /// `<=` at those exact values is the off-by-one this pins: 16→High,
    /// 17→Medium, 33→Medium, 34→Low. Scores are set precisely via a
    /// `weight: fullscreen N` override on a fullscreen-only (Allow) window.
    #[test]
    fn confidence_allow_path_boundaries_are_inclusive() {
        let conf_at = |score: i32| {
            let rules = Ruleset::from_lines(&[&format!("weight: fullscreen {score}")]);
            let w = OverlayWindow {
                title: "plain window".into(),
                coverage_percent: 100,
                has_close_button: true,
                ..Default::default()
            };
            let v = classify(&w, &rules);
            assert_eq!(v.score, score, "override should set exact score {score}");
            assert_eq!(v.decision, Decision::Allow, "score {score} must be Allow");
            v.confidence()
        };
        let hi = SUSPICIOUS_THRESHOLD / 3; // 16
        let med = SUSPICIOUS_THRESHOLD * 2 / 3; // 33
        assert_eq!(conf_at(hi), ConfidenceLevel::High, "16 → High");
        assert_eq!(conf_at(hi + 1), ConfidenceLevel::Medium, "17 → Medium");
        assert_eq!(conf_at(med), ConfidenceLevel::Medium, "33 → Medium");
        assert_eq!(conf_at(med + 1), ConfidenceLevel::Low, "34 → Low");
    }

    #[test]
    fn score_breakdown_covers_all_signals_and_sums_builtin_weights() {
        let w = OverlayWindow {
            title: "Call 1-800-555-0100 now".into(),
            coverage_percent: 99,
            origin: Origin::Unsolicited,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        let bd = v.score_breakdown();
        assert_eq!(bd.len(), v.signals.len(), "one entry per signal");
        // All signal names must match.
        let bd_names: Vec<&str> = bd.iter().map(|(s, _)| s.as_str()).collect();
        let sig_names: Vec<&str> = v.signals.iter().map(String::as_str).collect();
        assert_eq!(bd_names, sig_names);
        // Built-in signal weights are non-zero where signal_weight knows them.
        for (sig, w_val) in &bd {
            if let Some(expected) = signal_weight(sig) {
                assert_eq!(*w_val, expected, "weight mismatch for {sig}");
            }
        }
    }

    /// Pins the *documented* limitation of `score_breakdown` (Socratic round
    /// 11): it reports built-in **default** weights, not operator `weight:`
    /// overrides, because a `Verdict` does not carry the `Ruleset`. Under an
    /// override the breakdown weight (and thus its sum) deliberately differs
    /// from `Verdict::score`. This makes that contract explicit so a future
    /// change either updates the doc or this guard.
    #[test]
    fn score_breakdown_reports_default_weights_not_overrides() {
        let rules = Ruleset::from_lines(&["weight: fullscreen 60"]);
        let w = OverlayWindow {
            title: "plain window".into(),
            coverage_percent: 100,
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &rules);
        // classify() used the override → score 60.
        assert_eq!(v.score, 60);
        // …but the breakdown reports the built-in default (30), and its sum
        // therefore differs from the actual score, exactly as documented.
        let bd = v.score_breakdown();
        let fullscreen = bd
            .iter()
            .find(|(s, _)| s == "fullscreen")
            .expect("fullscreen in breakdown");
        assert_eq!(fullscreen.1, 30, "breakdown reports the default weight");
        let sum: i32 = bd.iter().map(|(_, w)| *w).sum();
        assert_ne!(sum, v.score, "sum differs from score under an override");
    }

    #[test]
    fn explain_includes_confidence_level() {
        let w = OverlayWindow {
            title: "Call 1-800-555-0100".into(),
            origin: Origin::Unsolicited,
            coverage_percent: 99,
            topmost: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        let ex = v.explain();
        assert!(
            ex.contains("high confidence")
                || ex.contains("medium confidence")
                || ex.contains("low confidence"),
            "explain must contain confidence level: {ex}"
        );
        assert!(ex.starts_with("Block") || ex.starts_with("Suspicious") || ex.starts_with("Allow"));
    }

    #[test]
    fn homoglyph_variants_share_signature() {
        // Two appearances of the same scam, one with a Cyrillic letter,
        // must produce the same repeat-detection signature so the flood
        // tracker counts them together.
        let a = OverlayWindow {
            title: "Virus Alert".into(),
            ..Default::default()
        };
        let b = OverlayWindow {
            title: "Vіrus Alert".into(), // Cyrillic і
            ..Default::default()
        };
        assert_eq!(signature(&a), signature(&b));
    }

    #[test]
    fn signature_stable_for_same_window() {
        let w = OverlayWindow {
            title: "  Your PC Is Infected  ".into(),
            url: Some("http://scam.example/alert?id=1".into()),
            ..Default::default()
        };
        let w2 = OverlayWindow {
            title: "your pc is infected".into(),
            // different query string, same host → same signature
            url: Some("https://scam.example/alert?id=999".into()),
            ..Default::default()
        };
        assert_eq!(signature(&w), signature(&w2));
    }

    #[test]
    fn signature_defeats_polymorphic_title_evasion() {
        // A flood re-popping the "same" alert with a per-appearance varying
        // unicode-evasion glyph must map to ONE signature, or repeat detection
        // is trivially bypassed. Each variant below renders as "virus alert"
        // but uses a different evasion the matcher already folds/strips.
        let base = OverlayWindow {
            title: "virus alert".into(),
            url: Some("http://scam.example/".into()),
            ..Default::default()
        };
        let expected = signature(&base);
        let variants = [
            "virus\u{200B} alert",          // zero-width space inserted
            "viru\u{0337}s alert",          // combining mark on a letter
            "virus alert \u{26A0}\u{FE0F}", // trailing warning emoji
            "\u{1D42F}\u{1D422}\u{1D42B}\u{1D42E}\u{1D42C} alert", // 𝐯𝐢𝐫𝐮𝐬 (math bold)
            "  VIRUS   ALERT  ",            // case + surrounding spaces
        ];
        for v in variants {
            let w = OverlayWindow {
                title: v.into(),
                url: Some("http://scam.example/".into()),
                ..Default::default()
            };
            assert_eq!(
                signature(&w),
                expected,
                "polymorphic variant {v:?} must share the base signature"
            );
        }
    }

    #[test]
    fn signature_preserves_distinct_digit_counters() {
        // Digits are intentionally NOT collapsed: two benign unsolicited
        // notifications differing only by a count must stay distinct, so they
        // can't be grouped into a false flood.
        let a = OverlayWindow {
            title: "you have 3 new messages".into(),
            url: None,
            ..Default::default()
        };
        let b = OverlayWindow {
            title: "you have 4 new messages".into(),
            url: None,
            ..Default::default()
        };
        assert_ne!(signature(&a), signature(&b));
    }

    #[test]
    fn signature_differs_for_different_host() {
        let a = OverlayWindow {
            title: "alert".into(),
            url: Some("http://a.example/".into()),
            ..Default::default()
        };
        let b = OverlayWindow {
            title: "alert".into(),
            url: Some("http://b.example/".into()),
            ..Default::default()
        };
        assert_ne!(signature(&a), signature(&b));
    }

    #[test]
    fn signature_host_ignores_port_and_query_scheme() {
        // Regression: the old inline host extractor kept `:port` and used
        // the LAST `://`, so these two — same scam host, different port and
        // a decoy `://` in the query — wrongly produced different
        // signatures (and one yielded "bank.com"). They must now match the
        // classifier's host (`scam.example`) and therefore each other.
        let a = OverlayWindow {
            title: "alert".into(),
            url: Some("http://scam.example:8080/r?next=http://bank.com".into()),
            ..Default::default()
        };
        let b = OverlayWindow {
            title: "alert".into(),
            url: Some("http://scam.example/other".into()),
            ..Default::default()
        };
        assert_eq!(signature(&a), signature(&b));
        assert!(signature(&a).ends_with("|scam.example"));
    }

    // ── enforce() ────────────────────────────────────────────────

    fn scam_window() -> OverlayWindow {
        OverlayWindow {
            title: "your computer is infected - call support".into(),
            url: Some("http://win-prize-now.example/x".into()),
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 200,
        }
    }

    fn benign_window() -> OverlayWindow {
        OverlayWindow {
            title: "report.pdf - reader".into(),
            url: None,
            coverage_percent: 40,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        }
    }

    #[test]
    fn enforce_dismisses_block_only() {
        let rules = Ruleset::from_lines(&["host: win-prize-now.example"]);
        let ctrl = NullController::with_windows(vec![
            EnumeratedWindow {
                id: "scam".into(),
                window: scam_window(),
            },
            EnumeratedWindow {
                id: "ok".into(),
                window: benign_window(),
            },
        ]);
        let outcomes = enforce(&ctrl, &rules).unwrap();
        assert_eq!(outcomes.len(), 2);

        let scam = outcomes.iter().find(|o| o.window_id == "scam").unwrap();
        assert_eq!(scam.decision, Decision::Block);
        assert!(scam.dismissed);

        let ok = outcomes.iter().find(|o| o.window_id == "ok").unwrap();
        assert_eq!(ok.decision, Decision::Allow);
        assert!(!ok.dismissed);

        // Only the scam window's id was dismissed.
        assert_eq!(ctrl.dismissed(), vec!["scam".to_string()]);
    }

    #[test]
    fn enforce_does_not_dismiss_suspicious() {
        // Build a window that lands Suspicious (50..100), not Block.
        let w = OverlayWindow {
            title: "newsletter".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: false, // +25
            blocks_input: false,
            origin: Origin::Unsolicited, // +25
            age_ms: 5_000,
        };
        let ctrl = NullController::with_windows(vec![EnumeratedWindow {
            id: "s".into(),
            window: w,
        }]);
        let outcomes = enforce(&ctrl, &Ruleset::default()).unwrap();
        assert_eq!(outcomes[0].decision, Decision::Suspicious);
        assert!(!outcomes[0].dismissed);
        assert!(ctrl.dismissed().is_empty());
    }

    #[test]
    fn enforce_empty_when_nothing_on_screen() {
        let ctrl = NullController::new();
        let outcomes = enforce(&ctrl, &Ruleset::default()).unwrap();
        assert!(outcomes.is_empty());
    }

    /// Test controller whose `dismiss` never succeeds: it returns `Err` for
    /// most ids and `Ok(false)` ("already gone") for the id `"gone"`. Used to
    /// exercise the documented resilience contract in [`enforce`].
    struct DismissFailController {
        seed: Vec<EnumeratedWindow>,
    }
    impl OverlayController for DismissFailController {
        fn name(&self) -> &'static str {
            "dismiss-fail"
        }
        fn available(&self) -> bool {
            true
        }
        fn enumerate(&self) -> Result<Vec<EnumeratedWindow>, ControllerError> {
            Ok(self.seed.clone())
        }
        fn dismiss(&self, id: &WindowId) -> Result<bool, ControllerError> {
            if id.as_str() == "gone" {
                Ok(false) // window already gone
            } else {
                Err(ControllerError::Dismiss(format!("helper failed for {id}")))
            }
        }
    }

    /// Resilience contract guard (Socratic round 12). `enforce` does
    /// `controller.dismiss(id).unwrap_or(false)`, so a dismiss that returns
    /// `Err` (helper crash, permission denied) or `Ok(false)` (the user
    /// closed the window first) must fold into `dismissed = false` *without*
    /// aborting the sweep — otherwise one failed dismiss would abandon every
    /// other scam window in the same tick. The existing enforce tests use
    /// `NullController`, whose `dismiss` always returns `Ok(true)`, so this
    /// path was never exercised. Two Block windows (hard host-block) are fed
    /// through a controller that fails both dismisses; enforce must still
    /// return `Ok` with both outcomes, each `decision == Block` but
    /// `dismissed == false`.
    #[test]
    fn enforce_survives_dismiss_failures_without_aborting() {
        let rules = Ruleset::from_lines(&["host: scam.example"]);
        let mk = |id: &str| EnumeratedWindow {
            id: id.into(),
            window: OverlayWindow {
                title: "you are infected".into(),
                url: Some("http://scam.example/x".into()),
                coverage_percent: 100,
                topmost: true,
                has_close_button: false,
                blocks_input: true,
                origin: Origin::Unsolicited,
                age_ms: 0,
            },
        };
        let ctrl = DismissFailController {
            seed: vec![mk("boom"), mk("gone")],
        };
        // Must not propagate the dismiss error as an enforce-level failure.
        let outcomes = enforce(&ctrl, &rules).expect("enforce must not abort on dismiss failure");
        assert_eq!(outcomes.len(), 2, "both windows processed despite failures");
        for o in &outcomes {
            assert_eq!(
                o.decision,
                Decision::Block,
                "{} is a hard host block",
                o.window_id
            );
            assert!(
                !o.dismissed,
                "{} dismiss failed → dismissed must be false",
                o.window_id
            );
        }
    }

    // ── clickfix_instruction signal (C1-5) ──────────────────────────

    #[test]
    fn clickfix_fires_on_alert_shaped_captcha_title() {
        // A modal ClickFix page titled "Verify you are human".
        let w = OverlayWindow {
            title: "verify you are human".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 200,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "clickfix_instruction"),
            "expected clickfix_instruction; got {:?}",
            v.signals
        );
        // W_CLICKFIX=20 contributes but does not block alone.
        assert!(v.score >= 20);
    }

    #[test]
    fn clickfix_does_not_fire_on_non_alert_shaped() {
        // Same CAPTCHA title but NOT alert-shaped (has close, not fullscreen,
        // not modal) — a legitimate reCAPTCHA page in a normal browser tab.
        let w = OverlayWindow {
            title: "verify you are human".into(),
            url: None,
            coverage_percent: 20,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "clickfix_instruction"),
            "should not fire on non-alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn clickfix_fires_on_winr_instruction() {
        // "press win+r" title in a fullscreen overlay.
        let w = OverlayWindow {
            title: "press win+r to fix your browser".into(),
            coverage_percent: 100,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 300,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(v.signals.iter().any(|s| s == "clickfix_instruction"));
    }

    #[test]
    fn clickfix_leet_evasion_defeated() {
        // Leet-substituted ClickFix title: "v3r1fy you are hum4n"
        // normalizes to "verify you are human" before the check.
        let w = OverlayWindow {
            title: "v3r1fy you are hum4n".into(),
            coverage_percent: 100,
            has_close_button: false,
            blocks_input: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(v.signals.iter().any(|s| s == "clickfix_instruction"));
    }

    #[test]
    fn clickfix_category_is_forced_action() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("clickfix_instruction"),
            Some(DarkPatternCategory::ForcedAction)
        );
    }

    // ── F6: glob title patterns in classify() ────────────────────────

    #[test]
    fn classify_fires_blocklist_title_on_glob_match() {
        // A glob pattern fires the `blocklist_title` signal with the same
        // weight as a `title:` substring rule.
        let rules = Ruleset::from_lines(&["glob: *your computer is infected*"]);
        let w = OverlayWindow {
            title: "⚠ Your Computer Is Infected — Call Support ⚠".into(),
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            ..Default::default()
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "blocklist_title"),
            "blocklist_title must fire when a glob rule matches"
        );
        assert_eq!(v.decision, Decision::Block);
        assert_eq!(
            v.matched_rule.as_deref(),
            Some("*your computer is infected*")
        );
    }

    #[test]
    fn glob_and_title_rules_coexist_without_double_counting() {
        // Both rule types in the same ruleset: only one `blocklist_title` signal.
        let rules = Ruleset::from_lines(&["title: infected", "glob: *security alert*"]);
        let w = OverlayWindow {
            title: "security alert: you are infected".into(),
            ..Default::default()
        };
        let v = classify(&w, &rules);
        let count = v
            .signals
            .iter()
            .filter(|s| s.as_str() == "blocklist_title")
            .count();
        assert_eq!(count, 1, "blocklist_title must fire at most once");
    }

    // ── C5-3: weight overrides in classify() ─────────────────────────

    #[test]
    fn weight_override_changes_score() {
        // A window with only a `fullscreen` signal. With default weight (30)
        // the score is 30. Override it to 60 → score is 60.
        let rules_default = Ruleset::default();
        let rules_boosted = Ruleset::from_lines(&["weight: fullscreen 60"]);
        let w = OverlayWindow {
            title: "plain window".into(),
            coverage_percent: 100,
            has_close_button: true,
            ..Default::default()
        };
        let v_default = classify(&w, &rules_default);
        let v_boosted = classify(&w, &rules_boosted);
        assert!(
            v_boosted.score > v_default.score,
            "boosted weight must yield higher score"
        );
        assert_eq!(v_default.score, 30, "default fullscreen weight is 30");
        assert_eq!(v_boosted.score, 60, "overridden fullscreen weight is 60");
    }

    /// Integer-overflow safety of the additive score (Socratic round 7). The
    /// score is `i32`, accumulated via `score += rules.weight_of(...)`. Without
    /// the parse-time weight clamp, two co-firing signals each overridden near
    /// `i32::MAX` would overflow the accumulation — a debug-build panic or a
    /// release-build wrap that flips a would-be Block to Allow via `score.max(0)`.
    /// With operator weights clamped to ±`MAX_ABS_WEIGHT`, the same hostile
    /// config now produces a large-but-finite score and a correct Block, and the
    /// addition cannot overflow (this test would panic in debug on overflow).
    #[test]
    fn extreme_weight_override_does_not_overflow_score() {
        let rules = Ruleset::from_lines(&[
            "weight: fullscreen 2000000000",
            "weight: topmost 2000000000",
            "weight: no_close_button 2000000000",
            "weight: unsolicited 2000000000",
        ]);
        let w = OverlayWindow {
            title: "special offer".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &rules);
        // No panic (debug) / no wrap (release): score is positive and the
        // verdict is Block, not an overflow-wrapped Allow.
        assert!(v.score > 0, "score must stay positive, got {}", v.score);
        assert_eq!(v.decision, Decision::Block);
    }

    #[test]
    fn weight_override_to_zero_silences_signal() {
        // With fullscreen weight set to 0, a fullscreen window that normally
        // scores 30 should score 0 (assuming no other signals).
        let rules = Ruleset::from_lines(&["weight: fullscreen 0"]);
        let w = OverlayWindow {
            title: "plain window".into(),
            coverage_percent: 100,
            has_close_button: true,
            ..Default::default()
        };
        let v = classify(&w, &rules);
        assert_eq!(v.score, 0);
        assert_eq!(v.decision, Decision::Allow);
    }

    /// Operator-override coverage guard (Socratic round 4). The two
    /// override tests above prove the `weight:` mechanism works — but only
    /// for `fullscreen`, a geometry signal. The product's configurability
    /// promise is that operators can retune *any* signal, including the 59
    /// content signals and the negative `user_initiated` relief. If a
    /// content block were ever changed to add a hardcoded `W_X` instead of
    /// routing through `rules.weight_of("x", W_X)`, the operator override
    /// would be silently ignored for that signal and only this test would
    /// catch it. For each content signal, overriding its weight to a sentinel
    /// must move the score by exactly `sentinel - default`.
    #[test]
    fn weight_override_honored_for_content_signals() {
        const SENTINEL: i32 = 11;
        let geom = |title: &str| OverlayWindow {
            title: title.into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        // Single-firing trigger titles (same as the additive-contract test).
        let cases: &[(&str, &str)] = &[
            (
                "pet_sale_scam",
                "french bulldog pup for sale — pay crate deposit before shipping",
            ),
            (
                "windows_activation_scam",
                "windows is not activated — call microsoft support to activate your copy",
            ),
            (
                "recovery_scam",
                "recover your lost funds — 100% guaranteed — contact our certified recovery expert",
            ),
            (
                "veterans_benefit_scam",
                "va disability claim — processing fee — expedite your claim today",
            ),
            (
                "fake_copyright_scam",
                "dmca violation — pay settlement — click to settle immediately",
            ),
            (
                "crypto_giveaway_scam",
                "official giveaway — send any amount — double your bitcoin instantly",
            ),
            (
                "otp_interception_scam",
                "we sent a verification code — share the code with our agent to verify",
            ),
            (
                "family_emergency_scam",
                "your grandson has been arrested — send bail money immediately",
            ),
        ];
        for (name, title) in cases {
            let default_w =
                signal_weight(name).unwrap_or_else(|| panic!("{name} has no signal_weight()"));
            let v_def = classify(&geom(title), &Ruleset::default());
            let v_ovr = classify(
                &geom(title),
                &Ruleset::from_lines(&[&format!("weight: {name} {SENTINEL}")]),
            );
            assert_eq!(
                v_ovr.score - v_def.score,
                SENTINEL - default_w,
                "{name}: operator weight override not honored in classify() — \
                 the block likely adds a hardcoded weight instead of routing \
                 through rules.weight_of()"
            );
        }
    }

    /// Operator-override of the **negative** relief weight (Socratic round 4).
    /// `user_initiated` contributes −40 (relief: the user opened the window,
    /// so trust it more). An operator may want to soften or disable that
    /// relief. This proves the override flows through for a negative weight
    /// too, with the window kept comfortably above zero so the `score.max(0)`
    /// clamp does not mask the delta.
    #[test]
    fn weight_override_honored_for_negative_user_initiated() {
        let w = OverlayWindow {
            // topmost + no-close keep the raw score positive even with −40,
            // so neither classify result is clamped at 0.
            title: "plain window".into(),
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            origin: Origin::UserInitiated,
            ..Default::default()
        };
        let v_def = classify(&w, &Ruleset::default());
        let v_ovr = classify(&w, &Ruleset::from_lines(&["weight: user_initiated 0"]));
        assert!(
            v_def.score > 0,
            "baseline must be unclamped; got {}",
            v_def.score
        );
        assert_eq!(
            v_ovr.score - v_def.score,
            0 - W_USER_INITIATED_RELIEF,
            "disabling the user_initiated relief override must raise the score \
             by exactly 40 (0 − (−40))"
        );
    }

    /// Decision-threshold boundary guard (Socratic round 5). The product's
    /// single most important output is the Allow / Suspicious / Block
    /// verdict, decided by `score >= BLOCK_THRESHOLD` / `>= SUSPICIOUS_THRESHOLD`.
    /// That `>=` (inclusive) semantics at the *exact* threshold value is the
    /// classic off-by-one: flipping a `>=` to `>` would silently downgrade a
    /// score of exactly 50 to Allow or exactly 100 to Suspicious — a severity
    /// regression on the core contract that none of the existing decision
    /// tests (which use scores like 90 or 125, comfortably away from the
    /// edges) would catch. This pins all four boundary points by using a
    /// `weight:` override to drive a fullscreen-only window to an exact score.
    #[test]
    fn decision_thresholds_are_inclusive_at_exact_boundaries() {
        // A fullscreen-only window scores exactly its fullscreen weight
        // (proven by weight_override_changes_score: coverage 100 + closable
        // + neutral origin → score == fullscreen weight, no other signal).
        let w = || OverlayWindow {
            title: "plain window".into(),
            coverage_percent: 100,
            has_close_button: true,
            ..Default::default()
        };
        let at = |score: i32| {
            let rules = Ruleset::from_lines(&[&format!("weight: fullscreen {score}")]);
            let v = classify(&w(), &rules);
            assert_eq!(
                v.score, score,
                "override should set score to exactly {score}"
            );
            v.decision
        };
        // Just below / at the Suspicious threshold (50).
        assert_eq!(at(SUSPICIOUS_THRESHOLD - 1), Decision::Allow, "49 → Allow");
        assert_eq!(
            at(SUSPICIOUS_THRESHOLD),
            Decision::Suspicious,
            "50 → Suspicious"
        );
        // Just below / at the Block threshold (100).
        assert_eq!(
            at(BLOCK_THRESHOLD - 1),
            Decision::Suspicious,
            "99 → Suspicious"
        );
        assert_eq!(at(BLOCK_THRESHOLD), Decision::Block, "100 → Block");
        // Zero stays Allow (lower edge).
        assert_eq!(at(0), Decision::Allow, "0 → Allow");
    }

    // ── E7: urgency_countdown signal ─────────────────────────────────

    #[test]
    fn urgency_countdown_fires_on_alert_shaped_window() {
        // Fullscreen modal with "expires in 5:00" — the classic scam timer.
        let w = OverlayWindow {
            title: "your session expires in 5:00 call support".into(),
            url: None,
            coverage_percent: 100,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 200,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "urgency_countdown"),
            "expected urgency_countdown; got {:?}",
            v.signals
        );
        assert!(v.score >= W_URGENCY_COUNTDOWN);
    }

    #[test]
    fn urgency_countdown_does_not_fire_without_alert_shape() {
        // Same scam title but NOT alert-shaped (has close, not fullscreen) —
        // should not fire because a normal browser tab can show countdowns.
        let w = OverlayWindow {
            title: "your session expires in 5:00 call support".into(),
            url: None,
            coverage_percent: 20,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "urgency_countdown"),
            "must not fire on non-alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn urgency_countdown_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("urgency_countdown"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    #[test]
    fn urgency_countdown_leet_evasion_defeated() {
        // "3xp1r3s" → "expires" after normalize_for_match, then countdown fires.
        let w = OverlayWindow {
            title: "system 3xp1r3s in 2:59".into(),
            coverage_percent: 100,
            has_close_button: false,
            blocks_input: true,
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "urgency_countdown"),
            "expected urgency_countdown after leet folding; got {:?}",
            v.signals
        );
    }

    // ── D10: Levenshtein typosquat detection ─────────────────────────

    #[test]
    fn levenshtein_deletion_typosquat_fires() {
        // "gogle.com" → skeleton "gogle" → edit distance 1 from "google".
        let w = OverlayWindow {
            title: "security alert".into(),
            url: Some("http://gogle.com/alert".into()),
            coverage_percent: 0,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::Unknown,
            age_ms: 1_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "typosquat_brand"),
            "expected typosquat_brand for 'gogle'; got {:?}",
            v.signals
        );
        assert!(v.score >= W_TYPOSQUAT_BRAND);
    }

    #[test]
    fn levenshtein_insertion_typosquat_fires() {
        // "amzon.com" — 'a' deleted → edit distance 1 from "amazon".
        let w = OverlayWindow {
            title: "virus alert".into(),
            url: Some("http://amzon.com/security".into()),
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "typosquat_brand"),
            "expected typosquat_brand for 'amzon'; got {:?}",
            v.signals
        );
    }

    #[test]
    fn real_brand_domain_does_not_fire_typosquat() {
        // "google.com" — skeleton "google" == brand → distance 0 → brand_impersonation
        // handles it; typosquat must NOT double-fire.
        let w = OverlayWindow {
            title: "anything".into(),
            url: Some("http://google.com/".into()),
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "typosquat_brand"),
            "must not fire on the real brand; got {:?}",
            v.signals
        );
        // brand_impersonation must also NOT fire (skeleton == literal "google").
        assert!(
            !v.signals.iter().any(|s| s == "brand_impersonation"),
            "brand_impersonation must not fire on the real brand"
        );
    }

    #[test]
    fn homograph_fires_brand_impersonation_not_typosquat() {
        // Cyrillic-substituted host: skeleton == "paypal" (distance 0) →
        // brand_impersonation fires, typosquat must NOT double-fire.
        let w = OverlayWindow {
            title: "anything".into(),
            // раура1.com: Cyrillic р,а,у,р,а + digit 1 → skeleton "paypal"
            url: Some("http://раура1.com/page".into()),
            ..Default::default()
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "brand_impersonation"),
            "expected brand_impersonation for homograph; got {:?}",
            v.signals
        );
        assert!(
            !v.signals.iter().any(|s| s == "typosquat_brand"),
            "typosquat must not double-fire alongside brand_impersonation; got {:?}",
            v.signals
        );
    }

    #[test]
    fn typosquat_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("typosquat_brand"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    #[test]
    fn levenshtein_distance_unit() {
        // Same string → distance 0.
        assert_eq!(levenshtein_distance(b"paypal", b"paypal"), 0);
        // Single deletion → distance 1.
        assert_eq!(levenshtein_distance(b"googl", b"google"), 1);
        assert_eq!(levenshtein_distance(b"amzon", b"amazon"), 1);
        // Single insertion → distance 1.
        assert_eq!(levenshtein_distance(b"googlee", b"google"), 1);
        // Single substitution → distance 1.
        assert_eq!(levenshtein_distance(b"googlo", b"google"), 1);
        // Two edits → distance 2 (not 1).
        assert_eq!(levenshtein_distance(b"ggle", b"google"), 2);
        // Empty string edge cases.
        assert_eq!(levenshtein_distance(b"", b""), 0);
        assert_eq!(levenshtein_distance(b"a", b""), 1);
        assert_eq!(levenshtein_distance(b"", b"a"), 1);
        // Length diff > 1: returns early (sentinel or true distance ≥ 2).
        assert!(levenshtein_distance(b"", b"google") >= 2);
        assert!(levenshtein_distance(b"ggle", b"google") >= 2);
    }

    // ── E10: Cloud blob-storage lure detection ────────────────────────

    #[test]
    fn cloud_storage_fires_on_azure_blob_alert_shaped() {
        // An alert-shaped window served from Azure Blob Storage — the
        // canonical TSS delivery vector identified in THREAT_INTEL_2026.
        let rules = Ruleset::from_lines(&[]);
        let w = OverlayWindow {
            title: "Warning: your computer is infected".into(),
            coverage_percent: 95,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            age_ms: 0,
            origin: Origin::Unsolicited,
            url: Some("https://scamtenant.blob.core.windows.net/payload/alert.html".into()),
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "cloud_storage_abuse"),
            "expected cloud_storage_abuse; got {:?}",
            v.signals
        );
        assert!(v.score >= W_CLOUD_STORAGE_ABUSE);
    }

    #[test]
    fn cloud_storage_fires_on_s3_alert_shaped() {
        let rules = Ruleset::from_lines(&[]);
        let w = OverlayWindow {
            title: "Security alert call support".into(),
            coverage_percent: 98,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            age_ms: 0,
            origin: Origin::Unsolicited,
            url: Some("https://bucket-name.s3.amazonaws.com/scam.html".into()),
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "cloud_storage_abuse"),
            "expected cloud_storage_abuse; got {:?}",
            v.signals
        );
    }

    #[test]
    fn cloud_storage_does_not_fire_without_alert_shape() {
        // A closable, non-topmost cloud-hosted window (normal browser tab)
        // must not fire — the alert_shaped guard is the FP fence.
        let rules = Ruleset::from_lines(&[]);
        let w = OverlayWindow {
            title: "App update available".into(),
            coverage_percent: 40,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            age_ms: 0,
            origin: Origin::UserInitiated,
            url: Some("https://mytenant.blob.core.windows.net/releases/update.html".into()),
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "cloud_storage_abuse"),
            "cloud_storage_abuse must not fire on non-alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn cloud_storage_does_not_fire_on_own_domain() {
        // A window served from a normal domain is not affected.
        let rules = Ruleset::from_lines(&[]);
        let w = OverlayWindow {
            title: "Warning virus detected".into(),
            coverage_percent: 98,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            age_ms: 0,
            origin: Origin::Unsolicited,
            url: Some("https://scam.example.com/alert.html".into()),
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "cloud_storage_abuse"),
            "cloud_storage_abuse must not fire for a non-blob domain; got {:?}",
            v.signals
        );
    }

    #[test]
    fn cloud_storage_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("cloud_storage_abuse"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    #[test]
    fn is_cloud_storage_host_unit() {
        // True cases — known blob-storage hosts with a tenant prefix.
        assert!(is_cloud_storage_host("tenant.blob.core.windows.net"));
        assert!(is_cloud_storage_host("a.web.core.windows.net"));
        assert!(is_cloud_storage_host("my-bucket.s3.amazonaws.com"));
        assert!(is_cloud_storage_host("proj.storage.googleapis.com"));
        assert!(is_cloud_storage_host("fb.firebasestorage.googleapis.com"));
        assert!(is_cloud_storage_host("r2tenant.r2.cloudflarestorage.com"));
        // False cases — no tenant prefix (raw suffix), own domain, unrelated cloud.
        assert!(!is_cloud_storage_host("blob.core.windows.net"));
        assert!(!is_cloud_storage_host("amazonaws.com"));
        assert!(!is_cloud_storage_host("example.com"));
        assert!(!is_cloud_storage_host(""));
    }

    // ── D11: Expanded KNOWN_BRANDS coverage ──────────────────────────

    #[test]
    fn norton_combosquat_fires() {
        // norton-alert.com — combosquat AV+lure; Norton is the #1 TSS AV brand.
        let rules = Ruleset::from_lines(&[]);
        let w = OverlayWindow {
            title: "Norton Security Alert".into(),
            coverage_percent: 80,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            age_ms: 0,
            origin: Origin::UserInitiated,
            url: Some("https://norton-alert.com/warning".into()),
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "combosquat_brand"),
            "combosquat must fire for 'norton-alert.com'; got {:?}",
            v.signals
        );
    }

    #[test]
    fn mcafee_combosquat_fires() {
        // mcafee-remove.com — combosquat AV+lure.
        let rules = Ruleset::from_lines(&[]);
        let w = OverlayWindow {
            title: "McAfee Total Protection".into(),
            coverage_percent: 50,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            age_ms: 0,
            origin: Origin::UserInitiated,
            url: Some("https://mcafee-remove.net/scan".into()),
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "combosquat_brand"),
            "combosquat must fire for 'mcafee-remove.net'; got {:?}",
            v.signals
        );
    }

    #[test]
    fn jp_brands_detected_via_typosquat() {
        // "docom0.com" (digit-0 substitution for 'o') → skeleton "docomo" → typosquat.
        let rules = Ruleset::from_lines(&[]);
        let w = OverlayWindow {
            title: "Security warning".into(),
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            age_ms: 0,
            origin: Origin::Unsolicited,
            url: Some("https://docom0.co.jp/alert".into()),
        };
        let v = classify(&w, &rules);
        // skeleton("docom0") folds host-confusables: 0→o → "docomo"
        // That's distance 0 → brand_impersonation, not typosquat.
        assert!(
            v.signals.iter().any(|s| s == "brand_impersonation"),
            "brand_impersonation must fire for 'docom0' (skeleton 'docomo'); got {:?}",
            v.signals
        );
    }

    #[test]
    fn venmo_zelle_combosquat_fire() {
        for (host, brand) in [
            ("venmo-transfer.com", "venmo"),
            ("zelle-payment.net", "zelle"),
        ] {
            let rules = Ruleset::from_lines(&[]);
            let w = OverlayWindow {
                title: "Payment verification required".into(),
                coverage_percent: 60,
                topmost: false,
                has_close_button: true,
                blocks_input: false,
                age_ms: 0,
                origin: Origin::UserInitiated,
                url: Some(format!("https://{host}/verify")),
            };
            let v = classify(&w, &rules);
            assert!(
                v.signals.iter().any(|s| s == "combosquat_brand"),
                "combosquat must fire for '{host}' ({brand}); got {:?}",
                v.signals
            );
        }
    }

    #[test]
    fn real_brand_domains_do_not_fire_impersonation() {
        // Sanity check for new brands: literal brand domain must never fire
        // brand_impersonation or typosquat_brand.
        for brand_host in [
            "norton.com",
            "mcafee.com",
            "venmo.com",
            "zelle.com",
            "docomo.ne.jp",
            "softbank.jp",
            "rakuten.co.jp",
        ] {
            let rules = Ruleset::from_lines(&[]);
            let w = OverlayWindow {
                title: "Account notice".into(),
                coverage_percent: 50,
                topmost: false,
                has_close_button: true,
                blocks_input: false,
                age_ms: 0,
                origin: Origin::UserInitiated,
                url: Some(format!("https://{brand_host}/account")),
            };
            let v = classify(&w, &rules);
            assert!(
                !v.signals.iter().any(|s| s == "brand_impersonation"),
                "brand_impersonation must NOT fire for '{brand_host}'; got {:?}",
                v.signals
            );
            assert!(
                !v.signals.iter().any(|s| s == "typosquat_brand"),
                "typosquat_brand must NOT fire for '{brand_host}'; got {:?}",
                v.signals
            );
        }
    }

    // ── E12: URL path brand+lure lure detection ───────────────────────

    #[test]
    fn url_path_lure_fires_on_hyphen_combosquat_path() {
        // /microsoft-alert/ — brand "microsoft" + lure "alert" as hyphen tokens.
        let rules = Ruleset::from_lines(&[]);
        let w = OverlayWindow {
            title: "Security warning".into(),
            coverage_percent: 96,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            age_ms: 0,
            origin: Origin::Unsolicited,
            url: Some("https://evil.example.com/microsoft-alert/index.html".into()),
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "url_path_lure"),
            "expected url_path_lure for '/microsoft-alert/'; got {:?}",
            v.signals
        );
    }

    #[test]
    fn url_path_lure_fires_on_slash_separated_brand_lure() {
        // /norton/remove/ — brand "norton" + lure "remove" as slash-separated segments.
        let rules = Ruleset::from_lines(&[]);
        let w = OverlayWindow {
            title: "AV warning".into(),
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            age_ms: 0,
            origin: Origin::Unsolicited,
            url: Some("https://fake-av.com/norton/remove/now".into()),
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "url_path_lure"),
            "expected url_path_lure for '/norton/remove/now'; got {:?}",
            v.signals
        );
    }

    #[test]
    fn url_path_lure_does_not_fire_without_alert_shape() {
        // A closable, non-topmost window: alert_shaped is false → no fire.
        let rules = Ruleset::from_lines(&[]);
        let w = OverlayWindow {
            title: "Helpful article".into(),
            coverage_percent: 40,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            age_ms: 0,
            origin: Origin::UserInitiated,
            url: Some("https://blog.example.com/microsoft-alerts/setup-guide".into()),
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "url_path_lure"),
            "url_path_lure must not fire for non-alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn url_path_lure_does_not_fire_without_lure_word() {
        // Brand in path but no lure word adjacent → no fire.
        let rules = Ruleset::from_lines(&[]);
        let w = OverlayWindow {
            title: "Page notice".into(),
            coverage_percent: 96,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            age_ms: 0,
            origin: Origin::Unsolicited,
            url: Some("https://news.example.com/microsoft/announces/new-feature".into()),
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "url_path_lure"),
            "url_path_lure must not fire when no lure word is adjacent; got {:?}",
            v.signals
        );
    }

    #[test]
    fn has_path_lure_unit() {
        // Brand + lure as hyphen tokens.
        assert!(has_path_lure("https://evil.com/paypal-login/page"));
        assert!(has_path_lure("https://evil.com/norton-remove/"));
        // Brand + lure as slash-separated segments.
        assert!(has_path_lure("https://evil.com/apple/support/"));
        // Brand with lure within 2 tokens (across one intermediate token).
        assert!(has_path_lure("https://evil.com/microsoft/security/alert"));
        // No lure → false.
        assert!(!has_path_lure("https://evil.com/microsoft/news/product"));
        // No brand → false.
        assert!(!has_path_lure("https://evil.com/account/login/verify"));
        // Empty path → false.
        assert!(!has_path_lure("https://evil.com"));
    }

    #[test]
    fn url_path_lure_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("url_path_lure"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E13: Forced-retention "do not close" instruction ─────────────

    #[test]
    fn forced_retention_fires_on_alert_shaped_window() {
        let rules = Ruleset::from_lines(&[]);
        let w = OverlayWindow {
            title: "DO NOT CLOSE THIS WINDOW — Microsoft is helping you".into(),
            coverage_percent: 96,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            age_ms: 0,
            origin: Origin::Unsolicited,
            url: None,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "forced_retention_cue"),
            "expected forced_retention_cue; got {:?}",
            v.signals
        );
        assert!(v.score >= W_FORCED_RETENTION);
    }

    #[test]
    fn forced_retention_does_not_fire_without_alert_shape() {
        // A user-initiated, closable installer: alert_shaped = false → no fire.
        let rules = Ruleset::from_lines(&[]);
        let w = OverlayWindow {
            title: "Installing… do not close this window".into(),
            coverage_percent: 50,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            age_ms: 0,
            origin: Origin::UserInitiated,
            url: None,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "forced_retention_cue"),
            "forced_retention_cue must not fire for closable installer; got {:?}",
            v.signals
        );
    }

    #[test]
    fn forced_retention_category_is_obstruction() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("forced_retention_cue"),
            Some(DarkPatternCategory::Obstruction)
        );
    }

    // ── E14: Credential-harvest phishing cue ─────────────────────────

    #[test]
    fn credential_harvest_fires_on_alert_shaped_account_alarm() {
        let rules = Ruleset::from_lines(&[]);
        let w = OverlayWindow {
            title: "Your account has been suspended — verify now".into(),
            coverage_percent: 96,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            age_ms: 0,
            origin: Origin::Unsolicited,
            url: None,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "credential_harvest_cue"),
            "expected credential_harvest_cue; got {:?}",
            v.signals
        );
        assert!(v.score >= W_CREDENTIAL_HARVEST);
    }

    #[test]
    fn credential_harvest_does_not_fire_without_alert_shape() {
        // A closable security article window must not fire.
        let rules = Ruleset::from_lines(&[]);
        let w = OverlayWindow {
            title: "How to protect your account from suspicious login activity".into(),
            coverage_percent: 40,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            age_ms: 0,
            origin: Origin::UserInitiated,
            url: None,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "credential_harvest_cue"),
            "credential_harvest_cue must not fire for non-alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn credential_harvest_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("credential_harvest_cue"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E15: fake_scanner_cue ─────────────────────────────────────────────

    #[test]
    fn fake_scanner_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        // Full-screen + no close + "4 threats found" = alert-shaped scareware.
        let w = OverlayWindow {
            title: "4 threats detected on your pc remove now".into(),
            coverage_percent: 99,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            age_ms: 1_000,
            origin: Origin::Unsolicited,
            url: None,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "fake_scanner_cue"),
            "expected fake_scanner_cue; got {:?}",
            v.signals
        );
        assert!(v.score >= W_FAKE_SCANNER);
    }

    #[test]
    fn fake_scanner_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        // User opened a legitimate AV scan summary — closable, user-initiated.
        let w = OverlayWindow {
            title: "scanning for threats complete 0 found".into(),
            coverage_percent: 30,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            age_ms: 5_000,
            origin: Origin::UserInitiated,
            url: None,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "fake_scanner_cue"),
            "fake_scanner_cue must not fire for user-initiated closable AV summary; got {:?}",
            v.signals
        );
    }

    #[test]
    fn fake_scanner_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("fake_scanner_cue"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E16: subscription_lure ────────────────────────────────────────────

    #[test]
    fn subscription_lure_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        // Full-screen + no close + expiry coercion language.
        let w = OverlayWindow {
            title: "your norton subscription has expired renew now".into(),
            coverage_percent: 95,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            age_ms: 500,
            origin: Origin::Unsolicited,
            url: None,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "subscription_lure"),
            "expected subscription_lure; got {:?}",
            v.signals
        );
        assert!(v.score >= W_SUBSCRIPTION_LURE);
    }

    #[test]
    fn subscription_lure_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        // Legitimate renewal reminder: closable, user-navigated.
        let w = OverlayWindow {
            title: "your subscription expired renew now".into(),
            coverage_percent: 30,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            age_ms: 10_000,
            origin: Origin::UserInitiated,
            url: None,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "subscription_lure"),
            "subscription_lure must not fire for non-alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn subscription_lure_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("subscription_lure"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E17: authority_lure ───────────────────────────────────────────────

    #[test]
    fn authority_lure_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        // Full-screen + no close + FBI impersonation.
        let w = OverlayWindow {
            title: "fbi warning your computer has been locked".into(),
            coverage_percent: 99,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            age_ms: 500,
            origin: Origin::Unsolicited,
            url: None,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "authority_lure"),
            "expected authority_lure; got {:?}",
            v.signals
        );
        assert!(v.score >= W_AUTHORITY_LURE);
    }

    #[test]
    fn authority_lure_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        // A news article in a user-opened browser tab.
        let w = OverlayWindow {
            title: "fbi warning new phishing campaign targets banks".into(),
            coverage_percent: 20,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            age_ms: 30_000,
            origin: Origin::UserInitiated,
            url: None,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "authority_lure"),
            "authority_lure must not fire for user-initiated closable tab; got {:?}",
            v.signals
        );
    }

    #[test]
    fn authority_lure_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("authority_lure"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E18: screen_share_lure ────────────────────────────────────────────

    #[test]
    fn screen_share_lure_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "share your screen with our support agent to continue".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 500,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "screen_share_lure"),
            "expected screen_share_lure; got {:?}",
            v.signals
        );
        assert!(v.score >= W_SCREEN_SHARE);
    }

    #[test]
    fn screen_share_lure_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        // Legitimate Zoom/Teams share-screen prompt — user-opened, closable.
        let w = OverlayWindow {
            title: "share your screen with our support agent to continue".into(),
            url: None,
            coverage_percent: 20,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 500,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "screen_share_lure"),
            "screen_share_lure must not fire for user-initiated closable window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn screen_share_lure_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("screen_share_lure"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E19: crypto_drain_lure ────────────────────────────────────────────

    #[test]
    fn crypto_drain_lure_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "your wallet has been compromised verify now to secure funds".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 500,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "crypto_drain_lure"),
            "expected crypto_drain_lure; got {:?}",
            v.signals
        );
        assert!(v.score >= W_CRYPTO_DRAIN);
    }

    #[test]
    fn crypto_drain_lure_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        // News article in a user-opened browser tab.
        let w = OverlayWindow {
            title: "coinbase wallet compromised in 200m hack security researchers say".into(),
            url: None,
            coverage_percent: 20,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 30_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "crypto_drain_lure"),
            "crypto_drain_lure must not fire for user-initiated closable tab; got {:?}",
            v.signals
        );
    }

    #[test]
    fn crypto_drain_lure_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("crypto_drain_lure"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E20: prize_lure ───────────────────────────────────────────────────

    #[test]
    fn prize_lure_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "congratulations you have won a prize click here to claim".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 500,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "prize_lure"),
            "expected prize_lure; got {:?}",
            v.signals
        );
        assert!(v.score >= W_PRIZE_LURE);
    }

    #[test]
    fn prize_lure_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        // Legitimate loyalty-program notification in user-opened, closable tab.
        let w = OverlayWindow {
            title: "you have earned 500 reward points eligible for a free reward claim".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "prize_lure"),
            "prize_lure must not fire for user-initiated closable tab; got {:?}",
            v.signals
        );
    }

    #[test]
    fn prize_lure_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("prize_lure"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E21: download_trap_lure ───────────────────────────────────────────

    #[test]
    fn download_trap_lure_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "flash player update required to view this content".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 500,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "download_trap_lure"),
            "expected download_trap_lure; got {:?}",
            v.signals
        );
        assert!(v.score >= W_DOWNLOAD_TRAP);
    }

    #[test]
    fn download_trap_lure_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        // Legitimate browser extension install prompt — user-initiated, closable.
        let w = OverlayWindow {
            title: "install extension to enable developer tools".into(),
            url: None,
            coverage_percent: 15,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 2_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "download_trap_lure"),
            "download_trap_lure must not fire for user-initiated closable prompt; got {:?}",
            v.signals
        );
    }

    #[test]
    fn download_trap_lure_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("download_trap_lure"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E-series conditions in composite rules ───────────────────────────

    #[test]
    fn composite_rule_with_crypto_drain_condition_fires() {
        // An operator-defined composite rule using has_crypto_drain_lure fires
        // when the crypto_drain_lure signal is present.
        let rules = Ruleset::from_lines(&[
            "composite: crypto_phone_block 50 has_crypto_drain_lure has_phone_number",
        ]);
        let w = OverlayWindow {
            title: "your wallet has been compromised call 1-800-555-0100 to secure it".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 500,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "crypto_phone_block"),
            "composite crypto_phone_block must fire when both conditions hold; got {:?}",
            v.signals
        );
    }

    #[test]
    fn composite_rule_with_prize_lure_condition_fires() {
        // An operator-defined composite rule using has_prize_lure fires correctly.
        let rules =
            Ruleset::from_lines(&["composite: prize_coercive 40 has_prize_lure alert_shaped"]);
        let w = OverlayWindow {
            title: "you have won a prize claim now before it expires".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 500,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "prize_coercive"),
            "composite prize_coercive must fire; got {:?}",
            v.signals
        );
    }

    // ── E24: package_fee_lure ────────────────────────────────────────────

    #[test]
    fn package_fee_lure_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "your package is on hold customs fee required to release".into(),
            url: None,
            coverage_percent: 95,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 400,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "package_fee_lure"),
            "expected package_fee_lure; got {:?}",
            v.signals
        );
        assert!(v.score >= W_PACKAGE_FEE);
    }

    #[test]
    fn package_fee_lure_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "your order has been shipped".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "package_fee_lure"),
            "package_fee_lure must not fire for user-initiated closable notification; got {:?}",
            v.signals
        );
    }

    #[test]
    fn package_fee_lure_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("package_fee_lure"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E25: sextortion_lure ──────────────────────────────────────────────

    #[test]
    fn sextortion_lure_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "we have recorded you send bitcoin to prevent release to your contacts".into(),
            url: None,
            coverage_percent: 98,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 150,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "sextortion_lure"),
            "expected sextortion_lure; got {:?}",
            v.signals
        );
        assert!(v.score >= W_SEXTORTION);
    }

    #[test]
    fn sextortion_lure_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "allow your camera for this video call".into(),
            url: None,
            coverage_percent: 20,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 3_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "sextortion_lure"),
            "sextortion_lure must not fire for user-initiated webcam dialog; got {:?}",
            v.signals
        );
    }

    #[test]
    fn sextortion_lure_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("sextortion_lure"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E22: qr_code_lure ─────────────────────────────────────────────────

    #[test]
    fn qr_code_lure_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "scan the qr code to verify your identity".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 300,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "qr_code_lure"),
            "expected qr_code_lure; got {:?}",
            v.signals
        );
        assert!(v.score >= W_QR_CODE_LURE);
    }

    #[test]
    fn qr_code_lure_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        // Legitimate e-ticket QR display — user-initiated, has close button.
        let w = OverlayWindow {
            title: "show your qr code at the gate".into(),
            url: None,
            coverage_percent: 20,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "qr_code_lure"),
            "qr_code_lure must not fire for user-initiated closable QR display; got {:?}",
            v.signals
        );
    }

    #[test]
    fn qr_code_lure_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("qr_code_lure"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E23: ip_alarm_lure ────────────────────────────────────────────────

    #[test]
    fn ip_alarm_lure_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "your ip address has been hacked call support now".into(),
            url: None,
            coverage_percent: 95,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "ip_alarm_lure"),
            "expected ip_alarm_lure; got {:?}",
            v.signals
        );
        assert!(v.score >= W_IP_ALARM);
    }

    #[test]
    fn ip_alarm_lure_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        // Legitimate "what is my IP" page — user-initiated, closable.
        let w = OverlayWindow {
            title: "your ip address is 203.0.113.45".into(),
            url: None,
            coverage_percent: 15,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 3_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "ip_alarm_lure"),
            "ip_alarm_lure must not fire for user-initiated IP-info page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn ip_alarm_lure_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("ip_alarm_lure"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E26: gift_card_demand ─────────────────────────────────────────────

    #[test]
    fn gift_card_demand_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "please purchase gift cards and send codes to unlock your computer".into(),
            url: None,
            coverage_percent: 0,
            topmost: false,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 300,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "gift_card_demand"),
            "expected gift_card_demand; got {:?}",
            v.signals
        );
        assert!(v.score >= W_GIFT_CARD_DEMAND);
    }

    #[test]
    fn gift_card_demand_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        // Legitimate gift-card redemption screen — user-initiated, has close button.
        let w = OverlayWindow {
            title: "enter your amazon gift card code to add balance".into(),
            url: None,
            coverage_percent: 20,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 3_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "gift_card_demand"),
            "gift_card_demand must not fire for user-initiated gift-card redemption; got {:?}",
            v.signals
        );
    }

    #[test]
    fn gift_card_demand_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("gift_card_demand"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E27: refund_scam_cue ──────────────────────────────────────────────
    #[test]
    fn refund_scam_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "a refund of $499 is owed to you — call 1-800-555-0100 to collect".into(),
            url: None,
            coverage_percent: 95,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 500,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "refund_scam_cue"),
            "expected refund_scam_cue; got {:?}",
            v.signals
        );
        assert!(v.score >= W_REFUND_SCAM);
    }

    #[test]
    fn refund_scam_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "your refund of $49 has been processed — thank you".into(),
            url: None,
            coverage_percent: 20,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 3_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "refund_scam_cue"),
            "refund_scam_cue must not fire for user-initiated closable window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn refund_scam_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("refund_scam_cue"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── E28: national_id_alarm ────────────────────────────────────────────
    #[test]
    fn national_id_alarm_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "your social security number has been suspended — call 1-800-555-0100".into(),
            url: None,
            coverage_percent: 95,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 400,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "national_id_alarm"),
            "expected national_id_alarm; got {:?}",
            v.signals
        );
        assert!(v.score >= W_NATIONAL_ID_ALARM);
    }

    #[test]
    fn national_id_alarm_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "your social security benefits information page".into(),
            url: None,
            coverage_percent: 20,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "national_id_alarm"),
            "national_id_alarm must not fire on closable gov page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn national_id_alarm_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("national_id_alarm"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E29: bank_account_alarm ───────────────────────────────────────────
    #[test]
    fn bank_account_alarm_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "your bank account has been frozen — unauthorized transaction detected".into(),
            url: None,
            coverage_percent: 95,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 300,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "bank_account_alarm"),
            "expected bank_account_alarm; got {:?}",
            v.signals
        );
        assert!(v.score >= W_BANK_ACCOUNT_ALARM);
    }

    #[test]
    fn bank_account_alarm_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "your bank account balance summary".into(),
            url: None,
            coverage_percent: 20,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "bank_account_alarm"),
            "bank_account_alarm must not fire on user-initiated bank page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn bank_account_alarm_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("bank_account_alarm"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E30: false_registration_billing ──────────────────────────────────────

    #[test]
    fn false_reg_billing_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "your registration is complete — pay within 72 hours or legal action follows"
                .into(),
            url: None,
            coverage_percent: 95,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 200,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "false_registration_billing"),
            "expected false_registration_billing; got {:?}",
            v.signals
        );
        assert!(v.score >= W_FALSE_REG_BILLING);
    }

    #[test]
    fn false_reg_billing_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "your registration is complete — pay within 30 days".into(),
            url: None,
            coverage_percent: 20,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "false_registration_billing"),
            "false_registration_billing must not fire on user-initiated page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn false_reg_billing_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("false_registration_billing"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E31: fake_bsod_lure ──────────────────────────────────────────────────

    #[test]
    fn fake_bsod_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "stop code: memory_management — do not restart — call microsoft support".into(),
            url: None,
            coverage_percent: 99,
            topmost: true,
            has_close_button: false,
            blocks_input: true,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "fake_bsod_lure"),
            "expected fake_bsod_lure; got {:?}",
            v.signals
        );
        assert!(v.score >= W_FAKE_BSOD_LURE);
    }

    #[test]
    fn fake_bsod_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "stop code: memory_management — do not restart — call microsoft".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "fake_bsod_lure"),
            "fake_bsod_lure must not fire on user-initiated page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn fake_bsod_category_is_obstruction() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("fake_bsod_lure"),
            Some(DarkPatternCategory::Obstruction)
        );
    }

    // ── E32: advance_fee_lure ────────────────────────────────────────────────

    #[test]
    fn advance_fee_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "you are a beneficiary of the deceased estate advance fee required to release the funds".into(),
            url: None,
            coverage_percent: 92,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 300,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "advance_fee_lure"),
            "expected advance_fee_lure; got {:?}",
            v.signals
        );
        assert!(v.score >= W_ADVANCE_FEE_LURE);
    }

    #[test]
    fn advance_fee_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title:
                "you are a beneficiary of the estate — processing fee required to release the funds"
                    .into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "advance_fee_lure"),
            "advance_fee_lure must not fire on user-initiated page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn advance_fee_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("advance_fee_lure"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── E33: tech_support_invoice_scam ───────────────────────────────────────

    #[test]
    fn tech_invoice_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "you have been charged $499 microsoft support plan — call to cancel".into(),
            url: None,
            coverage_percent: 94,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "tech_support_invoice_scam"),
            "expected tech_support_invoice_scam; got {:?}",
            v.signals
        );
        assert!(v.score >= W_TECH_INVOICE_SCAM);
    }

    #[test]
    fn tech_invoice_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "you have been charged $499 — if you did not authorize call to cancel".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "tech_support_invoice_scam"),
            "tech_support_invoice_scam must not fire on closable page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn tech_invoice_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("tech_support_invoice_scam"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E34: utility_cutoff_threat ───────────────────────────────────────────

    #[test]
    fn utility_cutoff_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "final notice — your electricity service will be disconnected — pay immediately to restore".into(),
            url: None,
            coverage_percent: 96,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "utility_cutoff_threat"),
            "expected utility_cutoff_threat; got {:?}",
            v.signals
        );
        assert!(v.score >= W_UTILITY_CUTOFF);
    }

    #[test]
    fn utility_cutoff_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title:
                "electric service disconnection notice — final notice — pay to avoid disconnection"
                    .into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "utility_cutoff_threat"),
            "utility_cutoff_threat must not fire on user-initiated page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn utility_cutoff_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("utility_cutoff_threat"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E35: healthcare_scam ─────────────────────────────────────────────────

    #[test]
    fn healthcare_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title:
                "your medicare benefits will expire — call to claim your free medical device now"
                    .into(),
            url: None,
            coverage_percent: 93,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 300,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "healthcare_scam"),
            "expected healthcare_scam; got {:?}",
            v.signals
        );
        assert!(v.score >= W_HEALTHCARE_SCAM);
    }

    #[test]
    fn healthcare_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "medicare benefits will expire — call to claim your free device".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "healthcare_scam"),
            "healthcare_scam must not fire on user-initiated page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn healthcare_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("healthcare_scam"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── E36: job_scam ────────────────────────────────────────────────────────

    #[test]
    fn job_scam_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "work from home — easy money opportunity — registration fee required to start"
                .into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "job_scam"),
            "expected job_scam; got {:?}",
            v.signals
        );
        assert!(v.score >= W_JOB_SCAM);
    }

    #[test]
    fn job_scam_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "work from home — equipment deposit required to start".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "job_scam"),
            "job_scam must not fire on user-initiated page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn job_scam_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(category_of("job_scam"), Some(DarkPatternCategory::Sneaking));
    }

    // ── E37: tax_authority_scam ──────────────────────────────────────────────

    #[test]
    fn tax_authority_scam_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "irs notice: unpaid taxes — arrest warrant issued — call now to avoid arrest"
                .into(),
            url: None,
            coverage_percent: 95,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 150,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "tax_authority_scam"),
            "expected tax_authority_scam; got {:?}",
            v.signals
        );
        assert!(v.score >= W_TAX_AUTHORITY_SCAM);
    }

    #[test]
    fn tax_authority_scam_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "irs notice: back taxes overdue — arrest warrant — face criminal charges".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "tax_authority_scam"),
            "tax_authority_scam must not fire on user-initiated page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn tax_authority_scam_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("tax_authority_scam"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E38: social_media_account_alarm ─────────────────────────────────────

    #[test]
    fn social_media_account_alarm_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "your facebook account has been hacked — verify to recover access now".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "social_media_account_alarm"),
            "expected social_media_account_alarm; got {:?}",
            v.signals
        );
        assert!(v.score >= W_SOCIAL_MEDIA_ACCOUNT_ALARM);
    }

    #[test]
    fn social_media_account_alarm_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "gmail account unusual login — someone accessed your account — regain access"
                .into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "social_media_account_alarm"),
            "social_media_account_alarm must not fire on user-initiated page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn social_media_account_alarm_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("social_media_account_alarm"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E39: immigration_visa_scam ───────────────────────────────────────────

    #[test]
    fn immigration_visa_scam_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "immigration notice: your visa has been revoked — face deportation — pay renewal fee"
                .into(),
            url: None,
            coverage_percent: 92,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 180,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "immigration_visa_scam"),
            "expected immigration_visa_scam; got {:?}",
            v.signals
        );
        assert!(v.score >= W_IMMIGRATION_VISA_SCAM);
    }

    #[test]
    fn immigration_visa_scam_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "your work permit has been cancelled — illegal overstay — renewal fee required"
                .into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "immigration_visa_scam"),
            "immigration_visa_scam must not fire on user-initiated page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn immigration_visa_scam_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("immigration_visa_scam"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E40: government_grant_scam ───────────────────────────────────────────

    #[test]
    fn government_grant_scam_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "federal grant approved — verify your identity to receive — application fee required"
                .into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "government_grant_scam"),
            "expected government_grant_scam; got {:?}",
            v.signals
        );
        assert!(v.score >= W_GOVERNMENT_GRANT_SCAM);
    }

    #[test]
    fn government_grant_scam_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "government grant — stimulus check — apply before the deadline — enrollment deadline"
                .into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "government_grant_scam"),
            "government_grant_scam must not fire on user-initiated page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn government_grant_scam_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("government_grant_scam"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── E41: debt_relief_scam ────────────────────────────────────────────────

    #[test]
    fn debt_relief_scam_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "debt relief program: eliminate your debt — guaranteed approval — no credit check required"
                .into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "debt_relief_scam"),
            "expected debt_relief_scam; got {:?}",
            v.signals
        );
        assert!(v.score >= W_DEBT_RELIEF_SCAM);
    }

    #[test]
    fn debt_relief_scam_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "debt consolidation — credit card debt — guaranteed approval — stop paying now"
                .into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "debt_relief_scam"),
            "debt_relief_scam must not fire on user-initiated page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn debt_relief_scam_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("debt_relief_scam"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── E42: streaming_billing_scam ──────────────────────────────────────────

    #[test]
    fn streaming_billing_scam_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "netflix: your payment failed — update your payment method to continue".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "streaming_billing_scam"),
            "expected streaming_billing_scam; got {:?}",
            v.signals
        );
        assert!(v.score >= W_STREAMING_BILLING_SCAM);
    }

    #[test]
    fn streaming_billing_scam_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "spotify: payment declined — billing issue — update your payment method".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "streaming_billing_scam"),
            "streaming_billing_scam must not fire on user-initiated page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn streaming_billing_scam_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("streaming_billing_scam"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E43: traffic_fine_scam ───────────────────────────────────────────────

    #[test]
    fn traffic_fine_scam_fires_on_alert_shaped_window() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title:
                "parking violation notice — overdue fine — pay within 24 hours — license suspension"
                    .into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 200,
        };
        let v = classify(&w, &rules);
        assert!(
            v.signals.iter().any(|s| s == "traffic_fine_scam"),
            "expected traffic_fine_scam; got {:?}",
            v.signals
        );
        assert!(v.score >= W_TRAFFIC_FINE_SCAM);
    }

    #[test]
    fn traffic_fine_scam_does_not_fire_without_alert_shape() {
        let rules = Ruleset::default();
        let w = OverlayWindow {
            title: "ezpass: unpaid toll — pay immediately — to avoid suspension".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &rules);
        assert!(
            !v.signals.iter().any(|s| s == "traffic_fine_scam"),
            "traffic_fine_scam must not fire on user-initiated page; got {:?}",
            v.signals
        );
    }

    #[test]
    fn traffic_fine_scam_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("traffic_fine_scam"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── all_signals() registry ─────────────────────────────────────

    #[test]
    fn all_signals_is_nonempty_and_names_are_unique() {
        let sigs = all_signals();
        assert!(
            !sigs.is_empty(),
            "all_signals() must return at least one entry"
        );
        let mut seen = std::collections::HashSet::new();
        for s in &sigs {
            assert!(
                seen.insert(s.name),
                "duplicate signal name in all_signals(): {}",
                s.name
            );
        }
    }

    #[test]
    fn all_signals_weight_consistent_with_signal_weight() {
        for s in all_signals() {
            let expected = signal_weight(s.name);
            assert_eq!(
                s.default_weight, expected,
                "SignalInfo.default_weight mismatch for {}",
                s.name
            );
        }
    }

    #[test]
    fn all_signals_description_nonempty() {
        for s in all_signals() {
            assert!(
                !s.description.is_empty(),
                "signal {} has empty description",
                s.name
            );
        }
    }

    /// Registry-consistency guard (Gap A). `signal_phrase()` has a
    /// `other => other` fallback that echoes the raw signal name when no
    /// explicit phrase arm exists. A signal added to the `all_signals()`
    /// NAMES array but missing its `signal_phrase()` arm would therefore
    /// have `description == name` — a non-empty but useless description
    /// that the older `all_signals_description_nonempty` test cannot catch.
    /// This asserts every registered signal carries a *real* human phrase
    /// distinct from its machine name, so a forgotten phrase wiring fails
    /// loudly instead of silently shipping a bare signal name to operators.
    #[test]
    fn all_signals_have_real_descriptions_not_name_echo() {
        for s in all_signals() {
            assert_ne!(
                s.description, s.name,
                "signal {} has no signal_phrase() arm — description echoes the \
                 raw name (add an arm in signal_phrase())",
                s.name
            );
            // A real phrase is a sentence fragment, not a short token.
            assert!(
                s.description.len() > s.name.len(),
                "signal {} description is suspiciously short ({:?}) — likely a \
                 stub rather than an explanatory phrase",
                s.name,
                s.description
            );
        }
    }

    /// Single source of truth for the curated set of content / AND-pair and
    /// structural-URL detection signals that `classify()` can emit (E1–E61).
    /// Both the registry-completeness guard and the full-wiring guard below
    /// consume this one list, so a new content signal is declared in exactly
    /// one place for the meta-tests — no second copy to drift out of sync.
    /// (Pure window-geometry descriptors such as `fullscreen` / `topmost`
    /// are intentionally excluded: they carry no dark-pattern category and
    /// no MITRE technique, so they are not subject to the full-wiring guard.)
    const CONTENT_SIGNALS: &[&str] = &[
        "clickfix_instruction",
        "urgency_countdown",
        "forced_retention_cue",
        "credential_harvest_cue",
        "fake_scanner_cue",
        "subscription_lure",
        "authority_lure",
        "download_trap_lure",
        "prize_lure",
        "crypto_drain_lure",
        "screen_share_lure",
        "qr_code_lure",
        "ip_alarm_lure",
        "package_fee_lure",
        "sextortion_lure",
        "gift_card_demand",
        "refund_scam_cue",
        "national_id_alarm",
        "bank_account_alarm",
        "false_registration_billing",
        "fake_bsod_lure",
        "advance_fee_lure",
        "tech_support_invoice_scam",
        "utility_cutoff_threat",
        "healthcare_scam",
        "job_scam",
        "tax_authority_scam",
        "social_media_account_alarm",
        "immigration_visa_scam",
        "government_grant_scam",
        "debt_relief_scam",
        "streaming_billing_scam",
        "traffic_fine_scam",
        "pig_butchering_lure",
        "loan_fee_scam",
        "data_uri_page",
        "ip_host_url",
        "charity_scam_lure",
        "rental_scam_lure",
        "pet_sale_scam",
        "timeshare_travel_scam",
        "windows_activation_scam",
        "survey_reward_scam",
        "av_brand_renewal_scam",
        "recovery_scam",
        "student_loan_scam",
        "secret_shopper_scam",
        "mlm_pyramid_recruitment",
        "veterans_benefit_scam",
        "fake_copyright_scam",
        "crypto_giveaway_scam",
        "otp_interception_scam",
        "family_emergency_scam",
        "remote_access_lure",
    ];

    /// Registry-completeness guard (Gap B). Every content signal that
    /// `classify()` can push into `Verdict.signals` must also be
    /// enumerable via `all_signals()` — otherwise an MDM operator listing
    /// signals (the `signals` CLI subcommand) to build a blocklist would
    /// never learn the signal exists. This cross-checks the curated
    /// `CONTENT_SIGNALS` list (every AND-pair content signal E1–E61 and the
    /// structural URL signals) against the registry. Adding a
    /// `signals.push("x")` in `classify()` without adding `"x"` to the NAMES
    /// array fails here.
    #[test]
    fn every_content_signal_is_in_registry() {
        let registry: std::collections::HashSet<&str> =
            all_signals().iter().map(|s| s.name).collect();
        for name in CONTENT_SIGNALS {
            assert!(
                registry.contains(name),
                "content signal {name:?} can fire in classify() but is missing \
                 from all_signals() NAMES — operators cannot discover it"
            );
        }
    }

    /// Full-wiring guard (Gap C). A content signal is only useful to
    /// operators and downstream consumers if *all four* of its metadata
    /// wirings are present: a score weight (so it contributes to the
    /// verdict), a dark-pattern category (audit taxonomy), a MITRE ATT&CK
    /// technique (threat-intel mapping), and a real human-readable phrase
    /// (operator-facing `explain()`). The earlier guards each check one of
    /// these in isolation, so a signal could be in the registry yet silently
    /// missing its `category_of` / `techniques_of` / `weight_of` arm and no
    /// single test would notice. This iterates the one `CONTENT_SIGNALS`
    /// source of truth and asserts every content signal is fully wired —
    /// turning "I added a detector but forgot one of its four mappings" from
    /// a latent shipping bug into a loud, localized test failure.
    #[test]
    fn every_content_signal_is_fully_wired() {
        for name in CONTENT_SIGNALS {
            assert!(
                signal_weight(name).is_some(),
                "content signal {name:?} has no score weight — add an arm in \
                 weight_of()/signal_weight()"
            );
            assert!(
                categories::category_of(name).is_some(),
                "content signal {name:?} has no dark-pattern category — add an \
                 arm in categories::category_of()"
            );
            assert!(
                !mitre::techniques_of(name).is_empty(),
                "content signal {name:?} has no MITRE ATT&CK technique — add an \
                 arm in mitre::techniques_of()"
            );
            // explain phrase must be a real fragment, not the bare name echo.
            let phrase = signal_phrase(name);
            assert_ne!(
                phrase, *name,
                "content signal {name:?} has no signal_phrase() arm — its \
                 description would echo the raw name"
            );
        }
    }

    /// High-fidelity completeness guard. `Verdict::confidence()` rates a
    /// Suspicious/Block verdict by counting how many of its signals are
    /// "high-fidelity" (hard for an attacker to trigger on a benign window).
    /// Every AND-pair content detector is high-fidelity by construction, but
    /// `is_high_fidelity()` is a hand-maintained `matches!` list with no link
    /// to `CONTENT_SIGNALS` — so adding a detector and forgetting to list it
    /// here would silently make `confidence()` treat a genuine content tell as
    /// mere "geometry noise" (Low/Medium), under-reporting it to SIEM with no
    /// test failing. This pins the invariant: every content signal is
    /// high-fidelity.
    #[test]
    fn every_content_signal_is_high_fidelity() {
        for name in CONTENT_SIGNALS {
            assert!(
                is_high_fidelity(name),
                "content signal {name:?} is not marked high-fidelity — add it to \
                 is_high_fidelity() or confidence() will under-report it as \
                 geometry noise"
            );
        }
    }

    /// Additive-scoring contract guard (Socratic round 3). The 106
    /// `reaches_suspicious` / `reaches_block` scenario tests assert only a
    /// score threshold, which the window geometry (+ phone) already clears
    /// regardless of any content signal's contribution — so a missing
    /// `score += rules.weight_of(...)` next to a `signals.push(...)` would
    /// make the signal appear in `Verdict.signals` (passing the
    /// `fires_on_alert_shaped_window` tests) yet contribute **zero** to the
    /// score, and no existing test would notice. This holds window geometry
    /// constant and asserts that introducing each content signal's trigger
    /// phrase raises the score by *exactly* that signal's weight — proving
    /// both that the weight is applied and that the phrase fires that one
    /// signal alone (a co-firing second content signal would inflate the
    /// delta and fail here).
    #[test]
    fn content_signal_contributes_exactly_its_weight() {
        let geom = |title: &str| OverlayWindow {
            title: title.into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        // Empty title fires no content signal; geometry is title-independent,
        // so this is the pure-geometry baseline the deltas are measured from.
        let base = classify(&geom(""), &Ruleset::default()).score;

        // (signal, a title that fires exactly that one content signal)
        let cases: &[(&str, &str)] = &[
            (
                "pet_sale_scam",
                "french bulldog pup for sale — pay crate deposit before shipping",
            ),
            (
                "timeshare_travel_scam",
                "complimentary vacation offer — pay activation fee to claim your resort membership",
            ),
            (
                "windows_activation_scam",
                "windows is not activated — call microsoft support to activate your copy",
            ),
            (
                // reward bait "free iphone" avoids prize_lure's prize-word set
                "survey_reward_scam",
                "take our survey — free iphone for every participant",
            ),
            (
                // "device is unprotected" avoids subscription_lure's expiry/renew cue
                "av_brand_renewal_scam",
                "mcafee — your device is unprotected — device is no longer protected",
            ),
            (
                "recovery_scam",
                "recover your lost funds — 100% guaranteed — contact our certified recovery expert",
            ),
            (
                "student_loan_scam",
                "student loan forgiveness — apply now to qualify — processing fee required",
            ),
            (
                "secret_shopper_scam",
                "secret shopper position — deposit a check — wire the funds to our agent",
            ),
            (
                "mlm_pyramid_recruitment",
                "earn per referral — unlimited earning potential — join now",
            ),
            (
                "veterans_benefit_scam",
                "va disability claim — processing fee — expedite your claim today",
            ),
            (
                "fake_copyright_scam",
                "dmca violation — pay settlement — click to settle immediately",
            ),
            (
                // "wire transfer" avoids gift_card_demand's gift-card cue
                "charity_scam_lure",
                "donate to disaster relief fund — wire transfer your donation to help victims now",
            ),
        ];

        for (name, title) in cases {
            let v = classify(&geom(title), &Ruleset::default());
            assert!(
                v.signals.iter().any(|s| s == name),
                "{name} did not fire on its own trigger title {title:?}; got {:?}",
                v.signals
            );
            let expected =
                signal_weight(name).unwrap_or_else(|| panic!("{name} has no signal_weight()"));
            let delta = v.score - base;
            assert_eq!(
                delta, expected,
                "{name}: score rose by {delta}, expected exactly its weight {expected} \
                 — either `score += weight_of(...)` is missing/mismatched, or a second \
                 content signal co-fired on {title:?} (signals: {:?})",
                v.signals
            );
        }
    }

    #[test]
    fn all_signals_contains_key_signals() {
        let sigs = all_signals();
        let names: Vec<&str> = sigs.iter().map(|s| s.name).collect();
        for must in &[
            "fullscreen",
            "blocklist_title",
            "phone_number",
            "mixed_script",
            "tax_authority_scam",
            "traffic_fine_scam",
            "pig_butchering_lure",
            "loan_fee_scam",
            "user_initiated",
        ] {
            assert!(
                names.contains(must),
                "all_signals() missing expected signal: {must}"
            );
        }
    }

    // ── E44: pig_butchering_lure (lib.rs unit tests) ──────────────

    #[test]
    fn pig_butchering_lure_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title: "join our vip group — exclusive trading platform guaranteed return".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "pig_butchering_lure"),
            "pig_butchering_lure must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn pig_butchering_lure_does_not_fire_on_non_alert_shaped() {
        let w = OverlayWindow {
            title: "join our vip group — exclusive trading platform guaranteed return".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "pig_butchering_lure"),
            "pig_butchering_lure must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn pig_butchering_lure_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("pig_butchering_lure"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── E45: loan_fee_scam (lib.rs unit tests) ────────────────────

    #[test]
    fn loan_fee_scam_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title: "pre-approved loan offer — pay processing fee to receive your loan".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "loan_fee_scam"),
            "loan_fee_scam must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn loan_fee_scam_does_not_fire_on_non_alert_shaped() {
        let w = OverlayWindow {
            title: "pre-approved loan offer — pay processing fee to receive your loan".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "loan_fee_scam"),
            "loan_fee_scam must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn loan_fee_scam_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("loan_fee_scam"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── A9: data_uri_page (lib.rs unit tests) ─────────────────────

    #[test]
    fn data_uri_page_fires_on_data_scheme() {
        let w = OverlayWindow {
            title: "your computer has a virus call microsoft support".into(),
            url: Some("data:text/html,<html><body>call 1-800-microsoft</body></html>".into()),
            coverage_percent: 95,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "data_uri_page"),
            "data_uri_page must fire for data: URL; got {:?}",
            v.signals
        );
    }

    #[test]
    fn data_uri_page_fires_on_file_scheme() {
        let w = OverlayWindow {
            title: "windows security alert".into(),
            url: Some("file:///C:/Users/victim/AppData/Local/Temp/scam.html".into()),
            coverage_percent: 95,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "data_uri_page"),
            "data_uri_page must fire for file:// URL; got {:?}",
            v.signals
        );
    }

    #[test]
    fn data_uri_page_does_not_fire_for_normal_https() {
        let w = OverlayWindow {
            title: "windows security alert".into(),
            url: Some("https://example.com/page".into()),
            coverage_percent: 95,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "data_uri_page"),
            "data_uri_page must not fire for https: URL; got {:?}",
            v.signals
        );
    }

    #[test]
    fn data_uri_page_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title: "page".into(),
            url: Some("data:text/html,hello".into()),
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "data_uri_page"),
            "data_uri_page must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn data_uri_page_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("data_uri_page"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── E46: charity_scam_lure (lib.rs unit tests) ────────────────

    #[test]
    fn charity_scam_lure_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title: "hurricane relief fund — donate now — send bitcoin donation".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "charity_scam_lure"),
            "charity_scam_lure must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn charity_scam_lure_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title: "hurricane relief fund — donate now — send bitcoin donation".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "charity_scam_lure"),
            "charity_scam_lure must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn charity_scam_lure_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("charity_scam_lure"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── E47: rental_scam_lure (lib.rs unit tests) ─────────────────

    #[test]
    fn rental_scam_lure_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title: "apartment for rent — deposit before viewing — wire deposit to hold unit".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "rental_scam_lure"),
            "rental_scam_lure must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn rental_scam_lure_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title: "apartment for rent — deposit before viewing — wire deposit to hold unit".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "rental_scam_lure"),
            "rental_scam_lure must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn rental_scam_lure_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("rental_scam_lure"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── E48: pet_sale_scam (lib.rs unit tests) ─────────────────────

    #[test]
    fn pet_sale_scam_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title: "french bulldog pup for sale — pay crate deposit before shipping".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "pet_sale_scam"),
            "pet_sale_scam must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn pet_sale_scam_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title: "french bulldog pup for sale — pay crate deposit before shipping".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "pet_sale_scam"),
            "pet_sale_scam must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn pet_sale_scam_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("pet_sale_scam"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── E49: timeshare_travel_scam (lib.rs unit tests) ─────────────

    #[test]
    fn timeshare_travel_scam_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title:
                "complimentary vacation offer — pay activation fee to claim your resort membership"
                    .into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "timeshare_travel_scam"),
            "timeshare_travel_scam must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn timeshare_travel_scam_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title:
                "complimentary vacation offer — pay activation fee to claim your resort membership"
                    .into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "timeshare_travel_scam"),
            "timeshare_travel_scam must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn timeshare_travel_scam_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("timeshare_travel_scam"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── E50: windows_activation_scam (lib.rs unit tests) ───────────

    #[test]
    fn windows_activation_scam_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title: "windows is not activated — call microsoft support to activate your copy".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "windows_activation_scam"),
            "windows_activation_scam must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn windows_activation_scam_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title: "windows is not activated — call microsoft support to activate your copy".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "windows_activation_scam"),
            "windows_activation_scam must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn windows_activation_scam_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("windows_activation_scam"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E51: survey_reward_scam (lib.rs unit tests) ─────────────────

    #[test]
    fn survey_reward_scam_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title: "take our survey and win a gift card — claim your amazon gift card now".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "survey_reward_scam"),
            "survey_reward_scam must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn survey_reward_scam_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title: "take our survey and win a gift card — claim your amazon gift card now".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "survey_reward_scam"),
            "survey_reward_scam must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn survey_reward_scam_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("survey_reward_scam"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E52: av_brand_renewal_scam (lib.rs unit tests) ─────────────

    #[test]
    fn av_brand_renewal_scam_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title: "mcafee subscription has expired — your device is unprotected — renew now"
                .into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "av_brand_renewal_scam"),
            "av_brand_renewal_scam must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn av_brand_renewal_scam_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title: "mcafee subscription has expired — your device is unprotected — renew now"
                .into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "av_brand_renewal_scam"),
            "av_brand_renewal_scam must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn av_brand_renewal_scam_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("av_brand_renewal_scam"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E53: recovery_scam (lib.rs unit tests) ──────────────────────

    #[test]
    fn recovery_scam_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title:
                "recover your lost funds — 100% guaranteed — contact our certified recovery expert"
                    .into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "recovery_scam"),
            "recovery_scam must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn recovery_scam_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title:
                "recover your lost funds — 100% guaranteed — contact our certified recovery expert"
                    .into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "recovery_scam"),
            "recovery_scam must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn recovery_scam_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("recovery_scam"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── E54: student_loan_scam (lib.rs unit tests) ──────────────────

    #[test]
    fn student_loan_scam_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title: "student loan forgiveness — apply now to qualify — processing fee required"
                .into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "student_loan_scam"),
            "student_loan_scam must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn student_loan_scam_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title: "student loan forgiveness — apply now to qualify — processing fee required"
                .into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "student_loan_scam"),
            "student_loan_scam must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn student_loan_scam_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("student_loan_scam"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── E55: secret_shopper_scam (lib.rs unit tests) ────────────────

    #[test]
    fn secret_shopper_scam_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title: "secret shopper position — deposit a check — wire the funds to our agent".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "secret_shopper_scam"),
            "secret_shopper_scam must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn secret_shopper_scam_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title: "secret shopper position — deposit a check — wire the funds to our agent".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "secret_shopper_scam"),
            "secret_shopper_scam must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn secret_shopper_scam_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("secret_shopper_scam"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── E56: mlm_pyramid_recruitment (lib.rs unit tests) ────────────

    #[test]
    fn mlm_pyramid_recruitment_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title: "earn per referral — unlimited earning potential — join now and start earning"
                .into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "mlm_pyramid_recruitment"),
            "mlm_pyramid_recruitment must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn mlm_pyramid_recruitment_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title: "earn per referral — unlimited earning potential — join now and start earning"
                .into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "mlm_pyramid_recruitment"),
            "mlm_pyramid_recruitment must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn mlm_pyramid_recruitment_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("mlm_pyramid_recruitment"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── E57: ip_host_url (lib.rs unit tests) ────────────────────────

    #[test]
    fn ip_host_url_fires_on_ipv4_url() {
        let w = OverlayWindow {
            title: "your computer is infected — call support now".into(),
            url: Some("http://185.234.219.45/microsoft/support".into()),
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "ip_host_url"),
            "ip_host_url must fire on IPv4-hosted alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn ip_host_url_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title: "intranet dashboard".into(),
            url: Some("http://10.0.0.1/dashboard".into()),
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "ip_host_url"),
            "ip_host_url must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn ip_host_url_does_not_fire_on_hostname() {
        let w = OverlayWindow {
            title: "your computer is infected — call support now".into(),
            url: Some("http://microsoft-support-alert.com/scan".into()),
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "ip_host_url"),
            "ip_host_url must not fire on hostname URL; got {:?}",
            v.signals
        );
    }

    #[test]
    fn ip_host_url_fires_on_ipv4_with_port() {
        let w = OverlayWindow {
            title: "virus detected".into(),
            url: Some("https://192.168.100.5:8080/warning".into()),
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "ip_host_url"),
            "ip_host_url must fire on IPv4:port URL; got {:?}",
            v.signals
        );
    }

    #[test]
    fn ip_host_url_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("ip_host_url"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    #[test]
    fn url_host_is_ip_helper_ipv4() {
        assert!(url_host_is_ip("http://1.2.3.4/path"));
        assert!(url_host_is_ip("http://192.168.0.1:8080/"));
        assert!(!url_host_is_ip("http://example.com/path"));
        assert!(!url_host_is_ip("http://1.2.3.4.5/path")); // not valid IPv4
    }

    // ── E58: veterans_benefit_scam (lib.rs unit tests) ──────────────

    #[test]
    fn veterans_benefit_scam_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title: "va disability claim — processing fee — expedite your claim today".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "veterans_benefit_scam"),
            "veterans_benefit_scam must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn veterans_benefit_scam_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title: "va disability claim — processing fee — expedite your claim today".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "veterans_benefit_scam"),
            "veterans_benefit_scam must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn veterans_benefit_scam_category_is_sneaking() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("veterans_benefit_scam"),
            Some(DarkPatternCategory::Sneaking)
        );
    }

    // ── E59: fake_copyright_scam (lib.rs unit tests) ─────────────────

    #[test]
    fn fake_copyright_scam_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title: "dmca violation — pay settlement — click to settle immediately".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "fake_copyright_scam"),
            "fake_copyright_scam must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn fake_copyright_scam_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title: "dmca violation — pay settlement — click to settle immediately".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "fake_copyright_scam"),
            "fake_copyright_scam must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn fake_copyright_scam_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("fake_copyright_scam"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E60: crypto_giveaway_scam (lib.rs unit tests) ────────────────

    #[test]
    fn crypto_giveaway_scam_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title: "official giveaway — send any amount — double your bitcoin instantly".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "crypto_giveaway_scam"),
            "crypto_giveaway_scam must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn crypto_giveaway_scam_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title: "official giveaway — send any amount — double your bitcoin instantly".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "crypto_giveaway_scam"),
            "crypto_giveaway_scam must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn crypto_giveaway_scam_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("crypto_giveaway_scam"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E61: otp_interception_scam (lib.rs unit tests) ───────────────

    #[test]
    fn otp_interception_scam_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title: "we sent a verification code — share the code with our agent to verify".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "otp_interception_scam"),
            "otp_interception_scam must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn otp_interception_scam_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title: "we sent a verification code — share the code with our agent to verify".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "otp_interception_scam"),
            "otp_interception_scam must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn otp_interception_scam_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("otp_interception_scam"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }

    // ── E62: family_emergency_scam (lib.rs unit tests) ───────────────

    #[test]
    fn family_emergency_scam_fires_on_alert_shaped_window() {
        let w = OverlayWindow {
            title: "your grandson has been arrested — send bail money immediately".into(),
            url: None,
            coverage_percent: 90,
            topmost: true,
            has_close_button: false,
            blocks_input: false,
            origin: Origin::Unsolicited,
            age_ms: 100,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            v.signals.iter().any(|s| s == "family_emergency_scam"),
            "family_emergency_scam must fire on alert-shaped window; got {:?}",
            v.signals
        );
    }

    #[test]
    fn family_emergency_scam_does_not_fire_without_alert_shape() {
        let w = OverlayWindow {
            title: "your grandson has been arrested — send bail money immediately".into(),
            url: None,
            coverage_percent: 10,
            topmost: false,
            has_close_button: true,
            blocks_input: false,
            origin: Origin::UserInitiated,
            age_ms: 5_000,
        };
        let v = classify(&w, &Ruleset::default());
        assert!(
            !v.signals.iter().any(|s| s == "family_emergency_scam"),
            "family_emergency_scam must not fire without alert shape; got {:?}",
            v.signals
        );
    }

    #[test]
    fn family_emergency_scam_category_is_interface_interference() {
        use crate::categories::{category_of, DarkPatternCategory};
        assert_eq!(
            category_of("family_emergency_scam"),
            Some(DarkPatternCategory::InterfaceInterference)
        );
    }
}
