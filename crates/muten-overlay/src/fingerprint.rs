//! Campaign fingerprinting — an eighth analytical lens.
//!
//! Every scam operator reuses the same overlay template with minor text or
//! domain variations, producing structurally identical windows across thousands
//! of victims.  This module provides two lightweight, stable identity tokens:
//!
//! - [`signal_fingerprint`]: a canonical string built from the **sorted,
//!   deduplicated** set of signal names that fired.  Two verdicts produced by
//!   the same attack template produce the *same* fingerprint regardless of the
//!   order signals were evaluated — a SOC analyst or a SIEM rule can use this
//!   to deduplicate reports and spot recurring attacks across endpoints.
//!
//! - [`campaign_bucket`]: a coarser `"category:stage:magnitude"` triple that
//!   groups structurally *similar* variants together even when the exact
//!   signal sets differ (e.g. `"tech_support_scam:extract:small"`).  Useful
//!   for roll-up dashboards and management reporting.
//!
//! ## Design invariants
//!
//! Both functions are **pure** (no I/O, deterministic), **zero-dependency**
//! (no new crates), and `forbid(unsafe_code)`-clean.  The fingerprint format
//! uses `'|'` as a separator because `'|'` never appears in a valid
//! snake_case signal name.  The bucket format is always `"A:B:C"` —
//! parseable with a simple `split(':')` call.

#![forbid(unsafe_code)]

/// Returns a **stable, human-readable canonical fingerprint** of a signal set.
///
/// The fingerprint is the sorted, deduplicated signal names joined by `'|'`.
/// Two calls with the same logical set of signals produce the same string
/// regardless of the order they appear in the input slice.  An empty signal
/// set yields an empty string.
///
/// # Stability
///
/// Fingerprints are stable as long as signal names are not renamed in this
/// crate.  Adding a new signal to the fired set extends the fingerprint;
/// removing a signal shortens it.  The separator `'|'` never appears in any
/// built-in signal name (all are `snake_case` ASCII).
///
/// # Example
///
/// ```
/// use muten_overlay::fingerprint::signal_fingerprint;
/// // Order-independent: both calls produce the same fingerprint.
/// let a = signal_fingerprint(&["urgency_countdown", "fake_bsod_lure", "phone_number"]);
/// let b = signal_fingerprint(&["phone_number", "fake_bsod_lure", "urgency_countdown"]);
/// assert_eq!(a, b);
/// assert_eq!(a, "fake_bsod_lure|phone_number|urgency_countdown");
/// ```
#[must_use]
pub fn signal_fingerprint<S: AsRef<str>>(signals: &[S]) -> String {
    let mut names: Vec<&str> = signals.iter().map(|s| s.as_ref()).collect();
    names.sort_unstable();
    names.dedup();
    names.join("|")
}

/// Returns a coarse **campaign bucket** string `"category:stage:magnitude"`
/// that groups structurally similar campaign variants together, even when
/// their exact signal sets differ.
///
/// # Arguments
///
/// * `primary_category` — the primary dark-pattern category (e.g.
///   `"tech_support_scam"`), or `None` when no category fired.
/// * `highest_stage` — the most advanced kill-chain stage present (e.g.
///   `"extract"`), or `None`.
/// * `highest_magnitude` — the worst-case expected-loss band (e.g.
///   `"small"`), or `None`.
///
/// Each absent component is represented by the sentinel `"unknown"`, so the
/// format is always exactly `"A:B:C"` — trivially parseable.
///
/// # Use case
///
/// Where [`signal_fingerprint`] gives an *exact* template match (dedup),
/// `campaign_bucket` gives a *family* match (roll-up).  The two are
/// complementary: pivot by bucket first, then inspect individual fingerprints
/// within the bucket to cluster distinct variants.
///
/// # Example
///
/// ```
/// use muten_overlay::fingerprint::campaign_bucket;
/// assert_eq!(
///     campaign_bucket(Some("tech_support_scam"), Some("extract"), Some("small")),
///     "tech_support_scam:extract:small"
/// );
/// assert_eq!(
///     campaign_bucket(None, None, None),
///     "unknown:unknown:unknown"
/// );
/// ```
#[must_use]
pub fn campaign_bucket(
    primary_category: Option<&str>,
    highest_stage: Option<&str>,
    highest_magnitude: Option<&str>,
) -> String {
    format!(
        "{}:{}:{}",
        primary_category.unwrap_or("unknown"),
        highest_stage.unwrap_or("unknown"),
        highest_magnitude.unwrap_or("unknown"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── signal_fingerprint ────────────────────────────────────────────────

    #[test]
    fn empty_signals_yield_empty_fingerprint() {
        assert_eq!(signal_fingerprint::<&str>(&[]), "");
    }

    #[test]
    fn single_signal_fingerprint_is_the_signal_itself() {
        assert_eq!(signal_fingerprint(&["fake_bsod_lure"]), "fake_bsod_lure");
    }

    #[test]
    fn fingerprint_is_sorted_alphabetically() {
        let fp = signal_fingerprint(&["urgency_countdown", "fake_bsod_lure", "phone_number"]);
        assert_eq!(fp, "fake_bsod_lure|phone_number|urgency_countdown");
    }

    #[test]
    fn fingerprint_is_order_independent() {
        let a = signal_fingerprint(&["urgency_countdown", "fake_bsod_lure", "phone_number"]);
        let b = signal_fingerprint(&["phone_number", "fake_bsod_lure", "urgency_countdown"]);
        let c = signal_fingerprint(&["fake_bsod_lure", "urgency_countdown", "phone_number"]);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn duplicates_are_removed_from_fingerprint() {
        let fp = signal_fingerprint(&[
            "gift_card_demand",
            "gift_card_demand",
            "fake_bsod_lure",
            "fake_bsod_lure",
        ]);
        assert_eq!(fp, "fake_bsod_lure|gift_card_demand");
    }

    #[test]
    fn all_signal_names_are_pipe_free() {
        // The '|' separator is safe only if no signal name contains it.
        let names = [
            "fake_bsod_lure",
            "pig_butchering_lure",
            "windows_defender_alert_lure",
            "tech_support_chat_lure",
            "urgency_countdown",
            "alarm_density",
            "gift_card_demand",
            "crypto_drain_lure",
            "otp_interception_scam",
            "mlm_pyramid_recruitment",
        ];
        for name in names {
            assert!(!name.contains('|'), "signal name contains '|': {name}");
        }
    }

    #[test]
    fn fingerprint_of_full_tech_support_bundle() {
        // Realistic tech-support scam signal set — order scrambled.
        let signals = [
            "urgency_countdown",
            "fake_bsod_lure",
            "phone_number",
            "fullscreen",
            "no_close_button",
        ];
        let fp = signal_fingerprint(&signals);
        // Must be sorted and pipe-separated.
        assert_eq!(
            fp,
            "fake_bsod_lure|fullscreen|no_close_button|phone_number|urgency_countdown"
        );
        // Applying again to an already-sorted set is idempotent.
        let fp2 = signal_fingerprint(&fp.split('|').collect::<Vec<_>>());
        assert_eq!(fp, fp2);
    }

    // ── campaign_bucket ───────────────────────────────────────────────────

    #[test]
    fn all_none_yields_unknown_triple() {
        assert_eq!(campaign_bucket(None, None, None), "unknown:unknown:unknown");
    }

    #[test]
    fn campaign_bucket_formats_all_components() {
        assert_eq!(
            campaign_bucket(Some("tech_support_scam"), Some("extract"), Some("small")),
            "tech_support_scam:extract:small"
        );
    }

    #[test]
    fn campaign_bucket_partial_none_uses_unknown_sentinel() {
        assert_eq!(
            campaign_bucket(Some("advance_fee_fraud"), None, Some("medium")),
            "advance_fee_fraud:unknown:medium"
        );
        assert_eq!(
            campaign_bucket(None, Some("lure"), None),
            "unknown:lure:unknown"
        );
    }

    #[test]
    fn campaign_bucket_always_has_exactly_two_colons() {
        for (cat, stage, mag) in [
            (None, None, None),
            (Some("a"), Some("b"), Some("c")),
            (Some("tech_support_scam"), Some("extract"), Some("small")),
            (None, Some("pressure"), None),
        ] {
            let bucket = campaign_bucket(cat, stage, mag);
            assert_eq!(
                bucket.chars().filter(|&ch| ch == ':').count(),
                2,
                "bucket does not have exactly 2 colons: {bucket}"
            );
        }
    }

    #[test]
    fn campaign_bucket_components_are_parseable_by_split() {
        let bucket = campaign_bucket(
            Some("pig_butchering"),
            Some("extract"),
            Some("catastrophic"),
        );
        let parts: Vec<&str> = bucket.splitn(3, ':').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "pig_butchering");
        assert_eq!(parts[1], "extract");
        assert_eq!(parts[2], "catastrophic");
    }
}
