//! Response-priority triage — a ninth, *synthesis* lens.
//!
//! The first eight lenses are each **descriptive**: they answer one question
//! about an overlay (which dark-pattern mechanic, which ATT&CK technique, why
//! the human complies, what the victim loses, how far the attacker has
//! progressed, who is targeted, how large the loss, which campaign template).
//! A responder triaging a queue of verdicts has eight columns to sort by and
//! no single answer to the only operational question that matters when the
//! queue is long: **which one do I handle first?**
//!
//! This module synthesises the prior lenses into a single ordinal
//! [`ResponsePriority`] (`Low` → `Critical`) plus the transparent integer
//! [`priority_score`] it is banded from.  The scoring deliberately mirrors the
//! main classifier's design philosophy (CLAUDE.md I6, explainable): every
//! contribution is a **named constant**, the total is an honest sum, and the
//! band thresholds are documented — no opaque model, no hidden weighting.
//!
//! ## What feeds the score
//!
//! - **Decision severity** — a confirmed `Block` outranks a `Suspicious`
//!   flag; an `Allow` contributes nothing.
//! - **Kill-chain stage** ([`ScamStage`]) — an active `Extract` demand is the
//!   most time-critical; earlier stages leave room for education.
//! - **Recoverability** ([`Recoverability`]) — `Irreversible` loss (gift card
//!   / crypto) cannot be clawed back, so prevention is urgent.
//! - **Loss magnitude** ([`LossMagnitude`]) — a `Catastrophic` per-victim loss
//!   warrants escalation a `Micro` fee does not.
//! - **Targeting** — a scam aimed at a specific vulnerable population is more
//!   urgent than a broadcast lure.
//!
//! All functions are **pure**, deterministic, and zero-dependency.

#![forbid(unsafe_code)]

use serde::Serialize;

use crate::extraction::Recoverability;
use crate::lifecycle::ScamStage;
use crate::magnitude::LossMagnitude;
use crate::Decision;

/// Operational response priority for a verdict — the ordinal a responder
/// sorts an alert queue by.  Variants are declared lowest-to-highest urgency,
/// so deriving [`Ord`] makes `Critical` the maximum and `Low` the minimum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponsePriority {
    /// Routine. Geometry-only or weak suspicious signals; no determinate
    /// extraction, loss, or targeting. Review in normal course (think "P4").
    Low,
    /// Notable. A content scam family fired but the worst-case loss is bounded
    /// and recoverable, or only a single urgency axis is present ("P3").
    Medium,
    /// Urgent. A confirmed block carrying an active demand, an irreversible
    /// cash-out channel, or a large expected loss — handle ahead of the
    /// routine queue ("P2").
    High,
    /// Drop-everything. An active extraction combined with an irreversible or
    /// catastrophic outcome: the money is about to leave and cannot be
    /// recovered. Immediate intervention / escalation ("P1").
    Critical,
}

impl ResponsePriority {
    /// Stable lowercase token (`"low"`, `"medium"`, `"high"`, `"critical"`),
    /// matching the `serde` rename. Suitable for JSON, logs, and tests.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// A short "P1".."P4" label in the conventional incident-severity
    /// convention (P1 = most urgent), for responders who pivot on that scale.
    #[must_use]
    pub fn p_label(self) -> &'static str {
        match self {
            Self::Critical => "P1",
            Self::High => "P2",
            Self::Medium => "P3",
            Self::Low => "P4",
        }
    }
}

// ── Named score contributions (explainable, like the classifier's W_*) ──────

// Decision severity.
const P_BLOCK: u32 = 40;
const P_SUSPICIOUS: u32 = 15;

// Kill-chain stage (how far the attacker has progressed).
const P_EXTRACT: u32 = 30;
const P_PRESSURE: u32 = 20;
const P_TRUSTBUILD: u32 = 10;
const P_LURE: u32 = 5;

// Recoverability (can the loss be undone?).
const P_IRREVERSIBLE: u32 = 30;
const P_TIMELIMITED: u32 = 20;
const P_DISPUTABLE: u32 = 10;
const P_MITIGABLE: u32 = 5;

// Expected loss magnitude (how much).
const P_CATASTROPHIC: u32 = 30;
const P_LARGE: u32 = 20;
const P_MEDIUM: u32 = 10;
const P_SMALL: u32 = 5;
const P_MICRO: u32 = 2;

// Targeting (a named vulnerable population vs. broadcast).
const P_TARGETED: u32 = 10;

// ── Band thresholds (score → ResponsePriority) ──────────────────────────────

/// At or above this score → [`ResponsePriority::Critical`].
pub const CRITICAL_THRESHOLD: u32 = 90;
/// At or above this score (and below `CRITICAL_THRESHOLD`) → `High`.
pub const HIGH_THRESHOLD: u32 = 55;
/// At or above this score (and below `HIGH_THRESHOLD`) → `Medium`.
pub const MEDIUM_THRESHOLD: u32 = 30;

/// Computes the transparent integer **urgency score** synthesised from the
/// prior lenses. Each argument contributes a named constant; the result is an
/// honest sum (never saturates in practice — the theoretical maximum is
/// `40 + 30 + 30 + 30 + 10 = 140`).
///
/// Pass the verdict's own [`Decision`], [`Verdict::highest_stage`],
/// [`Verdict::worst_recoverability`], [`Verdict::highest_magnitude`], and
/// [`Verdict::is_targeted_attack`].
///
/// [`Verdict::highest_stage`]: crate::Verdict::highest_stage
/// [`Verdict::worst_recoverability`]: crate::Verdict::worst_recoverability
/// [`Verdict::highest_magnitude`]: crate::Verdict::highest_magnitude
/// [`Verdict::is_targeted_attack`]: crate::Verdict::is_targeted_attack
#[must_use]
pub fn priority_score(
    decision: Decision,
    highest_stage: Option<ScamStage>,
    worst_recoverability: Option<Recoverability>,
    highest_magnitude: Option<LossMagnitude>,
    is_targeted: bool,
) -> u32 {
    let mut s = 0;

    s += match decision {
        Decision::Block => P_BLOCK,
        Decision::Suspicious => P_SUSPICIOUS,
        Decision::Allow => 0,
    };

    if let Some(stage) = highest_stage {
        s += match stage {
            ScamStage::Extract => P_EXTRACT,
            ScamStage::Pressure => P_PRESSURE,
            ScamStage::TrustBuild => P_TRUSTBUILD,
            ScamStage::Lure => P_LURE,
        };
    }

    if let Some(rec) = worst_recoverability {
        s += match rec {
            Recoverability::Irreversible => P_IRREVERSIBLE,
            Recoverability::TimeLimited => P_TIMELIMITED,
            Recoverability::Disputable => P_DISPUTABLE,
            Recoverability::Mitigable => P_MITIGABLE,
        };
    }

    if let Some(mag) = highest_magnitude {
        s += match mag {
            LossMagnitude::Catastrophic => P_CATASTROPHIC,
            LossMagnitude::Large => P_LARGE,
            LossMagnitude::Medium => P_MEDIUM,
            LossMagnitude::Small => P_SMALL,
            LossMagnitude::Micro => P_MICRO,
        };
    }

    if is_targeted {
        s += P_TARGETED;
    }

    s
}

/// Bands a [`priority_score`] into an ordinal [`ResponsePriority`].
///
/// Thresholds: `>= CRITICAL_THRESHOLD` → `Critical`, `>= HIGH_THRESHOLD` →
/// `High`, `>= MEDIUM_THRESHOLD` → `Medium`, else `Low`.
#[must_use]
pub fn priority_of_score(score: u32) -> ResponsePriority {
    if score >= CRITICAL_THRESHOLD {
        ResponsePriority::Critical
    } else if score >= HIGH_THRESHOLD {
        ResponsePriority::High
    } else if score >= MEDIUM_THRESHOLD {
        ResponsePriority::Medium
    } else {
        ResponsePriority::Low
    }
}

/// Convenience: compute [`priority_score`] and band it in one call.
#[must_use]
pub fn response_priority(
    decision: Decision,
    highest_stage: Option<ScamStage>,
    worst_recoverability: Option<Recoverability>,
    highest_magnitude: Option<LossMagnitude>,
    is_targeted: bool,
) -> ResponsePriority {
    priority_of_score(priority_score(
        decision,
        highest_stage,
        worst_recoverability,
        highest_magnitude,
        is_targeted,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ordering / labels ─────────────────────────────────────────────────

    #[test]
    fn priority_is_ordered_low_to_critical() {
        assert!(ResponsePriority::Low < ResponsePriority::Medium);
        assert!(ResponsePriority::Medium < ResponsePriority::High);
        assert!(ResponsePriority::High < ResponsePriority::Critical);
    }

    #[test]
    fn as_str_and_p_label_are_stable() {
        assert_eq!(ResponsePriority::Low.as_str(), "low");
        assert_eq!(ResponsePriority::Critical.as_str(), "critical");
        assert_eq!(ResponsePriority::Critical.p_label(), "P1");
        assert_eq!(ResponsePriority::High.p_label(), "P2");
        assert_eq!(ResponsePriority::Medium.p_label(), "P3");
        assert_eq!(ResponsePriority::Low.p_label(), "P4");
    }

    // ── score floor / ceiling ─────────────────────────────────────────────

    #[test]
    fn allow_with_nothing_scores_zero_and_is_low() {
        let s = priority_score(Decision::Allow, None, None, None, false);
        assert_eq!(s, 0);
        assert_eq!(priority_of_score(s), ResponsePriority::Low);
    }

    #[test]
    fn theoretical_maximum_is_140_and_critical() {
        let s = priority_score(
            Decision::Block,
            Some(ScamStage::Extract),
            Some(Recoverability::Irreversible),
            Some(LossMagnitude::Catastrophic),
            true,
        );
        assert_eq!(s, 140);
        assert_eq!(priority_of_score(s), ResponsePriority::Critical);
    }

    // ── representative real verdicts ──────────────────────────────────────

    #[test]
    fn gift_card_tech_support_block_is_critical() {
        // Block + Extract demand + Irreversible (gift card) + Small loss.
        // 40 + 30 + 30 + 5 = 105 → Critical (irreversible cash-out in progress).
        let s = priority_score(
            Decision::Block,
            Some(ScamStage::Extract),
            Some(Recoverability::Irreversible),
            Some(LossMagnitude::Small),
            false,
        );
        assert_eq!(s, 105);
        assert_eq!(priority_of_score(s), ResponsePriority::Critical);
    }

    #[test]
    fn pig_butchering_block_is_critical() {
        // 40 + 30 + 30 (irreversible crypto) + 30 (catastrophic) = 130.
        let s = priority_score(
            Decision::Block,
            Some(ScamStage::Extract),
            Some(Recoverability::Irreversible),
            Some(LossMagnitude::Catastrophic),
            true,
        );
        assert!(s >= CRITICAL_THRESHOLD);
        assert_eq!(
            response_priority(
                Decision::Block,
                Some(ScamStage::Extract),
                Some(Recoverability::Irreversible),
                Some(LossMagnitude::Catastrophic),
                true,
            ),
            ResponsePriority::Critical
        );
    }

    #[test]
    fn geometry_only_block_is_medium() {
        // A fullscreen modal input-trap with no content lens firing:
        // 40 only → Medium (worth attention, not a drop-everything).
        let s = priority_score(Decision::Block, None, None, None, false);
        assert_eq!(s, 40);
        assert_eq!(priority_of_score(s), ResponsePriority::Medium);
    }

    #[test]
    fn weak_suspicious_geometry_is_low() {
        // Suspicious with no content lens: 15 → Low.
        let s = priority_score(Decision::Suspicious, None, None, None, false);
        assert_eq!(s, 15);
        assert_eq!(priority_of_score(s), ResponsePriority::Low);
    }

    #[test]
    fn subscription_lure_suspicious_is_medium() {
        // Suspicious + Lure stage + Disputable (recoverable card charge) +
        // Small loss: 15 + 5 + 10 + 5 = 35 → Medium. A content scam with a
        // determinate (if recoverable) loss is worth a look, which is the
        // intended behavior.
        let s = priority_score(
            Decision::Suspicious,
            Some(ScamStage::Lure),
            Some(Recoverability::Disputable),
            Some(LossMagnitude::Small),
            false,
        );
        assert_eq!(s, 35);
        assert_eq!(priority_of_score(s), ResponsePriority::Medium);
    }

    #[test]
    fn lure_only_suspicious_is_low() {
        // Suspicious + Lure stage, no loss/recoverability: 15 + 5 = 20 → Low.
        let s = priority_score(
            Decision::Suspicious,
            Some(ScamStage::Lure),
            None,
            None,
            false,
        );
        assert_eq!(s, 20);
        assert_eq!(priority_of_score(s), ResponsePriority::Low);
    }

    #[test]
    fn wire_transfer_advance_fee_block_is_critical() {
        // Block + Extract + TimeLimited (wire) + Medium loss, broadcast:
        // 40 + 30 + 20 + 10 = 100 → Critical (race the recall window).
        let s = priority_score(
            Decision::Block,
            Some(ScamStage::Extract),
            Some(Recoverability::TimeLimited),
            Some(LossMagnitude::Medium),
            false,
        );
        assert_eq!(s, 100);
        assert_eq!(priority_of_score(s), ResponsePriority::Critical);
    }

    #[test]
    fn moderate_block_with_recoverable_loss_is_high() {
        // Block + Pressure + Disputable + Large loss: 40 + 20 + 10 + 0... wait,
        // 40 + 20 + 10 + 20 (Large) = 90 → Critical. Drop one axis to land High:
        // Block + Pressure + Disputable + Medium = 40 + 20 + 10 + 10 = 80 → High.
        let s = priority_score(
            Decision::Block,
            Some(ScamStage::Pressure),
            Some(Recoverability::Disputable),
            Some(LossMagnitude::Medium),
            false,
        );
        assert_eq!(s, 80);
        assert_eq!(priority_of_score(s), ResponsePriority::High);
    }

    #[test]
    fn targeted_adds_ten() {
        let base = priority_score(Decision::Block, Some(ScamStage::Lure), None, None, false);
        let targeted = priority_score(Decision::Block, Some(ScamStage::Lure), None, None, true);
        assert_eq!(targeted, base + P_TARGETED);
    }

    // ── monotonicity: more severe inputs never lower the score ────────────

    #[test]
    fn score_is_monotone_in_decision_severity() {
        let allow = priority_score(Decision::Allow, Some(ScamStage::Extract), None, None, false);
        let susp = priority_score(
            Decision::Suspicious,
            Some(ScamStage::Extract),
            None,
            None,
            false,
        );
        let block = priority_score(Decision::Block, Some(ScamStage::Extract), None, None, false);
        assert!(allow < susp);
        assert!(susp < block);
    }

    #[test]
    fn score_is_monotone_in_stage() {
        let f = |st| priority_score(Decision::Block, Some(st), None, None, false);
        assert!(f(ScamStage::Lure) < f(ScamStage::TrustBuild));
        assert!(f(ScamStage::TrustBuild) < f(ScamStage::Pressure));
        assert!(f(ScamStage::Pressure) < f(ScamStage::Extract));
    }

    #[test]
    fn score_is_monotone_in_magnitude() {
        let f = |m| priority_score(Decision::Block, None, None, Some(m), false);
        assert!(f(LossMagnitude::Micro) < f(LossMagnitude::Small));
        assert!(f(LossMagnitude::Small) < f(LossMagnitude::Medium));
        assert!(f(LossMagnitude::Medium) < f(LossMagnitude::Large));
        assert!(f(LossMagnitude::Large) < f(LossMagnitude::Catastrophic));
    }

    #[test]
    fn score_is_monotone_in_recoverability_worsening() {
        // Mitigable (least bad) → Irreversible (worst) increases the score.
        let f = |r| priority_score(Decision::Block, None, Some(r), None, false);
        assert!(f(Recoverability::Mitigable) < f(Recoverability::Disputable));
        assert!(f(Recoverability::Disputable) < f(Recoverability::TimeLimited));
        assert!(f(Recoverability::TimeLimited) < f(Recoverability::Irreversible));
    }

    #[test]
    fn band_thresholds_are_exact() {
        assert_eq!(
            priority_of_score(CRITICAL_THRESHOLD),
            ResponsePriority::Critical
        );
        assert_eq!(
            priority_of_score(CRITICAL_THRESHOLD - 1),
            ResponsePriority::High
        );
        assert_eq!(priority_of_score(HIGH_THRESHOLD), ResponsePriority::High);
        assert_eq!(
            priority_of_score(HIGH_THRESHOLD - 1),
            ResponsePriority::Medium
        );
        assert_eq!(
            priority_of_score(MEDIUM_THRESHOLD),
            ResponsePriority::Medium
        );
        assert_eq!(
            priority_of_score(MEDIUM_THRESHOLD - 1),
            ResponsePriority::Low
        );
    }
}
