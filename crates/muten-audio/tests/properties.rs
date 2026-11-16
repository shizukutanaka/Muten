//! Property tests for the enforcement invariants that must hold for
//! *every* input, not just the examples in the unit tests:
//!
//! - Sound is never permitted without (policy permission AND an active
//!   grant).
//! - With the master switch off, the decision is always Standby.
//! - The audit chain verifies for any sequence of events, and any
//!   single-character edit to a stored line breaks it.
//! - Local-time conversion never produces an out-of-range minute.

use muten_audio::audit::{verify_chain, AuditLog, Event, EventKind};
use muten_audio::decide::{decide, Decision, Observed};
use muten_audio::grant::Grant;
use muten_audio::policy::{Policy, Weekday, Window};
use muten_audio::time::local_from_unix;
use proptest::prelude::*;

fn arb_weekday() -> impl Strategy<Value = Weekday> {
    prop_oneof![
        Just(Weekday::Mon),
        Just(Weekday::Tue),
        Just(Weekday::Wed),
        Just(Weekday::Thu),
        Just(Weekday::Fri),
        Just(Weekday::Sat),
        Just(Weekday::Sun),
    ]
}

proptest! {
    #[test]
    fn no_unmute_permission_means_never_unmuted(
        allow in any::<bool>(),
        grant_start in 0i64..2_000_000_000,
        grant_mins in 0u32..600,
        now in 0i64..2_000_000_000,
        muted in any::<bool>(),
    ) {
        let mut policy = Policy::starter();
        policy.allow_unmute = allow;
        let grant = Grant::new(grant_start, grant_mins);
        let local = local_from_unix(now, policy.utc_offset_minutes);
        let d = decide(&policy, local, Observed { muted, volume_percent: None }, Some(&grant), now);
        let permitted = allow && grant.is_active(now);
        if !permitted {
            let is_unmute_grant = matches!(d, Decision::UnmuteForGrant { .. });
            prop_assert!(d != Decision::LeaveUnmuted);
            prop_assert!(!is_unmute_grant);
        }
    }

    #[test]
    fn master_switch_off_is_always_standby(
        now in 0i64..2_000_000_000,
        muted in any::<bool>(),
    ) {
        let mut policy = Policy::starter();
        policy.enforce = false;
        let local = local_from_unix(now, 540);
        let d = decide(&policy, local, Observed { muted, volume_percent: None }, None, now);
        prop_assert_eq!(d, Decision::Standby);
    }

    #[test]
    fn enforced_empty_schedule_always_enforces(
        now in -4_102_444_800i64..4_102_444_800,
        offset in -720i32..=840,
    ) {
        let mut policy = Policy::starter();
        policy.utc_offset_minutes = offset;
        let local = local_from_unix(now, offset);
        prop_assert!(policy.is_enforced_at(local));
    }

    #[test]
    fn local_time_minute_is_in_range(
        now in -4_102_444_800i64..4_102_444_800,
        offset in -720i32..=840,
    ) {
        let lt = local_from_unix(now, offset);
        prop_assert!(lt.minute_of_day < 1440);
    }

    #[test]
    fn same_day_window_contains_exactly_its_range(
        day in arb_weekday(),
        start in 0u16..1400,
        len in 1u16..(1440 - 1400 + 40),
        probe in 0u16..1440,
    ) {
        let end = (start + len).min(1439);
        prop_assume!(end > start);
        let fmt = |m: u16| format!("{:02}:{:02}", m / 60, m % 60);
        let w = Window { days: vec![day], start: fmt(start), end: fmt(end) };
        let t = muten_audio::time::LocalTime { weekday: day, minute_of_day: probe };
        prop_assert_eq!(w.contains(t), probe >= start && probe < end);
    }
}

#[test]
fn audit_chain_survives_many_events_and_detects_edits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let kinds = [
        EventKind::AgentStarted,
        EventKind::Muted,
        EventKind::VolumeRaisedDetected,
        EventKind::UnmuteGranted,
        EventKind::GrantExpired,
    ];
    {
        let mut log = AuditLog::open(&path).unwrap();
        for i in 0..50i64 {
            log.append(&Event {
                ts_unix: 1_700_000_000 + i,
                kind: kinds[(i as usize) % kinds.len()],
                detail: serde_json::json!({"i": i}),
            })
            .unwrap();
        }
    }
    let text = std::fs::read_to_string(&path).unwrap();
    let status = verify_chain(&text).unwrap();
    assert_eq!(status.events, 50);

    // Flip one character inside the first line's detail.
    let mut chars: Vec<char> = text.chars().collect();
    let pos = text.find("\"i\":0").unwrap() + 4;
    chars[pos] = '9';
    let tampered: String = chars.into_iter().collect();
    assert!(verify_chain(&tampered).is_err());
}
