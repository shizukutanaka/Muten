//! The watchdog decision function — the heart of the enforcement loop.
//!
//! Pure: policy + local time + observed endpoint state + grant in,
//! decision out. The agent executes the decision through the
//! [`crate::AudioBackend`]; every branch is unit-tested here without
//! any OS involvement.

use serde::{Deserialize, Serialize};

use crate::grant::Grant;
use crate::policy::Policy;
use crate::time::LocalTime;

/// What the backend reports about the default playback endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Observed {
    pub muted: bool,
    /// Master volume as a percentage 0..=100, when the backend can
    /// report it. Informational (logged); muting is the enforcement.
    pub volume_percent: Option<u8>,
}

/// What the agent should do on this poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Endpoint is unmuted with no valid grant: mute it now.
    MuteNow,
    /// Endpoint is already muted and should stay that way.
    LeaveMuted,
    /// A grant is active but the endpoint is muted (e.g. the agent
    /// started mid-grant): unmute it for the remainder of the grant.
    UnmuteForGrant { remaining_secs: i64 },
    /// A grant is active and the endpoint is already unmuted.
    LeaveUnmuted,
    /// Enforcement is off right now (master switch off, or outside the
    /// schedule): do not touch the audio state at all.
    Standby,
}

/// Decide one poll.
///
/// Rules, in order:
/// 1. Not enforced at this time → [`Decision::Standby`], whatever else
///    is true. (A grant never *forces* sound outside enforcement hours;
///    it merely permits it during them.)
/// 2. A grant that is active *and* permitted by policy
///    (`allow_unmute`) → sound is allowed for its remainder.
/// 3. Otherwise the endpoint must be muted.
pub fn decide(
    policy: &Policy,
    local: LocalTime,
    observed: Observed,
    grant: Option<&Grant>,
    now_unix: i64,
) -> Decision {
    if !policy.is_enforced_at(local) {
        return Decision::Standby;
    }
    if policy.allow_unmute {
        if let Some(g) = grant {
            if g.is_active(now_unix) {
                return if observed.muted {
                    Decision::UnmuteForGrant {
                        remaining_secs: g.remaining_secs(now_unix),
                    }
                } else {
                    Decision::LeaveUnmuted
                };
            }
        }
    }
    if observed.muted {
        Decision::LeaveMuted
    } else {
        Decision::MuteNow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Weekday, Window};

    fn mon(h: u16) -> LocalTime {
        LocalTime {
            weekday: Weekday::Mon,
            minute_of_day: h * 60,
        }
    }

    fn unmuted() -> Observed {
        Observed {
            muted: false,
            volume_percent: Some(40),
        }
    }
    fn muted() -> Observed {
        Observed {
            muted: true,
            volume_percent: Some(40),
        }
    }

    #[test]
    fn unmuted_without_grant_is_muted() {
        let p = Policy::starter();
        assert_eq!(
            decide(&p, mon(10), unmuted(), None, 1_000),
            Decision::MuteNow
        );
        assert_eq!(
            decide(&p, mon(10), muted(), None, 1_000),
            Decision::LeaveMuted
        );
    }

    #[test]
    fn active_grant_permits_sound() {
        let p = Policy::starter();
        let g = Grant::new(1_000, 30);
        assert_eq!(
            decide(&p, mon(10), unmuted(), Some(&g), 1_100),
            Decision::LeaveUnmuted
        );
        assert_eq!(
            decide(&p, mon(10), muted(), Some(&g), 1_100),
            Decision::UnmuteForGrant {
                remaining_secs: 1_700
            }
        );
    }

    #[test]
    fn expired_grant_no_longer_permits_sound() {
        let p = Policy::starter();
        let g = Grant::new(1_000, 30);
        let after = 1_000 + 30 * 60;
        assert_eq!(
            decide(&p, mon(10), unmuted(), Some(&g), after),
            Decision::MuteNow
        );
    }

    #[test]
    fn grant_is_ignored_when_policy_forbids_unmute() {
        let mut p = Policy::starter();
        p.allow_unmute = false;
        let g = Grant::new(1_000, 30);
        assert_eq!(
            decide(&p, mon(10), unmuted(), Some(&g), 1_100),
            Decision::MuteNow
        );
    }

    #[test]
    fn outside_schedule_is_standby_even_with_a_grant() {
        let mut p = Policy::starter();
        p.schedule = vec![Window {
            days: vec![Weekday::Mon],
            start: "08:00".into(),
            end: "19:00".into(),
        }];
        let g = Grant::new(1_000, 30);
        assert_eq!(
            decide(&p, mon(23), unmuted(), Some(&g), 1_100),
            Decision::Standby
        );
        assert_eq!(decide(&p, mon(23), muted(), None, 1_100), Decision::Standby);
    }

    #[test]
    fn master_switch_off_is_standby() {
        let mut p = Policy::starter();
        p.enforce = false;
        assert_eq!(
            decide(&p, mon(10), unmuted(), None, 1_000),
            Decision::Standby
        );
    }
}
