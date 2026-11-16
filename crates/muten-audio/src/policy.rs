//! Policy: the administrator-owned configuration file (`policy.json`).
//!
//! The policy decides *when* muting is enforced (master switch +
//! schedule), *whether* a temporary unmute may be granted at all, and
//! *how long* a grant may last. The admin PIN itself is stored only as a
//! salted, iterated hash (see [`crate::pin`]) — never in plaintext.
//!
//! Unknown fields are rejected (`deny_unknown_fields`) so a typo in a
//! hand-edited policy fails loudly at load time instead of silently
//! weakening enforcement.

use serde::{Deserialize, Serialize};

use crate::pin::PinRecord;
use crate::time::LocalTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Weekday {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

impl Weekday {
    /// The weekday before this one (for overnight schedule windows).
    pub fn previous(self) -> Weekday {
        match self {
            Weekday::Mon => Weekday::Sun,
            Weekday::Tue => Weekday::Mon,
            Weekday::Wed => Weekday::Tue,
            Weekday::Thu => Weekday::Wed,
            Weekday::Fri => Weekday::Thu,
            Weekday::Sat => Weekday::Fri,
            Weekday::Sun => Weekday::Sat,
        }
    }
}

/// One enforcement window, e.g. Mon–Fri 08:00–19:00.
///
/// Times are local wall-clock `"HH:MM"`. A window whose `end` is earlier
/// than its `start` crosses midnight: `fri 22:00–06:00` covers Friday
/// 22:00–24:00 and Saturday 00:00–06:00. The interval is half-open:
/// `start` is inclusive, `end` is exclusive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub days: Vec<Weekday>,
    pub start: String,
    pub end: String,
}

impl Window {
    /// Parse `"HH:MM"` into minutes since midnight.
    pub fn parse_hhmm(s: &str) -> Result<u16, PolicyError> {
        let err = || PolicyError::BadTime(s.to_string());
        let (h, m) = s.split_once(':').ok_or_else(err)?;
        if h.len() != 2 || m.len() != 2 {
            return Err(err());
        }
        let h: u16 = h.parse().map_err(|_| err())?;
        let m: u16 = m.parse().map_err(|_| err())?;
        if h > 23 || m > 59 {
            return Err(err());
        }
        Ok(h * 60 + m)
    }

    fn start_min(&self) -> u16 {
        // Validated at load; the fallback only fires for hand-built
        // structs in tests that skipped validation.
        Self::parse_hhmm(&self.start).unwrap_or(0)
    }

    fn end_min(&self) -> u16 {
        Self::parse_hhmm(&self.end).unwrap_or(0)
    }

    /// Does this window cover the given local time?
    pub fn contains(&self, t: LocalTime) -> bool {
        let (start, end) = (self.start_min(), self.end_min());
        if start < end {
            self.days.contains(&t.weekday) && t.minute_of_day >= start && t.minute_of_day < end
        } else {
            // Overnight: the evening part belongs to the listed day,
            // the early-morning part to the day *after* a listed day.
            (self.days.contains(&t.weekday) && t.minute_of_day >= start)
                || (self.days.contains(&t.weekday.previous()) && t.minute_of_day < end)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Policy format version. Must be 1.
    pub version: u32,
    /// Master switch. `false` = the agent runs but never touches audio.
    pub enforce: bool,
    /// Offset from UTC used for schedule evaluation, in minutes.
    /// Default 540 (JST). Administrators in DST regions must adjust it
    /// when the clocks change.
    #[serde(default = "default_utc_offset_minutes")]
    pub utc_offset_minutes: i32,
    /// Watchdog poll interval. Default 1000 ms; minimum 100.
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    /// May an administrator grant a temporary unmute at all?
    #[serde(default)]
    pub allow_unmute: bool,
    /// Hard cap on one grant, in minutes. Requests above the cap are
    /// clamped to it. Must be >= 1 when `allow_unmute` is true.
    #[serde(default = "default_max_unmute_minutes")]
    pub max_unmute_minutes: u32,
    /// Enforcement windows. Empty = enforce at all times (subject to
    /// `enforce`).
    #[serde(default)]
    pub schedule: Vec<Window>,
    /// Admin PIN record (salted iterated hash). `None` = no PIN set;
    /// unmute requests are then always refused.
    #[serde(default)]
    pub pin: Option<PinRecord>,
}

fn default_utc_offset_minutes() -> i32 {
    540
}
fn default_poll_interval_ms() -> u64 {
    1000
}
fn default_max_unmute_minutes() -> u32 {
    30
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("unsupported policy version {0} (expected 1)")]
    BadVersion(u32),
    #[error("invalid time {0:?} (expected \"HH:MM\", 00:00-23:59)")]
    BadTime(String),
    #[error("schedule window has an empty days list")]
    EmptyDays,
    #[error("schedule window start and end are identical ({0})")]
    ZeroLengthWindow(String),
    #[error("poll_interval_ms {0} is below the 100 ms minimum")]
    PollTooSmall(u64),
    #[error("utc_offset_minutes {0} is outside the valid range -720..=840")]
    BadOffset(i32),
    #[error("max_unmute_minutes must be at least 1 when allow_unmute is true")]
    BadMaxUnmute,
}

impl Policy {
    /// A starter policy: enforce always, unmute allowed up to 30 minutes,
    /// no PIN yet (unmute stays refused until `set-pin` runs).
    pub fn starter() -> Policy {
        Policy {
            version: 1,
            enforce: true,
            utc_offset_minutes: default_utc_offset_minutes(),
            poll_interval_ms: default_poll_interval_ms(),
            allow_unmute: true,
            max_unmute_minutes: default_max_unmute_minutes(),
            schedule: Vec::new(),
            pin: None,
        }
    }

    /// Validate structural invariants. Called on every load; an invalid
    /// policy must fail loudly, never silently degrade.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != 1 {
            return Err(PolicyError::BadVersion(self.version));
        }
        if self.poll_interval_ms < 100 {
            return Err(PolicyError::PollTooSmall(self.poll_interval_ms));
        }
        if !(-720..=840).contains(&self.utc_offset_minutes) {
            return Err(PolicyError::BadOffset(self.utc_offset_minutes));
        }
        if self.allow_unmute && self.max_unmute_minutes == 0 {
            return Err(PolicyError::BadMaxUnmute);
        }
        for w in &self.schedule {
            if w.days.is_empty() {
                return Err(PolicyError::EmptyDays);
            }
            let start = Window::parse_hhmm(&w.start)?;
            let end = Window::parse_hhmm(&w.end)?;
            if start == end {
                return Err(PolicyError::ZeroLengthWindow(w.start.clone()));
            }
        }
        Ok(())
    }

    /// Is muting enforced at this local time?
    pub fn is_enforced_at(&self, t: LocalTime) -> bool {
        if !self.enforce {
            return false;
        }
        if self.schedule.is_empty() {
            return true;
        }
        self.schedule.iter().any(|w| w.contains(t))
    }

    /// Load and validate a policy from disk.
    pub fn load(path: &std::path::Path) -> Result<Policy, crate::Error> {
        let text = std::fs::read_to_string(path)?;
        let policy: Policy = serde_json::from_str(&text)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Serialize (pretty JSON) for writing back, e.g. by `set-pin`.
    pub fn to_json(&self) -> Result<String, crate::Error> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(weekday: Weekday, h: u16, m: u16) -> LocalTime {
        LocalTime {
            weekday,
            minute_of_day: h * 60 + m,
        }
    }

    fn weekday_window() -> Window {
        Window {
            days: vec![
                Weekday::Mon,
                Weekday::Tue,
                Weekday::Wed,
                Weekday::Thu,
                Weekday::Fri,
            ],
            start: "08:00".into(),
            end: "19:00".into(),
        }
    }

    #[test]
    fn starter_policy_is_valid_and_enforces_always() {
        let p = Policy::starter();
        p.validate().unwrap();
        assert!(p.is_enforced_at(at(Weekday::Sun, 3, 0)));
    }

    #[test]
    fn master_switch_off_never_enforces() {
        let mut p = Policy::starter();
        p.enforce = false;
        assert!(!p.is_enforced_at(at(Weekday::Mon, 10, 0)));
    }

    #[test]
    fn window_boundaries_are_half_open() {
        let w = weekday_window();
        assert!(w.contains(at(Weekday::Mon, 8, 0))); // start inclusive
        assert!(!w.contains(at(Weekday::Mon, 7, 59)));
        assert!(w.contains(at(Weekday::Fri, 18, 59)));
        assert!(!w.contains(at(Weekday::Fri, 19, 0))); // end exclusive
        assert!(!w.contains(at(Weekday::Sat, 10, 0))); // not a listed day
    }

    #[test]
    fn overnight_window_covers_both_sides_of_midnight() {
        let w = Window {
            days: vec![Weekday::Fri],
            start: "22:00".into(),
            end: "06:00".into(),
        };
        assert!(w.contains(at(Weekday::Fri, 23, 30)));
        assert!(w.contains(at(Weekday::Sat, 5, 59))); // morning after Fri
        assert!(!w.contains(at(Weekday::Sat, 6, 0)));
        assert!(!w.contains(at(Weekday::Sat, 23, 30))); // Sat not listed
        assert!(!w.contains(at(Weekday::Fri, 21, 59)));
    }

    #[test]
    fn schedule_restricts_enforcement() {
        let mut p = Policy::starter();
        p.schedule = vec![weekday_window()];
        assert!(p.is_enforced_at(at(Weekday::Tue, 12, 0)));
        assert!(!p.is_enforced_at(at(Weekday::Tue, 20, 0)));
        assert!(!p.is_enforced_at(at(Weekday::Sun, 12, 0)));
    }

    #[test]
    fn invalid_policies_are_rejected() {
        let mut p = Policy::starter();
        p.version = 2;
        assert_eq!(p.validate(), Err(PolicyError::BadVersion(2)));

        let mut p = Policy::starter();
        p.poll_interval_ms = 50;
        assert!(matches!(p.validate(), Err(PolicyError::PollTooSmall(50))));

        let mut p = Policy::starter();
        p.schedule = vec![Window {
            days: vec![Weekday::Mon],
            start: "25:00".into(),
            end: "26:00".into(),
        }];
        assert!(matches!(p.validate(), Err(PolicyError::BadTime(_))));

        let mut p = Policy::starter();
        p.schedule = vec![Window {
            days: vec![Weekday::Mon],
            start: "09:00".into(),
            end: "09:00".into(),
        }];
        assert!(matches!(
            p.validate(),
            Err(PolicyError::ZeroLengthWindow(_))
        ));

        let mut p = Policy::starter();
        p.schedule = vec![Window {
            days: vec![],
            start: "09:00".into(),
            end: "17:00".into(),
        }];
        assert_eq!(p.validate(), Err(PolicyError::EmptyDays));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let text = r#"{"version":1,"enforce":true,"surprise":true}"#;
        assert!(serde_json::from_str::<Policy>(text).is_err());
    }

    #[test]
    fn json_round_trip() {
        let mut p = Policy::starter();
        p.schedule = vec![weekday_window()];
        let text = p.to_json().unwrap();
        let back: Policy = serde_json::from_str(&text).unwrap();
        assert_eq!(p, back);
    }
}
