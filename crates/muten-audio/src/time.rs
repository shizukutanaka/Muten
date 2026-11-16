//! Minimal civil-time conversion for schedule evaluation.
//!
//! The policy carries an explicit `utc_offset_minutes`, so conversion is
//! pure arithmetic on the Unix timestamp — no timezone database, no OS
//! calls, and fully deterministic in tests. The administrator is
//! responsible for keeping the offset right across DST changes (stated
//! in the README); managed fleets in Japan (muten's home market) have no
//! DST, and the default offset is JST (+540).

use crate::policy::Weekday;

/// A broken-down local time: weekday + minute of day (0..=1439).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalTime {
    pub weekday: Weekday,
    pub minute_of_day: u16,
}

/// Convert a Unix timestamp (seconds, UTC) plus an offset in minutes to
/// a local weekday / minute-of-day.
///
/// 1970-01-01 (day 0) was a Thursday.
pub fn local_from_unix(unix_secs: i64, utc_offset_minutes: i32) -> LocalTime {
    let shifted = unix_secs + i64::from(utc_offset_minutes) * 60;
    let days = shifted.div_euclid(86_400);
    let secs_of_day = shifted.rem_euclid(86_400);
    // Day 0 = Thursday. Weekday index with Monday = 0: Thursday is 3.
    let weekday = match (days + 3).rem_euclid(7) {
        0 => Weekday::Mon,
        1 => Weekday::Tue,
        2 => Weekday::Wed,
        3 => Weekday::Thu,
        4 => Weekday::Fri,
        5 => Weekday::Sat,
        _ => Weekday::Sun,
    };
    LocalTime {
        weekday,
        minute_of_day: (secs_of_day / 60) as u16,
    }
}

/// Current Unix time in seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_thursday_midnight_utc() {
        let lt = local_from_unix(0, 0);
        assert_eq!(lt.weekday, Weekday::Thu);
        assert_eq!(lt.minute_of_day, 0);
    }

    #[test]
    fn jst_offset_shifts_into_morning() {
        // 2026-11-16 00:00:00 UTC was a Monday; +9h -> Monday 09:00 JST.
        let monday_utc = 1_794_787_200; // 2026-11-16T00:00:00Z
        let lt = local_from_unix(monday_utc, 540);
        assert_eq!(lt.weekday, Weekday::Mon);
        assert_eq!(lt.minute_of_day, 9 * 60);
    }

    #[test]
    fn negative_offset_crosses_day_boundary_backwards() {
        // Monday 00:30 UTC at UTC-2 is still Sunday 22:30.
        let monday_utc = 1_794_787_200 + 30 * 60;
        let lt = local_from_unix(monday_utc, -120);
        assert_eq!(lt.weekday, Weekday::Sun);
        assert_eq!(lt.minute_of_day, 22 * 60 + 30);
    }

    #[test]
    fn pre_epoch_timestamps_do_not_panic() {
        let lt = local_from_unix(-1, 0);
        assert_eq!(lt.weekday, Weekday::Wed);
        assert_eq!(lt.minute_of_day, 23 * 60 + 59);
    }
}
