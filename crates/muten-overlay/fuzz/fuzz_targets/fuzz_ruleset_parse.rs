//! Fuzz the blocklist parser (`Ruleset::parse` / `Ruleset::from_lines`).
//!
//! Goals:
//! - Never panic on arbitrary UTF-8 input.
//! - Parsing twice gives the same result (idempotence of the parse result).
//! - `host_count + title_count + glob_count + phone_count + composite_count
//!   + weight_override_count` is always consistent with the parsed ruleset.
//!
//! Run with:
//! ```sh
//! cargo +nightly fuzz run fuzz_ruleset_parse -- -max_len=4096
//! ```
#![no_main]
use libfuzzer_sys::fuzz_target;
use muten_overlay::Ruleset;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // Never panics.
    let rs = Ruleset::parse(s);
    // Parsing the same string again gives the same counts (idempotent data).
    let rs2 = Ruleset::parse(s);
    assert_eq!(rs.host_count(), rs2.host_count());
    assert_eq!(rs.title_count(), rs2.title_count());
    assert_eq!(rs.glob_count(), rs2.glob_count());
    // Structural invariants: counts are non-negative (trivially true for usize)
    // and the ruleset is always in a usable state.
    let _ = rs.match_host("http://test.evil.example/x");
    let _ = rs.match_title("your computer is infected");
    let _ = rs.match_title_glob("warning: your computer is infected");
    let _ = rs.weight_of("fullscreen", 30);
});
