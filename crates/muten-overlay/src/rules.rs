//! Offline blocklist for overlay classification.
//!
//! ## Format
//!
//! A plain-text file, one rule per line. Two rule kinds:
//!
//! ```text
//! # comments start with '#'
//! host: win-prize-now.example      # block any URL on this host (or subdomain)
//! title: your computer is infected # substring match against the window title
//! ```
//!
//! Bare lines (no prefix) are treated as `host:` rules, which is the
//! common case and matches the muscle memory of hosts-file / pi-hole
//! users. Matching is case-insensitive; hosts match the registered
//! domain and any subdomain (`a.b.evil.example` matches `evil.example`).
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
use std::collections::BTreeSet;

/// The parsed offline blocklist. Parse with [`Ruleset::parse`] (or
/// [`Ruleset::from_lines`] in tests). An empty `Ruleset::default()`
/// matches nothing and is safe to use as a no-op placeholder.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ruleset {
    /// Registered hosts to block (lower-cased, no scheme/path).
    hosts: BTreeSet<String>,
    /// Title substrings to flag.
    title_patterns: Vec<TitlePattern>,
    /// Known rogue-AV / scareware process-name substrings (lower-cased).
    /// e.g. "pc protector plus", "advanced mac cleaner", "registrysmart".
    process_patterns: Vec<String>,
    /// Known scam phone numbers, digits-only key + authored display.
    phone_patterns: Vec<PhonePattern>,
    /// Declarative AND-condition composite rules (`composite:` prefix).
    composite_rules: Vec<CompositeRule>,
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

impl Ruleset {
    /// Parse a blocklist from its text form. Unknown/blank lines are
    /// skipped silently; a malformed entry never aborts the load
    /// (one bad line shouldn't disable the whole list).
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut hosts = BTreeSet::new();
        let mut title_patterns = Vec::new();
        let mut process_patterns = Vec::new();
        let mut phone_patterns = Vec::new();
        let mut composite_rules = Vec::new();
        for raw in text.lines() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("host:") {
                if let Some(h) = normalize_host(rest.trim()) {
                    hosts.insert(h);
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
                // (1-800-…, +1 800 …) and it still matches a title that
                // formats it differently. Require ≥ 7 digits so a stray
                // short number can't become an over-broad rule.
                let display = rest.trim().to_ascii_lowercase();
                let digits: String = display.chars().filter(char::is_ascii_digit).collect();
                // Normalize an 11-digit NANP number (leading country-code
                // "1") to its 10-digit national form. That national key is a
                // substring of the number whether the title writes it with or
                // without the "1", so `1-800-555-0100` matches both
                // "1 800 555 0100" and "(800) 555-0100". NANP national numbers
                // never start with 1, so this can't over-broaden.
                let key = if digits.len() == 11 && digits.starts_with('1') {
                    digits[1..].to_string()
                } else {
                    digits
                };
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
            process_patterns,
            phone_patterns,
            composite_rules,
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
    /// Access the composite AND-condition rules (for evaluation in classify).
    #[must_use]
    pub fn composite_rules(&self) -> &[CompositeRule] {
        &self.composite_rules
    }

    /// Does `url` resolve to a blocked host? Returns the matched rule
    /// host on success. Matches the host and any subdomain of it.
    #[must_use]
    pub fn match_host(&self, url: &str) -> Option<String> {
        let host = host_of(url)?;
        // Drop any zero-width/BiDi characters first (e.g. `ev\u{200B}il`),
        // then fold typosquat/homoglyph confusables (0→o, 1→l, Cyrillic
        // о→o, …) so `micros0ft.example` / `evіl.example` can't dodge an
        // ASCII host blocklist. We compare folded-host suffixes against
        // folded rules, but return the *original* matched rule string
        // for the audit log.
        let host = crate::confusables::strip_invisibles(&host);
        let folded_host = crate::confusables::fold_host_confusables(&host);
        let labels: Vec<&str> = folded_host.split('.').collect();
        for i in 0..labels.len() {
            let suffix = labels[i..].join(".");
            // Fast path: exact (already-folded-equal) membership.
            if self.hosts.contains(&suffix) {
                return Some(suffix);
            }
            // Folded comparison against each rule (host set is small).
            for rule in &self.hosts {
                if crate::confusables::fold_host_confusables(rule) == suffix {
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

    /// Does `title` contain a **known scam phone number**? Returns the
    /// authored rule on the first match.
    ///
    /// Matching is digits-only on both sides: the title is confusable-folded
    /// (so full-width / look-alike digits normalize to ASCII), every non-digit
    /// is dropped, and each rule's digit string is sought as a substring. A
    /// curated scam number is high-confidence evidence wherever it appears, so
    /// — unlike the shape-based `phone_number` heuristic — this does not
    /// require the window to look like an alert. It remains additive (it does
    /// not auto-block), consistent with `title:`.
    #[must_use]
    pub fn match_phone(&self, title: &str) -> Option<String> {
        if self.phone_patterns.is_empty() {
            return None;
        }
        let folded = crate::confusables::fold_confusables(title);
        let digits: String = folded.chars().filter(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        self.phone_patterns
            .iter()
            .find(|p| digits.contains(&p.digits))
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

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Lower-case and remove separators (space, hyphen, underscore) so
/// product names match regardless of how they're written.
fn squash(s: &str) -> String {
    s.to_ascii_lowercase()
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
    fn short_phone_rule_is_rejected() {
        // < 7 digits would be an over-broad rule; it must be dropped.
        let rs = Ruleset::from_lines(&["phone: 12345"]);
        assert_eq!(rs.phone_count(), 0);
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
}
