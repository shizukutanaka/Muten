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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ruleset {
    /// Registered hosts to block (lower-cased, no scheme/path).
    hosts: BTreeSet<String>,
    /// Title substrings to flag (lower-cased).
    title_patterns: Vec<String>,
    /// Known rogue-AV / scareware process-name substrings (lower-cased).
    /// e.g. "pc protector plus", "advanced mac cleaner", "registrysmart".
    process_patterns: Vec<String>,
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
                let pat = rest.trim().to_ascii_lowercase();
                if !pat.is_empty() {
                    title_patterns.push(pat);
                }
            } else if let Some(rest) = line.strip_prefix("process:") {
                let pat = rest.trim().to_ascii_lowercase();
                if !pat.is_empty() {
                    process_patterns.push(pat);
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
        }
    }

    /// Convenience for tests / programmatic construction.
    #[must_use]
    pub fn from_lines(lines: &[&str]) -> Self {
        Self::parse(&lines.join("\n"))
    }

    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }
    pub fn title_count(&self) -> usize {
        self.title_patterns.len()
    }
    pub fn process_count(&self) -> usize {
        self.process_patterns.len()
    }

    /// Does `url` resolve to a blocked host? Returns the matched rule
    /// host on success. Matches the host and any subdomain of it.
    #[must_use]
    pub fn match_host(&self, url: &str) -> Option<String> {
        let host = host_of(url)?;
        // Fold typosquat/homoglyph confusables (0→o, 1→l, Cyrillic о→o,
        // …) so `micros0ft.example` / `evіl.example` can't dodge an
        // ASCII host blocklist. We compare folded-host suffixes against
        // folded rules, but return the *original* matched rule string
        // for the audit log.
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
    /// The title is homoglyph-folded (Cyrillic/Greek/full-width
    /// look-alikes → ASCII) before matching, so a scam that swaps a
    /// Latin letter for a confusable (e.g. Cyrillic і in "іnfected")
    /// can't slip past an ASCII substring blocklist. See the
    /// `confusables` module.
    #[must_use]
    pub fn match_title(&self, title: &str) -> Option<String> {
        let folded = crate::confusables::fold_confusables(title);
        let t = folded.to_ascii_lowercase();
        self.title_patterns
            .iter()
            .find(|p| t.contains(p.as_str()))
            .cloned()
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
fn host_of(url: &str) -> Option<String> {
    let s = url.trim().to_ascii_lowercase();
    // Strip scheme.
    let after_scheme = match s.find("://") {
        Some(i) => &s[i + 3..],
        None => &s,
    };
    // Authority ends at the first '/', '?', or '#'.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Drop userinfo@ and :port.
    let no_userinfo = authority.rsplit('@').next().unwrap_or(authority);
    let host = no_userinfo.split(':').next().unwrap_or(no_userinfo);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
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
}
