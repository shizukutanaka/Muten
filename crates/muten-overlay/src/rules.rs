//! Offline blocklist for overlay classification.
//!
//! ## Format
//!
//! A plain-text file, one rule per line. Rule kinds:
//!
//! ```text
//! # comments start with '#'
//! host: win-prize-now.example      # block any URL on this host (or subdomain)
//! title: your computer is infected # substring match against the window title
//! glob: *your computer*infected*   # full-string glob match (*, ?)
//! phone: 1-800-555-0100            # curated scam phone number (digits-only match)
//! process: pc protector plus       # rogue-AV process-name substring
//! composite: <name> <weight> <cond…> # AND-condition named rule
//! ```
//!
//! Bare lines (no prefix) are treated as `host:` rules, which is the
//! common case and matches the muscle memory of hosts-file / pi-hole
//! users. Matching is case-insensitive; hosts match the registered
//! domain and any subdomain (`a.b.evil.example` matches `evil.example`).
//!
//! ### `glob:` patterns
//!
//! Unlike `title:` (which is a substring/contains match), `glob:` patterns
//! are full-string: the entire normalized title must match.  Use `*` at
//! either end for prefix, suffix, or contains behaviour:
//!
//! ```text
//! glob: *your computer is infected*   # contains (equivalent to title:)
//! glob: WARNING: *                    # any title that starts "warning: "
//! glob: * security alert *            # contains " security alert " anywhere
//! ```
//!
//! `*` matches any run of characters (including none); `?` matches exactly
//! one character.  Both the pattern and the title are normalized through
//! the same pipeline as `title:` (`strip_invisibles → fold_confusables →
//! fold_leet_in_words → lowercase`) before matching, so evasion via
//! homoglyphs, zero-width characters, and leetspeak is handled uniformly.
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
use std::collections::{BTreeMap, BTreeSet};

/// The parsed offline blocklist. Parse with [`Ruleset::parse`] (or
/// [`Ruleset::from_lines`] in tests). An empty `Ruleset::default()`
/// matches nothing and is safe to use as a no-op placeholder.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ruleset {
    /// Registered hosts to block (lower-cased, no scheme/path).
    hosts: BTreeSet<String>,
    /// Title substrings to flag.
    title_patterns: Vec<TitlePattern>,
    /// Title glob patterns (`*`/`?` wildcards, full-string match).
    glob_patterns: Vec<GlobPattern>,
    /// Known rogue-AV / scareware process-name substrings (lower-cased).
    /// e.g. "pc protector plus", "advanced mac cleaner", "registrysmart".
    process_patterns: Vec<String>,
    /// Known scam phone numbers, digits-only key + authored display.
    phone_patterns: Vec<PhonePattern>,
    /// Declarative AND-condition composite rules (`composite:` prefix).
    composite_rules: Vec<CompositeRule>,
    /// Per-signal weight overrides from `weight:` lines.  Operators can
    /// raise or lower any named signal's contribution without rebuilding.
    weight_overrides: BTreeMap<String, i32>,
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

/// A blocklist glob-pattern title rule.  `key` is the pattern after
/// normalization (same pipeline as `TitlePattern`; `*`/`?` preserved);
/// `display` is the authored text for audit-log readability.  Full-string
/// matching: the entire normalized title must match the entire pattern.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GlobPattern {
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
        let mut glob_patterns = Vec::new();
        let mut process_patterns = Vec::new();
        let mut phone_patterns = Vec::new();
        let mut composite_rules = Vec::new();
        let mut weight_overrides = BTreeMap::new();
        for raw in text.lines() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("host:") {
                if let Some(h) = normalize_host(rest.trim()) {
                    hosts.insert(h);
                }
            } else if let Some(rest) = line.strip_prefix("glob:") {
                // Full-string glob pattern. `*` matches any run of chars
                // (including none); `?` matches exactly one char. Normalized
                // at parse time with the same pipeline as `title:` — but `*`
                // and `?` are non-alphanumeric separators and are preserved
                // verbatim by `fold_leet_in_words`, so they remain as
                // metacharacters after normalization.
                let raw_pat = rest.trim();
                let key = crate::confusables::normalize_for_match(raw_pat);
                if !key.is_empty() {
                    glob_patterns.push(GlobPattern {
                        key,
                        display: raw_pat.to_ascii_lowercase(),
                    });
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
                // (1-800-…, +81-0120-…) and it still matches a title that
                // formats it differently. Require ≥ 7 digits so a stray
                // short number can't become an over-broad rule.
                let display = rest.trim().to_ascii_lowercase();
                let digits: String = display.chars().filter(char::is_ascii_digit).collect();
                let key = normalize_phone_digits(&digits);
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
            } else if let Some(rest) = line.strip_prefix("weight:") {
                // Per-signal weight override.
                // Format: weight: <signal_name> <value>
                // Allows operators to tune any named signal's additive
                // contribution without recompiling.  The value is any i32
                // (including negative, to soften or negate a relief signal).
                // Unknown signal names are silently stored — classify() will
                // look them up later; this future-proofs against new signals
                // added after the blocklist was authored.
                let mut parts = rest.split_whitespace();
                if let (Some(sig), Some(val_str)) = (parts.next(), parts.next()) {
                    if let Ok(val) = val_str.parse::<i32>() {
                        weight_overrides.insert(sig.to_ascii_lowercase(), val);
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
            glob_patterns,
            process_patterns,
            phone_patterns,
            composite_rules,
            weight_overrides,
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
    /// Number of title glob patterns loaded (`glob:` rules).
    pub fn glob_count(&self) -> usize {
        self.glob_patterns.len()
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
    /// Number of per-signal weight overrides (`weight:` lines) loaded.
    pub fn weight_override_count(&self) -> usize {
        self.weight_overrides.len()
    }
    /// Access the composite AND-condition rules (for evaluation in classify).
    #[must_use]
    pub fn composite_rules(&self) -> &[CompositeRule] {
        &self.composite_rules
    }

    /// Effective weight for a named signal.  Returns the operator-supplied
    /// override from a `weight:` blocklist line if one exists, otherwise
    /// falls back to `default` (the compile-time constant for that signal).
    ///
    /// `classify()` uses this for every signal so that a fleet-pushed
    /// blocklist can tune sensitivity without a rebuild — an operator who
    /// observes from `signal_firing_stats()` that `mixed_script` has a high
    /// FP rate in their environment can lower its weight while keeping all
    /// other signals at their compiled defaults.
    #[must_use]
    pub fn weight_of(&self, signal: &str, default: i32) -> i32 {
        self.weight_overrides
            .get(signal)
            .copied()
            .unwrap_or(default)
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

    /// Does `title` match any **glob title pattern**?  Returns the display
    /// form of the first matching pattern.
    ///
    /// The title is normalized through the same pipeline as [`match_title`]
    /// before matching.  Unlike `match_title`, which does a substring
    /// (contains) search, glob matching is **full-string**: the entire
    /// normalized title must match the pattern.  Use `*` at the edges for
    /// contains / prefix / suffix semantics.
    ///
    /// `*` matches any sequence of characters (including the empty sequence).
    /// `?` matches any single character.  Both are matched against normalized
    /// code points; the pattern is also normalized at parse time, so
    /// evasion via homoglyphs, zero-width characters, and leetspeak is
    /// thwarted symmetrically.
    ///
    /// [`match_title`]: Ruleset::match_title
    #[must_use]
    pub fn match_title_glob(&self, title: &str) -> Option<String> {
        if self.glob_patterns.is_empty() {
            return None;
        }
        let t: Vec<char> = crate::confusables::normalize_for_match(title)
            .chars()
            .collect();
        for pat in &self.glob_patterns {
            let p: Vec<char> = pat.key.chars().collect();
            if glob_match(&p, &t) {
                return Some(pat.display.clone());
            }
        }
        None
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
        // Also try the normalized form so that a title showing an international
        // prefix (+81, +44, +61, +1) matches a rule authored in national form.
        let normalized = normalize_phone_digits(&digits);
        self.phone_patterns
            .iter()
            .find(|p| digits.contains(&p.digits) || normalized.contains(&p.digits))
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

/// Normalize a digit-only phone string to its national (non-prefixed) form.
///
/// Strips known international dialing prefixes so that the same number
/// can be authored as `+1 800 555 0100`, `0120 000 000`, or `+81 120 000 000`
/// and still match regardless of how a title formats it (E6):
///
/// | Pattern | Action | Rationale |
/// |---|---|---|
/// | 11 digits starting `1` | strip leading `1` | NANP country code |
/// | 12 digits starting `81` | strip `81` (→ 10d) | Japan (+81), then JP rules apply |
/// | 11 digits starting `44` | strip `44` (→ 9d) | UK (+44) |
/// | 11 digits starting `61` | strip `61` (→ 9d) | Australia (+61) |
///
/// JP note: after stripping `81`, 0120-XXXXXX (toll-free) and 0570-XXXXXX
/// (charged-rate) numbers have their leading `0` intact, so a blocklist entry
/// of `0120-111-222` and a title showing `+81-120-111-222` both normalize to
/// `0120111222` and match correctly.
fn normalize_phone_digits(digits: &str) -> String {
    // NANP: 11 digits, leading "1" (not "11" or "12" etc.) → strip CC.
    // Check NANP first; "1-800-…" (11d, starts '1') must not collide with
    // any two-digit CC that also starts with '1'.
    if digits.len() == 11 && digits.starts_with('1') && !digits.starts_with("11") {
        return digits[1..].to_string();
    }
    // Japan: +81 → 11 digits with leading "81" (0120/0570 are 10d national,
    // +81 drops the leading 0, so +81-120-000-000 = "81120000000", 11 digits).
    // Prepend "0" to restore the national trunk prefix.
    if digits.len() == 11 && digits.starts_with("81") {
        return format!("0{}", &digits[2..]);
    }
    // UK: +44 → 11 digits, leading "44" → strip CC (national is 9–10 digits).
    if digits.len() == 11 && digits.starts_with("44") {
        return digits[2..].to_string();
    }
    // Australia: +61 → 11 digits, leading "61" → strip CC.
    if digits.len() == 11 && digits.starts_with("61") {
        return digits[2..].to_string();
    }
    digits.to_string()
}

/// Full-string glob matcher.  `*` matches any sequence of chars (including
/// none); `?` matches exactly one char.  Both `pattern` and `text` are slices
/// of pre-normalized `char` values.
///
/// Algorithm: single-pass with backtrack pointers (`star_pi`, `star_ti`).
/// O(m × n) worst-case (a long `*`-chain against a long text) but both are
/// bounded by window-title lengths in practice (≤ 500 chars), so stack depth
/// and runtime are negligible.
fn glob_match(pattern: &[char], text: &[char]) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    // Position of the last `*` in pattern and the text index when we committed to it.
    let mut star_pi = usize::MAX;
    let mut star_ti = usize::MAX;
    loop {
        if ti < text.len() {
            if pi < pattern.len() && pattern[pi] == '*' {
                star_pi = pi;
                star_ti = ti;
                pi += 1;
                continue;
            }
            if pi < pattern.len() && (pattern[pi] == '?' || pattern[pi] == text[ti]) {
                pi += 1;
                ti += 1;
                continue;
            }
            // Mismatch: backtrack to the last `*` and try matching one more char.
            if star_pi != usize::MAX {
                star_ti += 1;
                ti = star_ti;
                pi = star_pi + 1;
                continue;
            }
            return false;
        }
        // ti == text.len(): consume trailing `*`s then check exhaustion.
        while pi < pattern.len() && pattern[pi] == '*' {
            pi += 1;
        }
        return pi == pattern.len();
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

    // ── E6: International phone number normalization ─────────────────

    #[test]
    fn normalize_phone_nanp_strips_leading_1() {
        // 11-digit NANP (leading 1) → 10-digit national number.
        assert_eq!(normalize_phone_digits("18005550100"), "8005550100");
        // 10-digit (no country code) → unchanged.
        assert_eq!(normalize_phone_digits("8005550100"), "8005550100");
    }

    #[test]
    fn normalize_phone_japan_strips_country_code() {
        // Japan +81: 0120-000-000 national = "0120000000" (10d).
        // +81 drops the leading 0, so +81-120-000-000 = "81120000000" (11d).
        // normalize_phone_digits prepends "0" after stripping "81" → "0120000000".
        assert_eq!(normalize_phone_digits("81120000000"), "0120000000");
        // 0570 charged-rate number.
        assert_eq!(normalize_phone_digits("81570000000"), "0570000000");
    }

    #[test]
    fn normalize_phone_uk_strips_country_code() {
        // UK +44: 11 digits starting 44 → strip to 9 (national).
        assert_eq!(normalize_phone_digits("44800000000"), "800000000");
    }

    #[test]
    fn normalize_phone_australia_strips_country_code() {
        // Australia +61: 11 digits starting 61 → strip to 9.
        assert_eq!(normalize_phone_digits("61800000000"), "800000000");
    }

    #[test]
    fn normalize_phone_unrecognized_is_unchanged() {
        // A 9-digit number with no recognized prefix → returned as-is.
        assert_eq!(normalize_phone_digits("123456789"), "123456789");
        // An 11-digit number NOT starting with 1, 44, or 61 → unchanged.
        assert_eq!(normalize_phone_digits("55800000000"), "55800000000");
    }

    #[test]
    fn phone_rule_matches_jp_international_format_in_title() {
        // Operator writes the JP toll-free as "0120-111-222" (national);
        // title shows it as "+81 120 111 222" (international). Should match.
        let rs = Ruleset::from_lines(&["phone: 0120-111-222"]);
        // After normalize: rule key = "0120111222", title digits = "81120111222" → strip "81" → "0120111222".
        // match_phone strips all non-digit and then does substring match in folded digits.
        // The title "+81 120 111 222" contains "81120111222" as digits; we need the
        // normalized KEY "0120111222" to be a substring of "81120111222" — it IS.
        assert!(
            rs.match_phone("+81 120 111 222").is_some(),
            "JP international format should match national-format rule"
        );
        // The national format must also still work.
        assert!(rs.match_phone("0120-111-222").is_some());
        assert!(rs.match_phone("0120 111 222").is_some());
    }

    // ── F6: glob title patterns ──────────────────────────────────────

    #[test]
    fn glob_count_reflects_parsed_rules() {
        let rs = Ruleset::from_lines(&[
            "glob: *infected*",
            "glob: WARNING: ?",
            "title: ordinary substring",
        ]);
        assert_eq!(rs.glob_count(), 2);
        assert_eq!(rs.title_count(), 1);
    }

    #[test]
    fn glob_exact_match() {
        let rs = Ruleset::from_lines(&["glob: your computer is infected"]);
        assert_eq!(
            rs.match_title_glob("your computer is infected"),
            Some("your computer is infected".to_string())
        );
        // Must NOT match a title that only contains the phrase (not full-string).
        assert!(rs
            .match_title_glob("WARNING: your computer is infected!")
            .is_none());
    }

    #[test]
    fn glob_star_both_ends_behaves_like_contains() {
        // `glob: *phrase*` is equivalent to `title: phrase`.
        let rs = Ruleset::from_lines(&["glob: *your computer is infected*"]);
        assert!(rs
            .match_title_glob("⚠ YOUR COMPUTER IS INFECTED ⚠")
            .is_some());
        assert!(rs.match_title_glob("your computer is infected").is_some());
        assert!(rs.match_title_glob("call support now").is_none());
    }

    #[test]
    fn glob_question_mark_matches_any_single_char() {
        let rs = Ruleset::from_lines(&["glob: ?irus found"]);
        assert!(rs.match_title_glob("virus found").is_some());
        assert!(rs.match_title_glob("xirus found").is_some());
        // Zero chars for `?` → no match.
        assert!(rs.match_title_glob("irus found").is_none());
        // Two chars for `?` → no match.
        assert!(rs.match_title_glob("xvirus found").is_none());
    }

    #[test]
    fn glob_star_middle_skips_arbitrary_content() {
        let rs = Ruleset::from_lines(&["glob: your*infected"]);
        assert!(rs.match_title_glob("your computer is infected").is_some());
        assert!(rs.match_title_glob("your phone is infected").is_some());
        assert!(rs.match_title_glob("your infected").is_some()); // * = zero chars
        assert!(rs.match_title_glob("your computer").is_none());
    }

    #[test]
    fn glob_empty_pattern_drops_silently() {
        let rs = Ruleset::from_lines(&["glob:   "]);
        assert_eq!(rs.glob_count(), 0);
    }

    #[test]
    fn glob_pattern_normalized_symmetrically() {
        // Pattern with leet: `c0mputer` → normalized to `computer`.
        // Title with zero-width + uppercase: matches.
        let rs = Ruleset::from_lines(&["glob: *c0mputer*infected*"]);
        assert!(rs
            .match_title_glob("your\u{200B}COMPUTER is infected!")
            .is_some());
        // Pattern with Cyrillic confusable in the display text: folds to
        // the same skeleton as the ASCII equivalent.
        let rs2 = Ruleset::from_lines(&["glob: *раypаl*"]);
        assert!(rs2.match_title_glob("verify your paypal account").is_some());
    }

    #[test]
    fn glob_match_returns_display_form() {
        let rs = Ruleset::from_lines(&["glob: *YOUR COMPUTER IS INFECTED*"]);
        // The display is stored as lowercase.
        assert_eq!(
            rs.match_title_glob("your computer is infected"),
            Some("*your computer is infected*".to_string())
        );
    }

    #[test]
    fn glob_empty_ruleset_matches_nothing() {
        let rs = Ruleset::default();
        assert!(rs.match_title_glob("any title at all").is_none());
    }

    // ── C5-3: weight overrides ────────────────────────────────────────

    #[test]
    fn weight_override_parses_and_returns() {
        let rs = Ruleset::from_lines(&[
            "weight: phone_number 99",
            "weight: mixed_script 0",
            "weight: user_initiated -10",
        ]);
        assert_eq!(rs.weight_override_count(), 3);
        assert_eq!(rs.weight_of("phone_number", 35), 99);
        assert_eq!(rs.weight_of("mixed_script", 30), 0);
        assert_eq!(rs.weight_of("user_initiated", -40), -10);
    }

    #[test]
    fn weight_of_falls_back_to_default_when_no_override() {
        let rs = Ruleset::default();
        assert_eq!(rs.weight_of("phone_number", 35), 35);
        assert_eq!(rs.weight_of("nonexistent_signal", 42), 42);
    }

    #[test]
    fn weight_override_is_case_normalised() {
        let rs = Ruleset::from_lines(&["weight: Phone_Number 50"]);
        // Signal names are lower-cased at parse time.
        assert_eq!(rs.weight_of("phone_number", 35), 50);
    }

    #[test]
    fn weight_override_malformed_value_is_silently_dropped() {
        let rs = Ruleset::from_lines(&["weight: phone_number not_a_number"]);
        assert_eq!(rs.weight_override_count(), 0);
        // Falls back to default.
        assert_eq!(rs.weight_of("phone_number", 35), 35);
    }

    #[test]
    fn weight_override_missing_value_is_dropped() {
        let rs = Ruleset::from_lines(&["weight: phone_number"]);
        assert_eq!(rs.weight_override_count(), 0);
    }
}
