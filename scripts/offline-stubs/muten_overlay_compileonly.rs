//! Compile-only stand-in for `muten_overlay`. Provides just the surface
//! tests/benign_corpus.rs names. `classify` returns an empty verdict, so
//! this verifies COMPILATION ONLY — never behaviour.
#[path = "/home/user/Muten/crates/muten-overlay/src/confusables.rs"]
pub mod confusables;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Origin { #[default] Unknown, UserInitiated, Unsolicited }

#[derive(Debug, Clone, Default)]
pub struct OverlayWindow {
    pub title: String,
    pub url: Option<String>,
    pub coverage_percent: u8,
    pub topmost: bool,
    pub has_close_button: bool,
    pub blocks_input: bool,
    pub origin: Origin,
    pub age_ms: u64,
}

#[derive(Debug, Default)]
pub struct Ruleset;
impl Ruleset {
    pub fn from_lines(_l: &[&str]) -> Self { Ruleset }
    pub fn parse(_s: &str) -> Self { Ruleset }
}

#[derive(Debug, Default)]
pub struct Verdict {
    pub decision: Decision,
    pub score: i32,
    pub signals: Vec<String>,
    pub matched_rule: Option<String>,
}

pub fn classify(_w: &OverlayWindow, _r: &Ruleset) -> Verdict { Verdict::default() }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Decision { #[default] Allow, Suspicious, Block }

pub const BLOCK_THRESHOLD: i32 = 100;
pub const SUSPICIOUS_THRESHOLD: i32 = 50;
