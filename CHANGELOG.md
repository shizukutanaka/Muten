# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Conventional Commits](https://www.conventionalcommits.org/).

## [0.6.0] — evasion-resistant normalization (rounds 10–23)

A long, additive hardening cycle for the homoglyph / text-evasion defence.
Each round asked "what would an attacker who read our source code exploit
next?" and closed the gap, staying offline, pure, `forbid(unsafe_code)`,
dependency-free, MSRV 1.75, and false-positive-averse throughout. See
`docs/SPECIFICATION_V2.md` for the full coverage table and methodology.

### Added — confusable folding (`fold_char` / `normalize_for_match`)
- **Mathematical Alphanumeric Symbols** (U+1D400–U+1D7FF): all 16 letter
  styles (bold/italic/script/fraktur/double-struck/sans/mono), incl. the
  hole-filling Letterlike characters.
- **Greek** completeness: lowercase η/τ/ω/γ/μ, lunate sigma ϲ/Ϲ, yot ϳ,
  uppercase Ω, π/Π, ζ; **Coptic** block (U+2C80–U+2CB1, 30 letters);
  **Armenian** strong homoglyphs (օ/Օ→o, ո→n, ս→u, հ→h, յ→j); extended
  **Cyrillic** Supplement (һ, Ӏ, ԁ, ԛ, ԝ).
- **Small-capital / phonetic** letters (IPA, Phonetic Ext., Latin Ext-D),
  **Roman numeral** single-letter forms, **enclosed/circled** letters,
  **fullwidth** ASCII, **script decimal digits**, **circled/superscript
  digits**, **dash variants**, katakana middle dot.
- **Superscript/subscript/modifier** Latin letters (U+2071, U+207F,
  U+2090–U+209C, U+02B0–U+02E3).
- **NFKD-authoritative compat folds**: every codepoint Unicode declares
  compatibility-equivalent to a single ASCII letter (long-s ſ, Kelvin
  sign K, ⱼ, ꟴ, …). Ordinal indicators ª/º deliberately *not* folded
  (legitimate Spanish/Portuguese ordinals).

### Added — detection signals & pipeline
- `normalize_for_match` 11-step pipeline (bound → strip emoji → expand
  ligatures → fold halfwidth katakana → fold unicode spaces → strip
  invisibles → strip combining marks → fold confusables → collapse spaces
  → collapse spread-characters → fold leet → lowercase).
- `collapse_spread_characters`: rejoins ≥4 single-char spread words; R23
  expanded the separator set (`= # ; \ !` and dot-operators ‧ ∙ ⋅),
  keeping `:`/`+` excluded for countdown timers / Win+R shortcuts.
- `has_confusable_mixed_script`, `has_whole_script_confusable`,
  `has_compat_alpha` (incl. small-cap runs), `has_bidi_override`,
  `has_mixed_number_systems`, `has_excessive_combining_marks`.
- Dozens of scam-content detectors (clickfix, urgency countdown, forced
  retention, credential harvest, fake scanner, sextortion, gift-card,
  refund, tax-authority, pig-butchering, and many more).

### Changed
- `Script` enum is now `#[non_exhaustive]` and gained `Coptic` / `Armenian`
  variants (downstream exhaustive matches must add a wildcard arm).

### Tests
- ~1,053 unit tests + 242 scoring scenarios + extensive property tests
  (every detector: never-panic + no-false-positive invariants).

## [0.5.0] — mixed-script detection & explainability

### Added
- Mixed-script homoglyph signal, zero-width / BiDi stripping, leetspeak
  folding for blocklist matching.
- `Verdict::explain()` natural-language rationale; CLI `--json` output.
- `Sneaking` category mapping for `mixed_script`.

## [Unreleased] — v0.4.0 (product redefinition)

### Changed (BREAKING — product scope)
- **muten is redefined from "PC forced-mute" to "endpoint environment
  enforcement (audio + screen)".** The audio enforcement is unchanged
  and fully backward compatible; the product now *also* detects scam /
  full-screen overlay windows on the same managed PCs. README and
  positioning updated accordingly. See `Plan.md` for the scope
  decision and `docs/OVERLAY_BLOCKING.md` for the design.

### Added
- **`muten-overlay` crate** — pure-domain scam-overlay classifier
  (`forbid(unsafe_code)`, no OS, no network):
  - `OverlayWindow` observation type (title, url, coverage, topmost,
    close button, input capture, origin, age).
  - `classify()` — explainable additive-score heuristic with named
    weights; returns `Verdict { decision, score, signals, matched_rule }`.
  - `Decision`: `Allow` / `Suspicious` (audit, don't dismiss) / `Block`.
  - Offline `Ruleset` blocklist (host + subdomain matching, title
    substring patterns, comments, bare-host lines). Pushed via MDM,
    read offline.
  - `muten-overlay` dry-run CLI: `classify` (exit 0/5/6) and `rules`.
  - 18 unit tests + 7 property tests (~1,800 random cases): classifier
    never panics, score monotone in each suspicious signal, decision
    thresholds consistent, blocklist parser never panics, subdomain
    matching, hard-block on host hit.
- Example blocklist (`examples/overlay-blocklist.txt`) and sample scam
  observation (`examples/overlay-sample.json`).
- `docs/OVERLAY_BLOCKING.md`.

### Design notes
- **Observe-first**: default posture flags suspicious overlays for IT
  review rather than auto-dismissing, because false positives would
  break legitimate full-screen apps (video, presentations, exams,
  kiosk UIs). Only confirmed blocklist hits or unmistakable scores
  (≥100) yield `Block`.
- **No ML**: transparent, auditable scoring per CLAUDE.md I6 / Pike.
- **Privacy (I5)**: classification is fully on-device; no window
  metadata leaves the machine.

### Pending (next session)
- OS-specific window enumerator + dismisser (like the audio backends).
- Merge `muten-overlay` into the restored workspace + wire daemon to
  emit `OverlayBlocked` / `OverlaySuspicious` audit events into the
  hash chain.
- New `EventKind::OverlayBlocked` / `OverlaySuspicious` + SIEM severity
  mapping.
- README full rewrite around the "audio + screen" positioning.

## [0.3.x] / [0.3.0] / [0.2.0] / [0.1.x]

(Prior audio-enforcement history — preserved in earlier transcripts
and the restored workspace.)
