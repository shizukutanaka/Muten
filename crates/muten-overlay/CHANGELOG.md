# Changelog — muten-overlay

Follows [Keep a Changelog](https://keepachangelog.com/) and
[Conventional Commits](https://www.conventionalcommits.org/). This is
the crate that adds the "screen" half of muten's v0.4.0 endpoint
environment enforcement (scam-overlay + rogue-AV detection).

## [0.5.0] — unreleased

Evasion-resistant detection + explainability. Additive and
backward-compatible: the JSON verdict gains fields, no existing field
changes meaning. No new dependencies; still offline, pure,
`forbid(unsafe_code)`.

### Added
- **`#![deny(missing_docs)]`** enforced on the crate. All public items
  (struct fields, enum variants, trait methods, constants) now carry doc
  comments; `cargo doc --no-deps` builds cleanly at error level. (C3-2.)
- **Excessive-combining-mark signal** (`excessive_combining_marks`, weight
  20, `Sneaking` category). Fires when the raw title or host stacks **3 or
  more** combining marks on a single base character — the "Zalgo" text
  obfuscation used to corrupt a UI or evade substring matching. The
  threshold of 3 is the false-positive guard: legitimate scripts
  (Vietnamese, Arabic, Indic, IPA) stack at most one or two combining
  marks, and precomposed accented text (`café`) has none. New public
  functions `confusables::{is_combining_mark, has_excessive_combining_marks}`.
  (C8-7.)
- **Mixed-number-system signal** (`mixed_number_systems`, weight 20,
  `Sneaking` category). Fires when one whitespace-delimited token mixes
  decimal digits from two numbering systems — e.g. ASCII `5` beside
  Arabic-Indic `٥` (U+0665) — which no legitimate number does (ICU
  `SpoofChecker.MIXED_NUMBERS`). ASCII and full-width digits are treated
  as the same system, so legitimate Japanese full-width numerals beside
  ASCII are not flagged (JP false-positive guard). New public functions
  `confusables::{digit_system, has_mixed_number_systems}`. (C8-6.)
- **Enclosed/circled letter signal** (`compat_chars_present`, weight 20,
  `Sneaking` category). Detects and folds enclosed/circled Latin letters
  (Ⓐ–Ⓩ / ⓐ–ⓩ, U+24B6–U+24E9) used in phishing to evade plain-text
  blocklist matching: `ⓟⓐⓨⓟⓐⓛ` looks like "paypal" but `str::contains`
  misses it. `fold_char()` now folds this range so `normalize_for_match`
  automatically catches these in title matching; `has_compat_alpha()` detects
  their presence in raw text as a high-confidence, near-zero-FP signal
  (enclosed letters have essentially no legitimate use in window/document
  titles). New public function `confusables::has_compat_alpha()`. (C8-8.)
- **Whole-script confusable signal** (`whole_script_confusable`, weight 30,
  `Sneaking` category). Catches the blind spot of `mixed_script`: a token
  (or URL host label) that is entirely Cyrillic or Greek where **every**
  letter folds to an ASCII look-alike — e.g. `ѕсоре` (all Cyrillic, reads
  "scope") — contains zero Latin characters so a cross-script mix never
  fires, yet is indistinguishable from English to a human (UTS#39 §5). The
  FP guard: legitimate Cyrillic/Greek text contains letters without ASCII
  confusable mappings (`п`, `θ`, …), which fail the fold-to-ASCII check
  and are silently skipped. For URLs the check operates per dot-separated
  label (the TLD otherwise supplies Latin letters). New public function
  `confusables::has_whole_script_confusable()`. Also fixes a pre-existing
  ETXTBSY race in controller tests (fsync before exec under parallel
  threads). (Roadmap C8-3.)
- **Mixed-script evasion signal** (`mixed_script`, weight 30). A single
  token mixing Latin with Cyrillic/Greek letters (e.g. `раypаl`,
  `miсrosoft`) is flagged as a homoglyph-disguise tell (UTS #39
  mixed-script confusables; NDSS 2015 typosquatting). Evaluated on the
  **raw** title and the URL host — never CJK/Kana, so legitimate
  Japanese+Latin titles are not flagged. Maps to the `Sneaking`
  dark-pattern category (previously unmapped). The signal nudges toward
  `Suspicious`; it never blocks alone. (Roadmap C8-4, C9-1.)
- **Text-normalization pipeline** for blocklist title matching
  (`confusables::normalize_for_match`): strips zero-width / BiDi-control
  characters (C8-5/C8-9), folds confusables, and restores leetspeak
  digits inside words (`v1rus`→`virus`, `1nfected`→`infected`) while
  leaving pure-digit runs — phone numbers, counts — untouched (C8-6).
  Host matching now also strips invisibles. Phone-number scanning is
  unchanged (it deliberately keeps the original digits).
- **`input_trap` composite signal** (weight 5, `ForcedAction` category) —
  fires when a window is full-screen AND topmost AND input-grabbing: the
  shape of a browser/screen locker (Keyboard-Lock/Pointer-Lock abuse,
  CypherLoc-style scareware). The bonus is bounded so the bare lock shape
  with no content/provenance tell stays `Suspicious` (95 < 100) — kiosk
  shells and exam lockdown browsers with unknown origin are observed, not
  auto-dismissed. Surfaces the lock in `explain()` and the audit log.
- **`brand_impersonation` signal** (weight 40, `InterfaceInterference`)
  — a zero-config UTS#39 skeleton-collision guard. A host label whose
  confusable skeleton equals a built-in known brand but is not the
  literal brand (e.g. `раура1.com` → `paypal`) is flagged, while the
  real brand domain never fires. Catches homograph/typosquat domains a
  deployment hasn't (and shouldn't) blocklisted. New
  `confusables::skeleton()`. Additive (not an auto-block), consistent
  with `blocklist_title`. (Roadmap C8-2.)
- **`bidi_override` signal** (weight 30, `Sneaking`) — flags a BiDi
  directional **override** (`U+202D`/`U+202E`) in the raw title or host:
  the "Trojan Source" (arXiv:2111.00169) / RLO filename-spoof vector that
  makes displayed text read differently from the logical bytes. muten
  already strips these for matching; this surfaces their *presence* as a
  distinct, near-zero-false-positive tell (overrides have no honest use
  in a title — legit RTL text uses letters/marks/isolates, which do not
  fire). New `confusables::has_bidi_override()`. (Roadmap C8-5.)
- **`sudden_fullscreen_takeover` composite signal** (weight 5) — fires
  when an *unsolicited* window seizes the full screen, on top, the
  instant it appears (real nonzero age < 1s). The behavioural tell Edge
  Scareware Blocker keys on; muten's no-CV way to flag brand-new scam
  domains the blocklist hasn't caught yet. Bounded so the bare pattern
  stays `Suspicious` (85 < 100).
- **`Verdict::explain()`** — a deterministic, plain-language sentence
  describing why a verdict was reached, assembled from the signals that
  fired (CLAUDE.md I6 / roadmap C5-8).
- **`--json` on every decision subcommand** — `classify`/`scareware`
  emit a verdict object (classify adds an `explanation` field and a
  `why:` line in text mode); `enforce` emits a JSON array of per-window
  outcomes; `monitor` emits the audit-event document, or a verifiable
  `{sweeps, dismissals, event_count, head, verified}` summary with
  `--audit-log`. Exit codes unchanged. `tests/cli_contract.rs` covers the
  JSON schema + exit codes end to end. (Roadmap C4-2.)
- **Documented exit codes in `--help`** and a normative
  `docs/SPECIFICATION.md`; `OverlayWindow` now `#[serde(default)]` so
  partial window JSON (a helper omitting an undeterminable field) parses
  instead of erroring.
- **Audit log survives a crash mid-write.** `ChainedFileSink::open` now
  recovers a *torn final line* (a partial append with no trailing
  newline) by dropping it and resuming from the surviving prefix — iff
  that prefix still verifies. A tampered *complete* line still refuses to
  open, so tamper-evidence (S3) is preserved. Previously a single crash
  bricked the log forever.
- New public API: `confusables::{strip_invisibles, normalize_for_match,
  has_confusable_mixed_script, fold_leet_in_words, script_of, Script}`.
- ~30 new unit + property tests (160 total, up from 141): invisibles
  stripping, leet-in-words vs. phone digits, within-token mixed-script
  detection, the Japanese+Latin false-positive guard, and `explain()`
  well-formedness over random windows.

## [0.4.0] — unreleased

### Added
- GitHub Actions CI (fmt/clippy/test/doc, MSRV 1.75 build, cargo-audit
  + cargo-deny + gitleaks supply-chain gate, helper shell/PS lint),
  `deny.toml` license allow-list, `.gitleaks.toml` secret-scan config.
- `AuditEvent.timestamp_ms` (logical event time), folded into the
  hash chain so events cannot be backdated; chain line format gains a
  `timestamp_ms` field. Required for incident-timeline reconstruction.
- `LICENSE` (MIT) and complete `Cargo.toml` publish metadata
  (repository, readme, keywords, categories); `cargo package` passes.
- Dark-pattern strategy categories (Gray et al. 2018) on `Verdict` and
  audit events; `phone_number` signal (Miramirkhani et al. NDSS 2017).
- `classify()` — explainable additive-score overlay classifier with
  named signal weights; `Verdict { decision, score, signals,
  matched_rule }`. `Decision`: Allow / Suspicious (audit, never
  dismiss) / Block.
- `Ruleset` — offline blocklist with `host:` (suffix/subdomain match),
  `title:` (substring), and `process:` (space-insensitive, for
  rogue-AV) rules. Comments and bare-host lines supported.
- `scareware` module — `RepeatTracker` (sliding-window flood
  detection) + `assess()` (repeat-flood and rogue-AV-process signals).
- `controller` module — `OverlayController` trait (enumerate +
  dismiss), `NullController` (dry-run), and `SubprocessController`
  (per-OS helper over a 3-verb protocol). muten stays
  `forbid(unsafe_code)`; all FFI lives in the swappable helper.
- `monitor` module — `Monitor::sweep()` / `Monitor::run()` periodic
  loop with injected clock + stop flag; emits `overlay_blocked`,
  `overlay_suspicious`, `scareware_detected`, `overlay_sweep_error`
  audit events. `AuditSink` trait + `MemorySink`.
- `sink` module — `ChainedFileSink`, a self-contained SHA-256
  hash-chained audit log (on-disk format compatible with
  `muten-audit-chain`) + `verify_chain`. Refuses to append onto a
  tampered log (threat-model S3).
- `enforce()` — stateless one-shot enumerate→classify→dismiss helper.
- `signature()` — crate-defined repeat-detection key (title + host).
- `muten-overlay` CLI: `classify`, `rules`, `scareware`, `enforce`,
  `monitor`.
- 2026 threat-informed example blocklist (53 title + 5 host + 14
  process rules) and reference OS helpers for Linux/X11 (wmctrl),
  Windows (Win32 P/Invoke), and macOS (osascript).

### Fixed
- **Scareware false positive**: a user-initiated window kept on screen
  across sweeps tripped `repeated_flood`. The monitor now counts only
  *unsolicited* appearances toward the flood signal; the rogue-AV
  *process* signal still fires regardless of origin.
- **`very_new` noise**: `age_ms == 0` (the helpers' "age unknown"
  default) was scored as "brand new", adding +10 to every window. Now
  only a real, small, nonzero age counts as `very_new`.

### Design notes
- Observe-first / false-positive-averse: only confirmed blocklist hits
  or unmistakable scores (>=100) yield Block; everything else is
  audited and left alone.
- No ML — transparent additive scoring (CLAUDE.md I6 / Pike).
- Detect & audit only for scareware (CLAUDE.md I9); muten never kills
  processes or edits the registry — that's the EDR's job.

### Tests
82 tests: unit + 4 property-test suites (classifier monotonicity &
threshold consistency, blocklist parser, scareware repeat counting,
monitor sweep invariants), ~hundreds of generated cases each.
