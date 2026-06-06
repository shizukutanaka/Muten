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
