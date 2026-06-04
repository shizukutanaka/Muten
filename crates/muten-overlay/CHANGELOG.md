# Changelog — muten-overlay

Follows [Keep a Changelog](https://keepachangelog.com/) and
[Conventional Commits](https://www.conventionalcommits.org/). This is
the crate that adds the "screen" half of muten's v0.4.0 endpoint
environment enforcement (scam-overlay + rogue-AV detection).

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
