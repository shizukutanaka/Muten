# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Conventional Commits](https://www.conventionalcommits.org/).

## [0.6.0] — evasion-resistant normalization + TOAD/Web3/browser-security signals (rounds 10–28)

### Fixed — concurrent-instance audit-chain corruption risk
- **No single-instance guard on `daemon`** — `ChainedFileSink::open` reads
  the chain head into in-process memory with no cross-process coordination;
  two daemon instances pointed at the same `--audit-log` would each start
  from the same head and race to append, corrupting the tamper-evident
  hash chain — silently defeating the entire point of running one. A real
  advisory lock (`flock`) isn't reachable within this crate's constraints
  (needs either a newer std API than MSRV 1.75 ships, or raw libc FFI,
  and the crate is `forbid(unsafe_code)` with no new dependencies).
  Added a best-effort, std-only, safe-Rust lock: `daemon` atomically
  creates `<audit-log>.lock` (`create_new`, POSIX `O_EXCL`) before opening
  the audit log, refuses to start if it already exists, and removes it on
  a graceful stop. Documented, not hidden: a plain file isn't a kernel-
  held lock, so it does not self-clear after an unclean kill/crash — the
  error message tells the operator to confirm no other instance is
  genuinely running before deleting a stale lock, and the 3 service-
  manager templates were updated to auto-clear the lock in their
  supervisor-invoked startup step specifically (safe there, and only
  there, because systemd/launchd/Task Scheduler each independently
  guarantee the previous instance is fully dead before restarting the
  same managed unit/agent/task — an ad-hoc script bypassing the service
  manager must not adopt the same auto-clear).
- Proven with a real two-process race, not just a unit test of the lock
  function in isolation: a new `cli_contract.rs` test spawns one daemon,
  confirms a second spawn against the same `--audit-log` is refused (exit
  1), then stops the first gracefully and confirms the lock file is
  released for a legitimate restart.

### Fixed — untested `--helper-timeout-ms` CLI wiring
- The prior round's library-level timeout tests proved `SubprocessController
  ::with_timeout` works, but nothing proved the CLI flag actually reaches
  it — a refactor could silently revert `cmd_daemon` to
  `SubprocessController::new` (the library's own 5000ms default) and no
  test would notice. Added a regression test with a tight 2-second
  threshold (deliberately far below the 5000ms default, to actually
  distinguish "the flag worked" from "the flag was silently dropped") and
  verified it has real teeth by temporarily reverting the wiring and
  confirming the test fails, then restoring it.

### Fixed — hung-helper freeze and zero-event crash in the new daemon loop
- **`SubprocessController` had no timeout** — `Command::output()` blocks
  synchronously forever; a helper hang (a broken window-manager IPC call, a
  stuck modal blocking AppleScript, a frozen COM call) would freeze the
  entire `daemon` loop, including its own graceful-stop check (the
  stop-flag is only polled *between* sweeps). Found by turning the same
  Socratic questioning on the `daemon` feature just added in the prior
  round: "what happens if the subprocess never returns?" Fixed by
  rewriting `run`/`available` to spawn, drain stdout/stderr on separate
  threads (avoiding a pipe-buffer deadlock while polling), and poll
  `try_wait` against a bounded timeout (default 5s, `with_timeout`
  constructor, `--helper-timeout-ms` CLI flag) — a hung helper is killed
  and surfaced as the new `ControllerError::Timeout` variant instead of
  blocking forever. 4 new tests prove a genuinely hung helper (`sleep
  3600`) is killed within the configured timeout, not left running.
- **`cmd_monitor`/`cmd_daemon` crashed on an all-benign run** —
  `ChainedFileSink` creates its log file lazily on the first `emit()`; a
  run where every window classifies as Allow (or, for `daemon`, an empty
  desktop) never calls `emit()` at all, so the file may genuinely never
  exist. The post-run verification/metrics code unconditionally read the
  file, so this common, healthy, zero-detection case crashed with exit 1
  instead of exiting 0 with zero counts — caught by manually running the
  exact scenario end-to-end (not just unit-testing the pieces in
  isolation). Fixed in 3 places (`cmd_monitor`'s own chain-verification
  read, `cmd_daemon`'s, and the shared `count_audit_kinds` helper both use)
  by treating a missing file the same as an empty, trivially-valid chain.
  2 new `cli_contract.rs` regression tests cover both subcommands.

### Added — `daemon` subcommand (real continuous protection loop)
- **`muten-overlay daemon <helper>`** — Socratic gap analysis found that
  `enforce`/`monitor` only ever run against `NullController` over a static
  window list (dry-run/demo tooling), while `SubprocessController` (real
  helper invocation) and `Monitor::run`/`Monitor::sweep` (a fully generic,
  production-ready continuous loop with adaptive interval and a signal-free
  file-based stop mechanism) already existed in the library, fully tested,
  but nothing in the shipped binary ever wired them together. There was no
  way to actually run muten-overlay as a live protective agent on a real
  machine.
- Probes the helper once at startup and fails fast (exit 1) rather than
  looping forever against a broken helper; loops `Monitor::sweep` unbounded
  against a real wall clock and a real `--stop-flag` file
  (`--interval-ms`/`--alert-interval-ms`/`--audit-log`/`--stop-flag`/
  `--metrics`); writes an honest `muten_sweeps_total` Prometheus counter on
  graceful shutdown (hand-rolled sweep loop rather than calling
  `Monitor::run` directly, since `run` only returns the dismissed count).
- Verified end-to-end against a real fake-helper subprocess (not just unit
  tests of the library pieces in isolation): 2 new `cli_contract.rs`
  integration tests spawn the actual binary, drive it through several real
  sweeps, trigger a graceful stop via the flag-file convention, and assert
  the resulting audit log is a valid verifiable hash chain and the metrics
  file reflects real, non-zero activity.
- **`installer/overlay-helper/`** gained the actual deployment artifacts
  the product's own docs promised ("pushed via MDM") but never shipped:
  a systemd unit (`muten-overlay.service`), a macOS launchd agent
  (`com.muten.overlay.plist`), a Windows Scheduled Task
  (`muten-overlay-task.xml`), and a `README.md` documenting the
  Intune/Jamf/GPO/Ansible push pattern for each, plus the shared
  signal-free graceful-stop convention (touch a stop-flag file; the daemon
  exits 0 on its own within one sweep interval).

### Added — new detection signal (E66)
- **`notification_permission_bait`** (W=20, InterfaceInterference) — fake content-gate
  behind the browser's native notification-permission prompt: "Click Allow to continue
  watching / download / access" with no CAPTCHA framing at all (distinct from
  `clickfix_instruction`'s "not a robot" / "verify human" vocabulary, which does not
  cover this variant). Once granted, the site can push OS-level fake system alerts
  persistently, even with the browser closed — a distinct 2025-2026 growth vector
  ("Matrix Push C2", Malwarebytes Nov 2025) from ClickFix's clipboard-paste technique.
  Full 10-lens wiring: T1566 Phishing, Extract lifecycle stage, DeviceTakeover
  extraction (Mitigable), Medium magnitude, General victim profile; exempt from the
  persuasion lens as an action/gate mechanic (like `download_trap_lure`/`qr_code_lure`).

### Added — new detection signals (E63–E65)
- **`toad_case_number_lure`** (W=20, InterfaceInterference) — TOAD (Telephone-Oriented
  Attack Delivery) fingerprint: fake case/ticket/incident ID paired with "call now" /
  "call support" CTA. Proofpoint 2022/2024 data shows 554 % YoY surge in TOAD
  campaigns. Full 10-lens wiring: Authority persuasion, Pressure lifecycle stage,
  T1566 Phishing, General victim profile.
- **`wallet_connect_popup_lure`** (W=30, InterfaceInterference) — Web3 wallet-drainer
  popup: wallet-connect verb (connect MetaMask / link wallet / authorize wallet) +
  reward hook (claim airdrop / free NFT / token airdrop). IC3 2024 #1 loss category
  ($4.57 B). Full 10-lens wiring: Scarcity persuasion, Extract lifecycle, T1566,
  Cryptocurrency extraction (Irreversible), Catastrophic magnitude, CryptoInvestor
  victim profile.
- **`fake_browser_security_warning`** (W=25, InterfaceInterference) — Fake browser
  cert/SSL error + scam CTA (call support / click to fix / download security).
  Impersonates Chrome/Firefox/Edge/Safari security error pages. Full 10-lens
  wiring: Authority persuasion, TrustBuild lifecycle, T1036 Masquerading, TechVendor
  impersonation family, General victim profile.

### Fixed
- **`remote_access_lure` trigger gap** — `fake_alert_present` guard was limited to 3
  signals (blocklist_title, phone_number, clickfix_instruction). A fake BSOD + RAT
  lure would miss `remote_access_lure`. Widened to 11 signals, adding fake_bsod_lure,
  fake_scanner_cue, windows_defender_alert_lure, ip_alarm_lure, av_brand_renewal_scam,
  tech_support_invoice_scam, windows_activation_scam.
- **CONTENT_SIGNALS coverage gap** — 10 signals present in `all_signals()` were missing
  from `CONTENT_SIGNALS`, so the full-wiring coverage guard `every_content_signal_is_
  fully_wired()` silently skipped them. Added all 10 to the list (alarm_density,
  task_app_scam, software_subscription_scam, dark_web_breach_lure, cloud_quota_lure,
  windows_defender_alert_lure, tech_support_chat_lure, plus the 3 new E63–E65 signals).
- **MITRE ATT&CK mappings** — 7 signals (alarm_density, task_app_scam, software_
  subscription_scam, dark_web_breach_lure, cloud_quota_lure, tech_support_chat_lure,
  windows_defender_alert_lure) lacked MITRE technique entries, causing the now-active
  coverage guard to fail. Mapped to T1566 (Phishing) for 6 social-engineering signals
  and T1036 (Masquerading) for windows_defender_alert_lure.
- **2 broken rustdoc links** — `[fold_letter_digits_for_phone]` (rules.rs) and
  `[normalize_for_match]` (lib.rs) referenced private functions; changed to backtick-
  only code spans. `cargo doc --no-deps` now produces 0 warnings.
- **`crypto_drain_lure` false positive** — the `wallet_coerce` sub-pattern fired on
  bare "connect" + any wallet word (wallet/metamask/coinbase/web3/defi/nft) with no
  alarm or reward context. "Connect Wallet" is the universal, always-benign primary
  CTA on every legitimate Web3 dApp (Uniswap, OpenSea, MetaMask itself); confirmed via
  the `benign_corpus` adversarial-benign test harness. Removed "connect" from the
  coercion-verb list — genuine drainer patterns remain caught via `wallet_alarm`
  (connect + alarm word) and the new `wallet_connect_popup_lure` (connect + reward
  hook).
- **`cloud_quota_lure` false positive** — generic quota wording ("storage is full",
  "storage almost full", "upgrade your plan") is the verbatim text of Apple's and
  Google's own real, legitimate low-storage notifications (e.g. Apple's actual
  notification title "iCloud Storage Almost Full"), so a phishing overlay mimicking
  that UI could never be distinguished from the real thing by content alone. Redesigned
  as a two-tier AND-pair: an explicit deletion/loss consequence ("your photos will be
  deleted" — language real first-party copy avoids) fires alone; generic quota wording
  now additionally requires explicit sign-in/urgency pressure ("verify your account",
  "act now") that a passive OS notification never applies.

### Improved
- **Japanese alarm_density vocabulary** — Added 6 high-confidence Japanese fear-words
  sourced from IPA 2024 サポート詐欺 advisory and JPCERT/CC corpus: ウイルス (virus),
  マルウェア (malware), 凍結 (frozen/locked), 危険 (danger), ランサムウェア (ransomware),
  トロイ (Trojan). Previously these JP-only scam titles would fall below the 3-word
  threshold; now they correctly fire alarm_density.
- **`#[non_exhaustive]` on 6 public enums** — DarkPatternCategory, Origin, ScamStage,
  VictimProfile, ExtractionVector, AbusedAuthority. Prevents semver-breaking changes
  when future signal families add new variants (roadmap C5-5).
- **docs.rs metadata** — Added `[package.metadata.docs.rs]` with `all-features = true`
  and `rustdoc-args = ["--cfg", "docsrs"]` so docs.rs generates docs for all features.

### Documentation
- `docs/OVERLAY_BLOCKING.md` scoring table was missing 27 of 64 signals (everything
  added after `loan_fee_scam`) — added one row per signal, each individually verified
  against the actual `W_*` weight constant, detector doc comment, `category_of()`, and
  `techniques_of()` mapping. Also fixed a stale `remote_access_lure` row describing the
  old 3-signal trigger.

### Tests
- 1 323 unit tests + 19 `cli_contract` integration tests (up from 1 308
  unit-test baseline for this cycle), 0 failures, clippy-clean.

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
