# Changelog — muten-overlay

Follows [Keep a Changelog](https://keepachangelog.com/) and
[Conventional Commits](https://www.conventionalcommits.org/). This is
the crate that adds the "screen" half of muten's v0.4.0 endpoint
environment enforcement (scam-overlay + rogue-AV detection).

## [0.6.0] — unreleased

Composite AND-condition rules, canonical audit-chain hashing, NDJSON streaming
classify, build-info version, MITRE ATT&CK® technique tags, composite weight
guard, and expanded rogue-AV families. **API break**: `Verdict.signals` and
`EnforceOutcome.signals` change from `Vec<&'static str>` to `Vec<String>`;
`Verdict` gains a new `mitre_techniques: Vec<String>` field. No new
dependencies. All constraints preserved: offline, pure, `forbid(unsafe_code)`,
MSRV 1.75, 286 tests.

### Changed
- **Full-wiring meta-guard for content signals** (structural hardening; Gap C).
  Audited every detection signal's four metadata wirings (score weight,
  dark-pattern category, MITRE ATT&CK technique, `explain()` phrase) and found
  all 51 content signals fully and principled-ly wired — the only signals
  without a category/MITRE mapping are pure window-geometry descriptors
  (`fullscreen`, `topmost`, `unsolicited`, `very_new`, `user_initiated`,
  `sudden_fullscreen_takeover`), which correctly carry no dark-pattern strategy.
  To prevent future drift, the curated content-signal list is now a single
  `CONTENT_SIGNALS` source of truth (previously duplicated inline inside the
  registry test), and a new `every_content_signal_is_fully_wired` guard iterates
  it asserting all four mappings are present for every content signal. This
  turns "added a detector but forgot one of its four mappings" from a latent
  shipping bug into a localized test failure. 1204 tests total.

### Added
- **OTP / 2FA code-relay account-takeover scam** (`otp_interception_scam`; E61).
  `has_otp_interception_scam(s)` fires when the normalized title contains both an
  *OTP/code cue* (verification code, one-time code/password, OTP, 2FA/
  authentication code, "code we just sent", 認証コード, ワンタイムパスワード, etc.)
  AND a *relay demand* — an instruction to **share / read / give / tell /
  provide** the code to the page or caller (share the code, read us the code,
  tell us the code, コードを共有, コードを教えて, etc.). The relay framing is the
  decisive near-zero-FP tell: a legitimate two-factor flow has the user *enter*
  a code they requested into its own form — it never asks them to *share*, *read
  aloud*, or *give* the code to anyone. Attackers who triggered a real OTP with
  a stolen password need the victim to relay it in real time. Distinct from
  `credential_harvest_cue` (password/account-suspended framing), asserted by a
  distinctness test. FTC Consumer Sentinel 2024 OTP fraud; FBI IC3 2024
  account-takeover; 警察庁/IPA ワンタイムパスワード詐欺 advisory 2024. Weight
  `W_OTP_INTERCEPTION_SCAM = 30`. Category: InterfaceInterference. MITRE: T1566.
  10 confusables unit tests + 3 lib unit tests + 2 property tests + 4 scoring
  scenarios + 1 JP-normalization invariant; 1203 tests total. (E61.)
- **Cryptocurrency giveaway / coin-doubling scam** (`crypto_giveaway_scam`; E60).
  `has_crypto_giveaway_scam(s)` fires when the normalized title contains both a
  *giveaway/doubling cue* (crypto/bitcoin/ETH giveaway, official giveaway,
  doubling event, "we are giving away", Elon Musk / Tesla / Binance / Coinbase
  giveaway, "first 1000 participants", 仮想通貨プレゼント, ビットコイン配布, etc.)
  AND a *send-to-receive demand* (send to this address, send any amount, double
  your bitcoin/crypto/ETH, get 2x back, receive double, send 0., 送れば倍,
  送金すると2倍, 倍にして返金, etc.). The defining tell of the coin-doubling
  fraud — fake celebrity/exchange "giveaway" livestreams — is that the victim
  must *send* crypto first to "receive" a doubled amount back; no legitimate
  giveaway requires an upfront transfer. Distinct from `crypto_drain_lure`
  (seed-phrase / wallet-connect theft) and `pig_butchering_lure` (romance/mentor
  recruitment into a fake platform). FTC Consumer Sentinel 2024 crypto
  impersonation fraud; FBI IC3 2024; 消費者庁 暗号資産詐欺 advisory 2024. Weight
  `W_CRYPTO_GIVEAWAY_SCAM = 30`. Category: InterfaceInterference (exchange/
  celebrity impersonation). MITRE: T1566. 10 confusables unit tests + 3 lib unit
  tests + 2 property tests + 4 scoring scenarios + 1 JP-normalization invariant;
  1183 tests total. (E60.)
- **Composite AND-condition rules** (`composite: <name> <weight> <cond1> …`
  in the blocklist; C5-2). A blocklist line like
  `composite: kiosk_lockdown 60 fullscreen topmost blocks_input unsolicited`
  fires when **all** listed conditions hold simultaneously, adds `weight` to the
  score, and pushes the operator-chosen `name` into the `signals` list. The 11
  supported conditions cover window geometry, origin, existing blocklist signals,
  and phone presence. Rules with zero recognized conditions are silently dropped.
  Allows operators to express YARA/Sigma-style intent without code changes;
  condition names map cleanly to `CompositeCondition` variants in `rules.rs`.
  Public API: `rules::{CompositeCondition, CompositeRule}`,
  `Ruleset::{composite_count, composite_rules}`. (C5-2.)
- **NDJSON streaming classify** (`classify --stream`; M4). When `--stream` is
  set, the `window` argument is read line-by-line (use `-` for stdin). Each
  non-empty line is parsed as an `OverlayWindow` JSON object; one verdict JSON
  object is written to stdout per line (NDJSON format, includes `explanation`).
  Exit code is the worst verdict seen (0 all-Allow, 5 any-Suspicious, 6
  any-Block). Zero-allocation per-line path; directly consumable by
  `jq`, Elastic, Splunk, and any SIEM with NDJSON ingest. (M4.)
- **Build-info in `--version`** (`build.rs`; M6). `muten-overlay --version`
  now prints `0.6.0 (commit abc1234)`. A `build.rs` captures the short git
  commit hash at compile time via `git rev-parse --short HEAD`; the result is
  embedded as the `MUTEN_GIT_COMMIT` compile-time env var. Falls back to
  `"unknown"` in environments without git. `cargo:rerun-if-changed` is wired
  to `.git/HEAD` and `.git/refs/heads/` so the version re-embeds on every
  commit. (M6.)

- **Audit canonical round-trip guard for complex `detail`** (Socratic round 13).
  The hash chain takes its hash over the canonical form of each event's `detail`
  and recomputes it on `verify_chain`, so any drift in how a non-trivial `detail`
  is serialized would make a legitimate log fail to verify. Every existing
  write→verify test used a single-key ASCII detail (`{"x":id}`), leaving
  `write_canonical`'s nested-object, array, number, and non-ASCII/escaped-string
  paths unexercised through the real emit→read→verify cycle. New
  `verifies_complex_unicode_detail_round_trip` emits an event whose detail mixes
  a nested object, an array, a number, Japanese text, and a string with
  quotes/backslashes, confirms the chain verifies, and confirms a one-byte
  tamper inside that detail breaks it — guarding the tamper-evidence claim
  against a canonicalization regression. 1163 tests total.
- **`enforce` dismiss-failure resilience guard** (Socratic round 12). `enforce`
  does `controller.dismiss(id).unwrap_or(false)`, so a dismiss returning `Err`
  (helper crash, permission denied) or `Ok(false)` (the user closed the window
  first) folds into `dismissed = false` *without* aborting the sweep — otherwise
  one failed dismiss would abandon every other scam window in the same tick. All
  existing enforce tests used `NullController`, whose `dismiss` always returns
  `Ok(true)`, so this documented contract was never exercised. New
  `enforce_survives_dismiss_failures_without_aborting` feeds two hard-host-block
  windows through a controller that fails both dismisses and asserts enforce
  still returns `Ok` with both outcomes, each `decision == Block` but
  `dismissed == false`. 1162 tests total.
- **`score_breakdown()` doc accuracy + behavior guard** (Socratic round 11).
  A hot-path panic hunt (untrusted window titles, `forbid(unsafe_code)`) and the
  existing `*_never_panics` property tests confirmed the detection/normalization/
  host-parsing paths are panic-safe and adequately fuzzed — no change needed
  there. But `score_breakdown()`'s doc listed only "composite rules or score
  clamping" as reasons its sum may differ from `Verdict::score`, omitting
  operator `weight:` overrides: the method reports built-in **default** weights
  (a `Verdict` carries no `Ruleset`), so under an override the breakdown
  deliberately differs from the actual score. The doc now states this, and
  `score_breakdown_reports_default_weights_not_overrides` pins the contract
  (override fullscreen→60, breakdown still reports 30, sum ≠ score). 1161 tests
  total.
- **Scareware sliding-window boundary guard** (Socratic round 10).
  `RepeatTracker` prunes appearances with `t >= cutoff` (`cutoff = now −
  window_ms`), so an appearance *exactly* `window_ms` old is still inside the
  window and one tick older falls out. The existing test only checked an event
  far outside the window, so flipping `>= cutoff` to `> cutoff` — shrinking the
  window by one tick, enough to miss a flood whose appearances are spaced
  exactly `window_ms` apart — would pass it. New
  `sliding_window_boundary_is_inclusive_of_exactly_window_ms` pins both sides of
  the exact edge via the non-mutating `count`. 1160 tests total.
- **Scareware flood-threshold boundary guard** (Socratic round 9). `assess`
  flags a flood at `repeat_count >= REPEAT_THRESHOLD` (3). The existing tests
  covered count 1 (Benign) and count 3 (= threshold, Scareware) but skipped the
  decisive lower edge — count 2, the last *benign* count. Lowering the threshold
  to 2 or weakening the comparison to `>= REPEAT_THRESHOLD - 1` would still pass
  those tests while turning a legitimate app that merely pops up twice into a
  false "flood" — a false positive on the scareware path the FP-averse design
  must avoid. New `flood_threshold_boundary_one_below_is_benign` pins both edges
  relative to the constant (THRESHOLD−1 → Benign, THRESHOLD → Scareware) so it
  stays correct if the threshold is retuned. 1159 tests total.
- **Phone-number digit-count boundary guard** (Socratic round 8).
  `contains_phone_number` fires on a run of `(7..=15)` digits, inclusive at both
  ends — but every existing test used 10–11-digit numbers (well inside) or a
  4-digit year (well below), so flipping the range to `(8..=15)`, `(7..15)`, or
  `(7..=16)` would pass CI while silently missing a real 7-digit local or
  15-digit international scam number, or false-firing on a 16-digit card/serial.
  Since `phone_number` is a weight-35 high-fidelity signal, such a regression
  can drop a scam verdict below threshold. New
  `phone_digit_count_boundaries_are_inclusive` pins all four edges with exact
  digit counts (6→false, 7→true, 15→true, 16→false). No bug today; this is a
  regression guard completing the boundary-coverage theme (round 5 decision
  thresholds, round 6 confidence cutoffs). 1158 tests total.

### Fixed
- **Additive score could overflow under extreme operator weights** (Socratic
  round 7). The `i32` score is accumulated with plain `score += rules.weight_of(...)`,
  and `weight:` / `composite:` weights were parsed as unbounded `i32`. Two
  co-firing signals each overridden near `i32::MAX` (e.g. a fat-fingered
  `weight: fullscreen 2000000000` on two signals) would overflow the
  accumulation — a debug-build panic (config-driven DoS) or a release-build
  two's-complement wrap that flips a would-be **Block** to **Allow** after the
  `score.max(0)` clamp (a security-relevant misverdict). Operator weights are
  now clamped at parse time to ±`MAX_ABS_WEIGHT` (10 000 — ~250× the largest
  built-in weight, so legitimate tuning is unaffected and any larger value is
  semantically identical since it already exceeds `BLOCK_THRESHOLD`). Even with
  every signal plus thousands of composites at the bound, the worst-case sum
  stays far below `i32::MAX`, so the arithmetic cannot overflow. Three tests:
  `weight_override_is_clamped_to_sane_bound`, `composite_weight_is_clamped_to_sane_bound`,
  and `extreme_weight_override_does_not_overflow_score` (which would panic in a
  debug build if the overflow were still reachable).
- **`confidence()` under-reported a lone blocklist-host hard block** (Socratic
  round 6). `Verdict::confidence()` had a collapsed match guard — `1 if
  self.signals.len() == 1 => Medium` immediately followed by `1 => Medium` with
  identical bodies — so a confirmed `blocklist_host` hard block, whose verdict
  carries exactly one (high-fidelity) signal and is the single most definitive
  result the classifier emits, was reported as only **Medium** confidence. That
  contradicted the method's own doc ("High when … a rule-based signal fired")
  and understated an operator's explicitly-listed match. The lone-high-fidelity
  arm now returns **High**; the "one tell amid geometry noise" case (e.g. a
  phone number alongside `unsolicited`) stays Medium, so no multi-signal verdict
  changes. Found by Socratic self-examination (a `match` arm whose guard was
  provably dead). Two new tests:
  `confidence_high_for_lone_blocklist_host_hard_block` pins the fix, and
  `confidence_allow_path_boundaries_are_inclusive` pins the Allow-branch score
  cutoffs (16→High, 17→Medium, 33→Medium, 34→Low) against an off-by-one,
  parallel to the round-5 decision-threshold boundary guard.
- **Canonical JSON for `link_hash`** (C6-4). The audit-chain link hash used
  `serde_json::to_vec(detail)` to serialize the `AuditEvent.detail` payload,
  relying on serde_json's BTreeMap ordering. A new private `canonical_json()`
  function now sorts object keys explicitly via a recursive visitor, making the
  hash deterministic against any future serde_json representation change.
  Existing log hashes are unchanged (serde_json without `preserve_order` already
  uses BTreeMap). Two new tests confirm determinism and key-insertion-order
  stability.

### Added (this pass)
- **Extended `authority_lure` agency + coercion coverage** (E17 / C9-7).
  `has_authority_lure` gains six additional English-language agencies commonly
  impersonated in US government scams (FTC 2024 top-impersonators list):
  "internal revenue service" (IRS — FTC #2 government impersonator), "federal
  trade commission" (FTC impersonation), "customs and border protection" (CBP
  scams), "social security administration" (complement to `national_id_alarm`),
  "secret service", and "drug enforcement" (DEA impersonation).  Three
  additional JP agencies: 法務省 (Ministry of Justice — fake "arrest warrant"
  scams), 検察庁 (Public Prosecutors Office), 最高裁 (Supreme Court fake-order
  scams).  Four new English coercion words: "warrant" (arrest-warrant
  impersonation), "subpoena" (court-order impersonation), "indicted", and
  "charges".  Three new JP coercion words: 令状 (warrant), 差し押さえ (seizure /
  asset freeze), 起訴 (prosecution / indictment).  No weight or threshold
  change — only the agency and coercion match lists are extended.  3 new
  fires/not-fires test groups; 627 tests total.
- **MITRE ATT&CK® technique tags** (`mitre` module; H3). A new
  `Verdict.mitre_techniques: Vec<String>` field carries the sorted,
  deduplicated set of ATT&CK for Enterprise v16 technique IDs implied by the
  signals that fired — e.g. `["T1036","T1566"]` for a homoglyph-title +
  phone-number window. Mapping: `T1566` Phishing (phone/title lures),
  `T1656` Impersonation (brand/combosquat/rogue-AV), `T1036` Masquerading
  (homoglyph/mixed-script/BiDi/combining-mark evasion), `T1204` User Execution
  (ClickFix), `T1219` Remote Access Software (RAT lure), `T1056` Input Capture
  (modal/input_trap). The tags appear in `--json` output and the text
  `classify` summary. Purely classification over already-computed signals; no
  new dependencies. New public module `mitre::{techniques_of,
  techniques_of_signals}`; 6 unit tests. (H3.)
- **Composite weight guard in `rules` subcommand**. `muten-overlay rules
  <file>` now checks each `composite:` rule: if a rule covers only
  geometry/origin conditions (no `has_blocklist_title`, `has_phone_number`, or
  `has_blocklist_phone`) and its weight is ≥ `BLOCK_THRESHOLD` (100), a
  warning is printed to stderr and the subcommand exits 1. This machine-checks
  the bounded-weight FP-aversion convention documented in SPECIFICATION §5.1,
  so CI can catch inadvertent auto-Block-of-shape-only rules before they reach
  a fleet. The `rules` output now also includes `phones:` and `composites:`
  counts.
- **Expanded rogue-AV / scareware process families** in
  `examples/overlay-blocklist.txt` (+35 entries). Additional entries grounded in
  CCCS-Yara FakeAV corpus, Malwarebytes Rogue.* detections, and SafetyDetectives
  2026 rogue-AV guide: includes historical families (WinFixer, Antivirus Pro,
  IE Defender, Reimage), system-optimizer rogues (iolo System Mechanic, Disk
  Heal), and newer names (Malware Crusher, AV Guard Online). These are
  illustrative defaults — IT should extend with fleet-specific observations
  pushed via MDM. (G4.)

- **International phone normalization** (`E6`). `match_phone()` now strips NANP
  (+1), Japan (+81 → restores national trunk "0"), UK (+44), and Australia (+61)
  country codes so that `+81 120 111 222` matches a blocklist entry for
  `0120-111-222`. Normalization runs at both rule-parse time and match time, so
  either the blocklist or the title may carry the country-code prefix
  interchangeably. 7 new tests including a JP international-format end-to-end
  match.
- **Prometheus textfile metrics** (`monitor --metrics <path>`; L4). When
  `--metrics` is given, `monitor` writes a Prometheus exposition file after
  every sweep, consumable by node_exporter's `--collector.textfile`. Five
  counters: `muten_overlay_sweeps_total`, `muten_overlay_events_dismissed_total`,
  `muten_overlay_events_blocked_total`, `muten_overlay_events_suspicious_total`,
  `muten_overlay_events_scareware_total`. Counts are parsed from the audit log's
  `kind` field; file is written atomically (`.tmp` → rename). (L4.)
- **RFC 9162 §2.1.4 Merkle consistency proofs** (`J4b`). `merkle::consistency_proof(first, leaves)`
  generates an O(log n) proof that `leaves[..first]` is a prefix of the full
  leaf set. `merkle::verify_consistency(first, n, proof, old_root, new_root)`
  verifies the proof against two published roots without needing the original
  leaves. `sink::consistency_proof_for_range(text, first)` wraps both over a
  verified audit log. Any holder of two Merkle roots (e.g. from two SIEM records
  or MDM pushes at different points in time) can now prove no events were
  inserted or re-ordered between the snapshots. 8 new tests including exhaustive
  coverage of all prefix sizes 1..=25 with tamper checks. (J4b.)

- **Adaptive sweep interval** (`SweepOutcome`, `RunConfig::alert_interval_ms`; L3).
  `Monitor::sweep()` now returns `SweepOutcome { dismissed: u32, detections: u32 }`
  instead of bare `u32`.  `detections` counts Block + Suspicious verdicts per sweep.
  `RunConfig` gains an optional `alert_interval_ms` field: when set and the previous
  sweep had ≥1 detection, `run()` sleeps for `alert_interval_ms` instead of the
  normal `interval_ms`, so the monitor reacts faster when malware is actively
  re-spawning overlays.  The default (`alert_interval_ms = None`) restores the
  previous behaviour unchanged.  3 new tests; monitor properties updated.  (L3.)
- **`cli` feature flag** (N4). A new `[features] cli` gates the binary and its
  `clap` dependency. `default = ["cli"]` keeps existing `cargo build` /
  `cargo install` behavior unchanged. Library-only consumers (embedding
  muten-overlay as a crate dependency) can add `default-features = false` to
  skip clap entirely. The CLI integration tests (`tests/cli_contract.rs`) are
  gated with `required-features = ["cli"]` so `cargo test --no-default-features`
  (library-only) passes cleanly. `cargo build --no-default-features --lib`
  compiles only the domain library. (N4, C3-4.)
- **Signal-quality confidence** (`ConfidenceLevel`; B6). A new `pub enum ConfidenceLevel { High, Medium, Low }` and `Verdict::confidence()` method indicate how much the verdict relies on high-fidelity (text-analysis / rule-based) signals vs low-fidelity geometry signals (fullscreen / topmost / modal). `High` when ≥2 text signals fired; `Medium` when exactly one; `Low` when only geometry signals fired. A new `pub fn signal_weight(name: &str) -> Option<i32>` exposes the built-in signal weights for external tooling, and `Verdict::score_breakdown()` returns per-signal `(name, weight)` pairs. The `explain()` output now includes the confidence level, e.g. "Block (score 130, high confidence): ...". The `--json` output gains `confidence` and `score_breakdown` fields. SIEM operators can route `High` confidence blocks to auto-response and `Low` to human review. 6 new tests. (B6, C5-5.)
- **Per-signal weight externalization** (`weight:` rule kind; B9 / C5-3). A new
  `weight: <signal> <value>` blocklist line lets operators override any named signal's
  additive contribution without recompiling. Fleet managers who observe from
  `signal_firing_stats()` that, say, `mixed_script` has a high FP rate in their
  environment can add `weight: mixed_script 10` to their MDM-pushed blocklist to soften
  it, while all other signals remain at their compiled defaults. The override is stored
  in `Ruleset::weight_overrides` (a `BTreeMap`) and applied through the new
  `Ruleset::weight_of(signal, default)` helper. All 22 heuristic `score +=` calls in
  `classify()` route through `weight_of` so every tunable signal is reachable. Malformed
  values (non-numeric, missing) are silently ignored — one bad override line never
  disables the whole list. New accessor `Ruleset::weight_override_count()`. The `rules`
  subcommand now prints a `weight overrides:` count. 7 new tests; 330 total. (C5-3.)
- **Glob title patterns in the blocklist** (`glob:` rule kind; F6). A new `glob: <pattern>`
  rule type complements the existing `title:` (substring) rules with full-string wildcard
  matching: `*` matches any run of characters (including none), `?` matches exactly one.
  Use `*` at both ends for contains-style matching (`glob: *infected*`), or anchor one end
  for prefix/suffix patterns (`glob: WARNING: *`). The pattern is normalized through the
  same `strip_invisibles → fold_confusables → fold_leet_in_words → lowercase` pipeline as
  `title:` at parse time, so homoglyph/leet evasion is handled symmetrically. The matching
  algorithm is O(m × n) with O(1) extra space (no regex dep; ReDoS-immune).  Both rule
  types contribute the `blocklist_title` signal at the same weight; at most one fires per
  window.  New public methods `Ruleset::match_title_glob()` and `Ruleset::glob_count()`.
  The `rules` CLI subcommand now shows a `globs:` count.  11 new tests. (F6.)
- **Per-signal firing statistics from audit logs** (`SignalStats`, `signal_firing_stats`; B7, B8).
  `sink::SignalStats { blocks: u64, suspicious: u64 }` tracks how many times a named signal
  appeared in `overlay_blocked` vs `overlay_suspicious` events across a verified audit log.
  `sink::signal_firing_stats(text)` parses the entire log (verifying chain integrity first),
  aggregates the `detail.signals` array of each detection event, and returns a
  `HashMap<String, SignalStats>`. Operators can rank signals by `.total()` to find which drive
  the most alerts, and compare `blocks / total` ratios to spot signals that mostly contribute
  to the review queue vs confirmed dismissals — giving direct, field-data-driven evidence for
  weight and threshold tuning. 3 new tests. (B7, B8.)
- **Multi-file log rotation with chain continuity** (`rotate_log`, `verify_chain_continued`; J6).
  `rotate_log(old_path, new_path, timestamp_ms)` verifies the old log (returns `ChainError` on
  tampered input), then creates a fresh GENESIS-anchored chain in `new_path` whose first event is
  a `log_rotation` marker. The old chain's head is recorded in the marker's `detail.old_head`
  field, which is itself SHA-256-committed in the marker's `hash` — so tampering with the
  cross-file reference breaks the new chain at line 1. The new file is immediately openable
  with `ChainedFileSink::open()` for further events. `verify_chain_continued(new_log_text,
  prev_head)` verifies the new chain AND checks that `detail.old_head == prev_head`, providing
  the cross-file continuity guarantee. Tamper-evidence is preserved at both file boundaries.
  4 unit tests. (J6.)
- **cargo-fuzz targets** (`fuzz/` sub-crate; N6). A new `crates/muten-overlay/fuzz/`
  sub-crate (its own `Cargo.toml`, `libfuzzer-sys` dep isolated there) provides four
  coverage-guided fuzz targets runnable with `cargo +nightly fuzz run <target>`:
  `fuzz_ruleset_parse` (never-panic + idempotence of `Ruleset::parse`),
  `fuzz_classify` (threshold-consistency + explain() well-formedness + score_breakdown
  coverage), `fuzz_verify_chain` (never-panic + sign/verify roundtrip over arbitrary
  log text), `fuzz_window_json` (serde_json never-panic + classify() survives all valid
  deserialized windows). Zero new dependencies in the main crate. (N6.)
- **GitHub Actions CI workflows** (N3). `.github/workflows/ci.yml` runs on push/PR
  to `main` and `claude/**` branches: `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test --all-targets` on Ubuntu/Windows/macOS, `cargo test --no-default-features --lib`
  (library-only path), MSRV build on Rust 1.75.0, and `cargo semver-checks` (advisory, not
  gating, until a baseline is published). `.github/workflows/supply-chain.yml` runs
  `cargo-audit`, `cargo-deny`, and `gitleaks` on push+PR+weekly schedule to catch
  newly-published advisories between releases. Matches the CI described in the README
  Status section. (N3.)
- **HMAC-SHA256 signed checkpoints** (`sign_checkpoint`, `verify_checkpoint_sig`; J5).
  `hmac_sha256(key, data) -> [u8; 32]` implements RFC 2104 HMAC over the `sha2` crate
  already in scope — no new dependencies. `sign_checkpoint(log_text, key)` verifies the
  chain first (returns `ChainError` on tampered input), then produces a `CheckpointSig {
  head, count, sig }` where `sig = hex(HMAC-SHA256(key, head_bytes || 0x00 || count_be64))`.
  `verify_checkpoint_sig(checkpoint, key)` recomputes and compares in constant time
  (byte-fold XOR, no short-circuit) to resist timing side-channels. `CheckpointSig`
  derives `Serialize/Deserialize` for JSON transport to SIEM/MDM. Use case: a fleet
  management server holds the HMAC key and can confirm a device's audit log hasn't been
  truncated or extended since a published checkpoint, even without storing the entire log.
  RFC 4231 test vector + 6 unit tests; total 364. (J5.)
- **Keyboard-adjacent typosquatting** (`typosquat_brand` signal; D10).
  `levenshtein_distance(a, b)` implements the standard 2-row DP Levenshtein
  distance with an early-exit when lengths differ by more than 1. `typosquat_brand(host)`
  checks each host label's confusable skeleton against all entries in `KNOWN_BRANDS` for
  edit distance exactly 1 — catching deletions ("gogle"), insertions ("googlee"),
  substitutions ("googlo"), and adjacent transpositions that happen to have edit distance 1.
  This fills the gap between `brand_impersonation` (skeleton equals brand = distance 0)
  and `combosquat_brand` (hyphenated brand+lure). The signals are mutually exclusive:
  typosquat_brand only fires when the skeleton is NOT identical to the brand. Weight
  `W_TYPOSQUAT_BRAND = 25` (lower than brand_impersonation=40, since single-edit
  variants are less certain than skeleton-exact homographs). Category:
  `InterfaceInterference`. 7 unit tests + 2 property tests; total 357. (D10.)
- **Countdown/timer urgency cue** (`urgency_countdown` signal; E7).
  `confusables::has_urgency_countdown(s)` detects a `M:SS` or `MM:SS` countdown pattern
  combined with at least one urgency keyword (`expir`, `warn`, `alert`, `infect`, `block`,
  `lock`, `urgent`, `critical`, `threat`, `danger`, `support`, `call`) in the normalized
  window title. Scam overlays routinely pair a visible countdown with fear language ("Your
  session expires in 5:00 — call support now!") to coerce rapid action before the target
  can think. The `alert_shaped` guard (full-screen / modal / no-close) in `classify()`
  eliminates false positives from clock apps, media players, and meeting timers, which
  are user-initiated or closable and therefore never `alert_shaped`. Leet-coded urgency
  words (`3xp1r3s`) are defeated via `normalize_for_match` before the check. Weight
  `W_URGENCY_COUNTDOWN = 15` (weak supporting signal, not sufficient to block alone).
  Category: `InterfaceInterference` (urgency / scarcity coercion). 9 unit tests + 2
  property tests; total now 349. (E7.)
- **GlitchFix / CrashFix browser-error ClickFix variants** (E9).
  `has_clickfix_instruction()` now also fires on browser-error lures introduced in
  the GlitchFix campaign (Huntress / The Hacker News, Jan 2026): "browser stopped
  working", "browser stopped abnormally", "font required / missing", and "update
  browser to continue / required / click". These lures embed the same Win+R clipboard
  paste instruction as classic ClickFix but wrap it in a fake browser-crash or missing-
  font dialog. The "update browser" arm requires an explicit gating word ("continue",
  "required", "click", "press") to avoid FPs from benign browser update notifications.
  `s.contains("system font")` directly catches the canonical GlitchFix phrase.
  2 new unit tests (glitchfix_patterns_fire, glitchfix_does_not_fire_on_benign_browser_text).
  370 tests total. (E9.)
- **Cloud blob-storage lure signal** (`cloud_storage_abuse`; E10).
  `is_cloud_storage_host(host)` returns true when the URL host ends with a
  well-known blob-storage suffix with a non-empty tenant label:
  `*.blob.core.windows.net`, `*.web.core.windows.net`, `*.s3.amazonaws.com`,
  `*.storage.googleapis.com`, `*.firebasestorage.googleapis.com`,
  `*.r2.cloudflarestorage.com`. These domains look trustworthy but let anyone
  publish arbitrary content under a tenant-unique subdomain — Azure Blob in
  particular is named as a primary TSS delivery vector in THREAT_INTEL_2026.
  The `alert_shaped` guard (fullscreen / no-close + topmost / no-close +
  blocks_input) prevents legitimate cloud-app browser tabs from firing.
  Weight `W_CLOUD_STORAGE_ABUSE = 20` (additive; alone pushes to Suspicious
  when combined with shape signals, not to Block). Category: `Sneaking`
  (the cloud infrastructure disguises the attacker's real origin).
  `signal_phrase()` phrase and `signal_weight()` entry added.
  6 new unit tests; 376 tests total. (E10.)
- **Expanded `KNOWN_BRANDS` and `BRAND_LURE_WORDS`** (D11). `KNOWN_BRANDS`
  grows from 19 to 33 entries, adding: payment-fraud targets (venmo, zelle,
  cashapp, americanexpress), social/messaging platforms (twitter, discord),
  AV brands most impersonated by TSS (norton, mcafee), signing/document
  service (docusign), crypto ecosystem (ethereum, kraken), and JP-market
  carriers (docomo, softbank, rakuten); all used by `brand_impersonation`,
  `combosquat_brand`, and `typosquat_brand`.  `BRAND_LURE_WORDS` grows from
  19 to 27 with: remove, transfer, refund, claim, portal, center, protection,
  payment — drawn from the dnstwist corpus and IC3 2025 combosquat examples.
  5 new unit tests (norton/mcafee combosquat, JP brand impersonation,
  venmo/zelle combosquat, real-brand FP sanity). 381 tests total. (D11.)
- **Forced-retention "do not close" signal** (`forced_retention_cue`; E13).
  `has_forced_retention(s)` fires when the normalized window title contains
  "do not close", "do not turn off", "do not exit", "do not shut down",
  "do not restart", "keep this window open", "stay on this page", or
  "this window must remain open". Tech-support scammers use these phrases to
  prevent victims from escaping while the fake "support agent" acts. Legitimate
  software almost never puts a retention instruction in a *window title* (only
  in dialog bodies, which are user-initiated and closable — handled by the
  `alert_shaped` guard). Homoglyph/leet variants (`dо not сlose`) are defeated
  via `normalize_for_match`. Weight `W_FORCED_RETENTION = 20`. Category:
  `Obstruction`. MITRE: T1566. 3 lib unit tests + 3 confusables unit tests;
  393 tests total. (E13.)
- **URL-path brand+lure lure signal** (`url_path_lure`; E12). `url_path(url)`
  extracts the path component (after host, before `?`/`#`); `has_path_lure(url)`
  normalizes it via the full `strip_invisibles → fold_confusables → fold_leet →
  lowercase` pipeline, then splits on non-alphanumeric boundaries and checks for
  a known-brand token within 2 positions of a known lure word. Catches
  `/microsoft-alert/`, `/norton/remove/now`, and `/paypal-login/page` — paths
  that attackers construct to make scam URLs look credible in the address bar.
  The `alert_shaped` guard prevents legitimate webapps (whose closable windows
  happen to contain a brand name in a path) from firing. Weight `W_URL_PATH_LURE
  = 20`; Category: `InterfaceInterference`. 6 unit tests; 387 tests total. (E12.)
- **Credential-harvest cue signal** (`credential_harvest_cue`; E14).
  `has_credential_harvest_cue(s)` fires on two complementary phishing patterns
  in the normalized window title: (1) *account-alarm language* — account
  suspended/locked/disabled/blocked/compromised, unusual sign-in/login, suspicious
  sign-in/login/activity; (2) *credential-entry instructions* — "verify your
  account", "confirm your password/identity", "re-enter your password", "enter
  your credentials", "update your payment". These are the canonical language
  patterns used in phishing overlays that mimic bank/social/email account alerts
  to steal usernames, passwords, and payment details. Each pattern uses AND-pair
  matching (two keyword tokens must both appear in the normalized title) rather
  than adjacent substrings, handling natural English phrasing like "your account
  has been suspended". The `alert_shaped` guard prevents legitimate account-
  management UIs (closable/user-initiated) from firing. Weight `W_CREDENTIAL_HARVEST
  = 20` (additive; combined with other social-engineering signals reaches Suspicious).
  Category: `InterfaceInterference`. MITRE: T1566 (phishing lure). Homoglyph/leet
  variants are defeated via `normalize_for_match`. 3 confusables unit tests +
  3 lib unit tests + 2 property tests. (E14.)
- **End-to-end scoring scenario tests** (`tests/scoring_scenarios.rs`; 20 tests).
  A new integration test file validates that all major threat families score at
  or above threshold using only built-in heuristic signals — no operator blocklist.
  Scenarios cover: classic TSS phone overlays, ClickFix/GlitchFix, Azure Blob
  cloud_storage_abuse, forced_retention_cue, credential_harvest_cue,
  fake_scanner_cue, subscription_lure, authority_lure, multi-signal composites,
  FP firewall (user-initiated / closable windows MUST Allow), and leet/homoglyph
  evasion resistance. These serve as regression guards: any signal removal or
  weight change that drops a known scam below Suspicious will be caught.
- **Japanese credential-harvest & fake-scanner coverage** (`credential_harvest_cue`,
  `fake_scanner_cue`; 法域別tuning). Both heuristics now recognize Japanese
  phrasings in addition to English. `credential_harvest_cue` adds JP account
  alarms (アカウントが停止/凍結/ロック/無効/制限, 不審な/不正な/異常なログイン) and
  credential instructions (パスワードを確認/再入力, 本人確認, 身元確認, アカウントを
  確認/再開) — JP credential phishing is a dominant local variant per IPA /
  国民生活センター advisories. `fake_scanner_cue` adds JP rogue-AV progress
  framing (スキャン中+脅威, 脅威が見つかりました, ウイルス/マルウェアを検出しました,
  マルウェアを削除しています, ウイルスを駆除, システムを修復しています). CJK passes
  through `normalize_for_match` (`to_ascii_lowercase`) untouched. FP guards
  preserved: benign JP account-settings / login-help / generic-progress titles
  do not fire. 4 new confusables unit tests + 2 scoring scenarios. 583 tests total.
- **Japanese forced-retention coverage** (`forced_retention_cue`; 法域別tuning).
  `has_forced_retention(s)` now recognizes Japanese retention-coercion phrasings —
  この画面を閉じないで / 閉じないでください, 電源を切らないで, シャットダウンしないで,
  再起動しないで, このページから離れないで, ウィンドウを閉じないで, この画面を閉じ,
  操作を続けないで — in addition to the existing English set. "この画面を閉じないで
  ください" (do not close this screen) is the single most iconic phrase in Japanese
  サポート詐欺 overlays and is explicitly called out in IPA (情報処理推進機構)
  advisories. CJK passes through `normalize_for_match` (`to_ascii_lowercase`)
  untouched. FP guard preserved: benign close/restart instructions without negation
  ("読み終わったら閉じてください") do not fire. 2 new confusables unit tests +
  1 scoring scenario + 3 supplementary blocklist titles. 577 tests total.
- **Japanese law-enforcement impersonation coverage** (`authority_lure`; C9-7 / 法域別tuning).
  `has_authority_lure(s)` now recognizes Japanese agency names (警察庁 NPA, 警視庁 Tokyo
  Metropolitan Police, 国税庁 National Tax Agency, 消費者庁 Consumer Affairs Agency,
  サイバー警察, 公安委員会, 財務省, 総務省) and Japanese coercion words (警告/違反/違法/
  ロック/ブロック/罰金/逮捕/摘発/不正アクセス/調査中/凍結), in addition to the existing
  English set. Also extends the English agency list (Europol, HMRC, UK NCA, Australian
  Federal Police, German BKA, French Gendarmerie). `normalize_for_match` uses
  `to_ascii_lowercase()`, so CJK passes through untouched and the JP tokens match
  intact. Grounds the JP-market focus in IPA (情報処理推進機構) サポート詐欺 /
  警察なりすまし詐欺 advisories. 3 new confusables unit tests (JP fires, JP benign FP-guard,
  additional Western agencies) + 2 scoring scenarios (JP overlay reaches Suspicious,
  legitimate JP police notice stays silent) + 6 supplementary blocklist titles.
  Category: `InterfaceInterference`. MITRE: T1566. 574 tests total.
- **Gift-card payment demand** (`gift_card_demand`; E26). `has_gift_card_demand(s)`
  fires when the normalized title contains a *gift_card_noun* ("gift card/gift cards",
  "itunes card", "google play card", "steam gift card", "amazon/apple/ebay gift card",
  "prepaid card", "vanilla card") AND a *payment_instruction* (buy/purchase gift card,
  send codes/the codes, read the codes/me the codes, scratch the card, pay with/using/in
  gift card, go to the store, nearest store).  Tech-support and authority-impersonation
  scams routinely instruct victims to purchase gift cards and read out the codes as
  "payment" to unlock a device, pay a fabricated fine, or satisfy a fake debt.  No
  legitimate software ever demands payment in gift cards through an alert-shaped overlay.
  FTC: gift cards are the #1 payment method in tech-support fraud losses.  Weight
  `W_GIFT_CARD_DEMAND = 30` (highest content-signal weight, reflecting near-zero FP
  rate in combination with the alert_shaped guard). Category: `InterfaceInterference`.
  MITRE: T1566.  7 confusables unit tests + 3 lib unit tests + 2 property tests + 3
  scoring scenarios; 569 tests total. (E26.)
- **Refund / overpayment scam lure** (`refund_scam_cue`; E27). `has_refund_scam_cue(s)`
  fires when the normalized title contains a *refund_noun* ("refund", "overpayment",
  "reimbursement", "rebate", "cashback", "excess charge", "overcharged", 返金, 払い戻し,
  過払い, 補償金) AND a *refund_action* ("owed to you", "you are owed", "claim your
  refund", "collect your refund", "pending refund", "refund is ready", "refund has been",
  "process/transfer/receive/get your refund", "your refund of", "refund amount",
  返金手続き, 払い戻し手続き, 返金が完了, お手続きください, ご返金, 返金いたします,
  返金を受け取). Scammers posing as support agents, banks, or government agencies
  falsely claim the victim has an uncollected refund or overpayment to return,
  then direct them to call a number or click a link to "process the refund" —
  leading to credential theft or gift-card coercion. The AND-pair prevents plain
  e-commerce return-policy text ("refund within 30 days") from firing; the
  alert_shaped guard prevents legitimate bank refund-portal windows (user-initiated,
  closable) from triggering. FTC 2024 and IC3 2025 identify refund/overpayment
  scams as a top financial-fraud vector, particularly targeting elderly users.
  Full JP coverage (返金手続き patterns). Weight `W_REFUND_SCAM = 25`. Category:
  `Sneaking` (Gray et al. 2018 — false information disguised as a benefit). MITRE:
  T1566. 9 confusables unit tests + 3 lib unit tests + 2 property tests + 4 scoring
  scenarios; 596 tests total. (E27.)
- **National ID / benefit-number alarm scam** (`national_id_alarm`; E28).
  `has_national_id_alarm(s)` fires when the normalized title contains an
  *id_noun* ("social security number", "social security", "ssn", "national
  insurance number", "medicare", "medicaid", マイナンバー, 個人番号, 基礎年金番号,
  年金番号) AND an *id_alarm* ("has been suspended", "is/was suspended", "has
  been blocked", "used in criminal", "criminal activity", "criminal charges",
  "criminal case", "fraudulent activity", "associated with fraud", "under
  federal investigation", "identity theft", "has been compromised", 凍結,
  不正使用, 不正利用, 犯罪に使用, 捜査中, 停止されました). The US SSA impersonation
  scam is the #1 government-impersonation variant per FTC 2024; scammers
  claim the victim's SSN has been "suspended" or "used in criminal activity"
  and demand an immediate call. No legitimate government service suspends a
  national ID via a browser overlay. Full JP coverage (マイナンバー / 年金番号
  scam patterns). Weight `W_NATIONAL_ID_ALARM = 30`. Category:
  `InterfaceInterference`. MITRE: T1566. 9 confusables unit tests + 3 lib
  unit tests + 2 property tests + 4 scoring scenarios + 10 blocklist titles +
  2 glob patterns; 610 tests total. (E28.)
- **Fake bank-fraud alert overlay** (`bank_account_alarm`; E29).
  `has_bank_account_alarm(s)` fires when the normalized title contains a
  *bank_noun* ("bank account", "checking account", "savings account", "debit
  card", "credit card", "your account at", 銀行口座, キャッシュカード, 通帳,
  クレジットカード, デビットカード) AND a *bank_alarm* ("unauthorized transaction",
  "fraudulent transaction", "suspicious transaction", "fraudulent charge", "has
  been frozen", "account has been frozen", "fraudulent access", "unauthorized
  access detected", 不正な取引, 不審な取引, 口座が停止, 口座が凍結, 不正アクセスを検知).
  Scammers impersonating banks or payment processors display alert-shaped
  overlays claiming a victim's account or card has been frozen or has
  experienced fraudulent transactions, prompting a call to a fake helpline.
  Distinct from `credential_harvest_cue` (which requires a credential-entry
  instruction): `has_bank_account_alarm` fires when only the alarm framing is
  present — the attacker wants a call, not credential entry. AND-pair prevents
  a screen that merely mentions "credit card" (no alarm) or "suspicious
  activity" (no bank noun) from firing. Full JP coverage (銀行口座/キャッシュ
  カード + 不正な取引/口座が凍結 patterns). alert_shaped guard prevents legitimate
  bank-app notifications (user-initiated, closable) from triggering. Weight
  `W_BANK_ACCOUNT_ALARM = 25`. Category: `InterfaceInterference`. MITRE: T1566.
  9 confusables unit tests + 3 lib unit tests + 2 property tests + 4 scoring
  scenarios; 624 tests total. (E29.)
- **False-registration billing / ワンクリック詐欺** (`false_registration_billing`;
  E30). `has_false_registration_billing(s)` fires when the normalized title
  contains a *reg_claim* ("you have been registered", "membership confirmed",
  "registration complete", "your subscription has been activated", 登録が完了,
  会員登録が完了, ご入会, ご登録, 登録されました, 会員登録されました) AND a
  *payment_ultimatum* ("pay within", "outstanding fee", "legal action",
  "failure to pay", "penalty fee", "collection agency", "amount due", 法的措置,
  お支払い期限, 未払い, 延滞, ご入金, 督促). Targets the Japanese ワンクリック詐欺
  (one-click fraud) pattern and its English counterparts — overlays that
  *falsely claim* the user registered for a paid service and demand immediate
  payment or threaten legal consequences.  Distinct from `subscription_lure`
  (which targets *expired* subscriptions): E30 fires on *false creation* of a
  new payment obligation regardless of prior history.  Grounded in 消費者庁
  (Japan Consumer Affairs Agency) ワンクリック詐欺 guidance and IC3 2024 impostor
  category data.  Weight `W_FALSE_REG_BILLING = 25`. Category:
  `InterfaceInterference`. MITRE: T1566. alert_shaped guard prevents legitimate
  e-commerce order confirmations (user-initiated, closable) from triggering.
  9 confusables unit tests + 3 lib unit tests + 2 property tests + 4 scoring
  scenarios; 641 tests total. (E30.)
- **Fake BSOD / "Windows has been blocked" tech-support scam**
  (`fake_bsod_lure`; E31). `has_fake_bsod_lure(s)` fires when the normalized
  title contains a *bsod_marker* ("stop code", "windows has been blocked",
  "your pc is blocked", "memory_management", "kmode exception",
  "kernel security check", "irql not less", "dpc watchdog", "blue screen",
  "kernel panic", "critical process died", ブルースクリーン, windowsがブロック,
  pcがブロック, カーネルパニック) AND a *call_barrier* ("do not restart",
  "do not turn off", "do not close this", "call microsoft", "contact microsoft",
  "microsoft support", "microsoft certified", "windows helpline", "apple support",
  再起動しないでください, マイクロソフトサポート, テクニカルサポートに電話).
  Targets the widespread "FakeBlue" campaign (Microsoft MSTIC 2025) and FBI
  IC3 2025 tech-support fraud category where an overlay mimics a Windows BSOD
  or macOS kernel panic to push victims to call a scam phone number. Distinct
  from `has_fake_scanner_cue` (rogue-AV scanning progress): E31 targets
  *OS crash impersonation* with a call-to-phone instruction. Legitimate Windows
  BSODs display a QR code linking to support.microsoft.com, not a phone number.
  The AND-pair ensures BSOD-related IT articles (bsod_marker only) and
  legitimate update warnings ("do not restart while installing") do not fire.
  Weight `W_FAKE_BSOD_LURE = 30`. Category: `Obstruction`. MITRE: T1036
  (Masquerading — impersonates OS crash). alert_shaped guard prevents
  IT troubleshooting browser tabs from triggering. 10 confusables unit tests
  + 3 lib unit tests + 2 property tests + 4 scoring scenarios; 656 tests total.
  (E31.)
- **Advance-fee fraud / "419" / inheritance / unclaimed-funds scam**
  (`advance_fee_lure`; E32). `has_advance_fee_lure(s)` fires when the
  normalized title contains a *fund_claim* ("inheritance", "inherited",
  "beneficiary", "estate of", "deceased", "unclaimed funds", "won the lottery",
  "trust fund", "next of kin", 遺産, 受益者, 未請求の資産, 宝くじ当選, 相続財産)
  AND a *release_fee* ("processing fee", "transfer fee", "customs fee",
  "release fee", "advance fee", "notary fee", "legal fee", "to release the
  funds", "to claim your inheritance", "to unlock your funds", 手数料, 振込手数料,
  関税, リリース手数料, 受け取るには手数料).  Distinct from `has_prize_lure`
  (click-to-claim, no payment demand): E32 requires the *fee-extraction* step
  alongside the windfall claim — the defining characteristic of advance-fee
  fraud (FTC BCP 2024 "Money you didn't expect" category, FBI IC3 2025
  impostor/BEC sub-category).  Weight `W_ADVANCE_FEE_LURE = 25`.  Category:
  `Sneaking` (creating false expectations of a windfall benefit).  MITRE: T1566.
  alert_shaped guard prevents legitimate estate-attorney notifications
  (user-initiated, closable) from triggering.  10 confusables unit tests +
  3 lib unit tests + 2 property tests + 4 scoring scenarios; 670 tests total.
  (E32.)
- **Fake tech-support invoice / "you were charged" cancel-scam**
  (`tech_support_invoice_scam`; E33). `has_tech_support_invoice_scam(s)` fires
  when the normalized title contains a *charge_claim* ("you have been charged",
  "a charge of", "an invoice for", "subscription has been renewed",
  "auto-charged", "billing confirmation", "renewal charge", "has been debited",
  ご請求が完了, 課金されました, お引き落とし, 自動更新料金) AND a *cancel_cta*
  ("call to cancel", "if you did not authorize", "dispute this charge",
  "unauthorized charge", "to cancel call", "contact billing",
  キャンセルするには電話, 不正な請求, ご解約はお電話, 請求に心当たりのない).
  Targets the prevalent attack where an overlay claims a large charge (e.g.,
  $499 Microsoft support plan, $399 McAfee renewal) was already processed and
  urges the victim to call a scam "cancel" line — directly resulting in
  tech-support fraud engagement.  Distinct from `subscription_lure` (no charge
  claimed — subscription expired), `false_registration_billing` (false
  registration + pay-or-face-consequences), and `refund_scam_cue` (owed a
  refund).  Grounded in FTC 2025 impostor-scam category data.  Weight
  `W_TECH_INVOICE_SCAM = 25`.  Category: `InterfaceInterference`.  MITRE: T1566.
  alert_shaped guard prevents legitimate invoice notifications (user-initiated,
  closable) from triggering.  10 confusables unit tests + 3 lib unit tests +
  2 property tests + 4 scoring scenarios; 684 tests total.  (E33.)
- **Fake utility disconnection threat** (`utility_cutoff_threat`; E34).
  `has_utility_cutoff_threat(s)` fires when the normalized title contains a
  *utility_service* noun ("electricity", "electric service", "gas service",
  "water service", "power company", "utility account", 電気, ガス, 水道, 電力,
  公共料金) AND a *cutoff_threat* ("will be disconnected", "will be shut off",
  "disconnection notice", "service termination", "final notice", "pay to avoid
  disconnection", "immediate payment required", 停止予告, 供給停止, 料金未払い,
  即時お支払い, 強制停止).  Targets the well-documented utility-impersonation
  scam (FTC 2024 #3 impostor-scam type) where an overlay mimics an official
  electric, gas, or water company notice and threatens disconnection within
  hours unless a "payment" is made immediately.  Distinct from
  `subscription_lure` (expired subscriptions), `national_id_alarm` (government-ID
  suspension), and `authority_lure` (government agency impersonation): E34
  specifically targets public-utility service interruption threats.  Weight
  `W_UTILITY_CUTOFF = 25`.  Category: `InterfaceInterference`.  MITRE: T1566.
  alert_shaped guard prevents legitimate utility account portals (user-initiated,
  closable) from triggering.  10 confusables unit tests + 3 lib unit tests +
  2 property tests + 4 scoring scenarios; 698 tests total.  (E34.)
- **Medicare / healthcare benefit scam** (`healthcare_scam`; E35).
  `has_healthcare_scam(s)` fires when the normalized title contains a
  *health_benefit* noun ("medicare", "medicaid", "health insurance",
  "medical coverage", "prescription benefit", "health plan", "your benefits",
  "medical device", "healthcare plan", 健康保険, 医療保険, 介護保険, 保険証,
  国民健康保険) AND a *benefit_urgency* phrase ("will expire", "expiring soon",
  "claim your free", "you have been approved", "at no cost to you",
  "enrollment period ends", "limited time offer", "call to claim",
  受給期限, 無料で受け取る, 給付が承認).  Targets the #1 IC3 2025 elder-fraud
  category and FTC 2024 leading impostor-scam type by dollar loss for victims
  over 60 — overlays that impersonate Medicare, Medicaid, or an insurance
  provider and lure victims into calling a scam line by claiming a benefit is
  expiring or a free medical device is available.  Distinct from
  `national_id_alarm` (SSN suspension) and `authority_lure` (government-agency
  impersonation): E35 specifically targets healthcare benefit false-urgency.
  Weight `W_HEALTHCARE_SCAM = 25`.  Category: `Sneaking`.  MITRE: T1566.
  alert_shaped guard prevents legitimate Medicare portal sessions
  (user-initiated, closable) from triggering.  10 confusables unit tests +
  3 lib unit tests + 2 property tests + 4 scoring scenarios; 712 tests total.
  (E35.)
- **Fake job / work-from-home employment fraud** (`job_scam`; E36).
  `has_job_scam(s)` fires when the normalized title contains a *job_offer*
  ("work from home", "remote work opportunity", "earn from home",
  "make money from home", "part time job", "data entry job",
  "easy money opportunity", "hiring now", 在宅ワーク, 副業, テレワーク,
  在宅アルバイト, 内職) AND a *fee_gate* ("registration fee", "equipment
  deposit", "background check fee", "starter kit", "training fee",
  "upfront fee", "refundable deposit", "security deposit",
  登録料, 機材費, 保証金, 入会金, 初期費用).  Targets the top-5 IC3 2025
  non-elder-fraud loss category and FTC 2024 #1 business-opportunity fraud type
  — fake work-from-home job postings that require an advance fee (registration,
  equipment deposit, starter kit) to "start working".  Legitimate employers
  never charge candidates an upfront fee; the fee is the sole scam tell, making
  the AND-pair extremely high specificity.  Weight `W_JOB_SCAM = 25`.  Category:
  `Sneaking`.  MITRE: T1566.  alert_shaped guard prevents legitimate job-board
  pages (user-initiated, closable) from triggering.  10 confusables unit tests
  + 3 lib unit tests + 2 property tests + 4 scoring scenarios.  (E36.)
- **Tax authority impersonation scam** (`tax_authority_scam`; E37).
  `has_tax_authority_scam(s)` fires when the normalized title contains a
  *tax_authority* phrase ("irs notice", "internal revenue service", "unpaid
  taxes", "tax debt", "back taxes", "hmrc notice", "delinquent taxes",
  "tax warrant", "tax lien", 国税庁, 税務署, 延滞税, 税金未納, 税金滞納) AND
  an *arrest_threat* ("arrest warrant", "warrant for your arrest", "face arrest",
  "you will be arrested", "criminal charges have been filed", "your assets will
  be seized", "wage garnishment", "bank levy", 逮捕状, 差し押さえ, 刑事訴追,
  逮捕されます, 法的手続き).  Targets IRS/HMRC/国税庁 impersonators who threaten
  arrest or asset seizure over fabricated tax debts and demand immediate wire
  transfer or gift-card payment; FTC 2025 government-impostor fraud #2 category.
  Real tax authorities communicate exclusively by certified mail and online portal
  — no legitimate tax authority delivers an arrest-warrant threat via a browser
  overlay.  Weight `W_TAX_AUTHORITY_SCAM = 30` (elevated: arrest-threat +
  tax-authority AND-pair is near-zero-FP).  Category: `InterfaceInterference`.
  MITRE: T1566.  10 confusables unit tests + 3 lib unit tests + 2 property tests
  + 4 scoring scenarios.  (E37.)
- **Social media / email account hijacking alarm** (`social_media_account_alarm`; E38).
  `has_social_media_account_alarm(s)` fires when the normalized title contains
  a *social_platform* ("facebook account", "instagram account", "twitter account",
  "gmail account", "google account", "apple id", "icloud account", "discord
  account", "whatsapp account", "telegram account", フェイスブック, インスタグラム,
  ツイッター, ライン, ユーチューブ, グーグルアカウント, アップルid, アイクラウド) AND
  an *account_jeopardy* phrase ("has been hacked", "has been hijacked", "has been
  suspended", "account terminated", "unauthorized login", "suspicious login
  detected", "unusual login", "verify to recover", "regain access", "click to
  restore", "account will be permanently deleted", アカウントが停止, 不正ログイン,
  アカウントを回復するには, 本人確認が必要).  Social-platform credential-phishing
  overlays that impersonate Facebook, Instagram, Gmail, LINE or Google account
  notices to coerce victims into a fake "account recovery" flow, where they enter
  credentials into a phishing form; APWG Q1 2025 social-media credential phishing
  surge; FBI IC3 2025 social-media fraud reporting.  Distinct from
  `national_id_alarm` (national ID numbers) and `bank_account_alarm` (financial
  accounts) — this signal keys on named social or email platform brands.  Weight
  `W_SOCIAL_MEDIA_ACCOUNT_ALARM = 25`.  Category: `InterfaceInterference`.  MITRE:
  T1566.  10 confusables unit tests + 3 lib unit tests + 2 property tests + 4
  scoring scenarios.  (E38.)
- **Immigration / visa authority scam** (`immigration_visa_scam`; E39).
  `has_immigration_visa_scam(s)` fires when the normalized title contains an
  *immigration_doc* phrase ("your visa", "your work permit", "your green card",
  "your residence permit", "immigration notice", "visa application", "visa
  status", "customs and border", "department of homeland", "immigration and
  customs", ビザ, 在留資格, 在留カード, 永住許可, 就労ビザ, 入国管理, 外国人登録)
  AND a *status_threat* ("has been revoked", "has been cancelled", "deportation",
  "will be deported", "illegal overstay", "out of status", "renewal fee required",
  "pay the renewal fee", "face deportation", "removal proceedings", 取り消し,
  不法滞在, 強制送還, 在留資格の失効, 更新料, オーバーステイ).  Targets immigrant
  populations by impersonating USCIS, ICE, CBP, or 出入国在留管理庁 (MOJI), threatening
  visa revocation, deportation, or illegal-overstay prosecution unless the victim
  pays an immediate renewal or settlement fee; FTC 2024 government-impostor
  campaigns targeting immigrant communities; MOJI scam advisories for the JP market.
  No legitimate immigration authority delivers enforcement notices via unsolicited
  browser overlays.  Weight `W_IMMIGRATION_VISA_SCAM = 25`.  Category:
  `InterfaceInterference`.  MITRE: T1566.  10 confusables unit tests + 3 lib unit
  tests + 2 property tests + 4 scoring scenarios.  (E39.)
- **Government grant / stimulus scam** (`government_grant_scam`; E40).
  `has_government_grant_scam(s)` fires when the normalized title contains a
  *grant_program* phrase ("government grant", "federal grant", "stimulus
  payment", "stimulus check", "economic relief", "pandemic relief", "covid
  relief", "emergency relief fund", "unclaimed government funds", 政府給付金,
  補助金, 給付金, 特別定額給付金, 緊急経済支援, 公的補助, 国庫補助, 給付が決定)
  AND a *claim_barrier* ("claim your grant", "claim your funds", "application
  fee required", "processing fee to receive", "verify your identity to receive",
  "enrollment deadline", "apply before the deadline", "funds will expire",
  "disbursement fee", 今すぐ申請, 給付金を受け取るには, 手数料が必要, 申請期限,
  確認が必要です).  Distinct from `advance_fee_lure` (which covers personal
  windfall stories — inheritance, lottery): this signal keys on impersonation
  of official government grant or stimulus programs.  No real government grant
  program requires an upfront fee, and no legitimate government notice is
  delivered via an unsolicited browser overlay.  FTC BCP 2024 government
  impostor enforcement; 消費者庁 2025 給付金詐欺 advisories for the JP market.
  Weight `W_GOVERNMENT_GRANT_SCAM = 25`.  Category: `Sneaking`.  MITRE: T1566.
  10 confusables unit tests + 3 lib unit tests + 2 property tests + 4 scoring
  scenarios.  (E40.)
- **Debt relief / credit repair scam** (`debt_relief_scam`; E41).
  `has_debt_relief_scam(s)` fires when the normalized title contains a
  *debt_claim* ("credit card debt", "credit card balance", "unsecured debt",
  "get out of debt", "debt forgiveness", "debt consolidation", "debt relief
  program", "debt settlement", "credit repair program", "eliminate your debt",
  "student debt relief", 借金, 債務整理, 過払い金, 借金の悩み, 多重債務,
  クレジットカードの借金, 借金解決) AND a *scam_cta* ("guaranteed approval",
  "no credit check required", "100% guaranteed results", "we can eliminate
  your debt", "settled for pennies", "stop paying now", "stop payments today",
  "you qualify for relief", "application fee required", "processing fee
  required", "initial consultation fee", "pay to start your case",
  "guaranteed debt relief", 確実に解決, 審査不要, 着手金, 相談料が必要,
  初期費用が必要, 保証料).  Fake debt-relief operations collect upfront
  fees while promising guaranteed debt elimination or "stop paying now"
  outcomes — results they never deliver — leaving victims worse off than
  before.  The upfront-fee or guaranteed-results CTA is the sole scam tell:
  legitimate NFCC-accredited credit counselors charge no advance fee and
  never guarantee specific debt-reduction outcomes.  alert_shaped guard
  prevents legitimate credit-counseling websites (user-initiated, closable)
  from firing.  FTC 2025 debt-relief enforcement actions; 日本弁護士連合会
  2025 多重債務詐欺 advisories for the JP market.  Weight `W_DEBT_RELIEF_SCAM
  = 25`.  Category: `Sneaking`.  MITRE: T1566.  10 confusables unit tests +
  3 lib unit tests + 2 property tests + 4 scoring scenarios; 797 tests total.
  (E41.)
- **Streaming / subscription service billing scam** (`streaming_billing_scam`; E42).
  `has_streaming_billing_scam(s)` fires when the normalized title contains a
  *streaming_platform* ("netflix", "spotify", "disney+", "disney plus", "hulu",
  "amazon prime", "hbo max", "youtube premium", "paramount+", "peacock
  subscription", "crunchyroll", ネットフリックス, スポティファイ, アマゾンプライム,
  ディズニープラス, ユーチューブプレミアム, アップルtv) AND a *payment_problem*
  ("payment failed", "payment declined", "payment method expired", "payment
  method failed", "credit card declined", "billing issue", "billing problem",
  "failed to process payment", "unable to charge", "update your payment",
  "verify your payment", "payment information required", "reactivate your
  account", "account on hold", "membership suspended due to billing",
  お支払いが失敗, 決済が失敗, 支払い方法が無効, 支払い情報の更新,
  お支払い情報をご確認).  Phishing overlays impersonate Netflix, Spotify,
  Disney+, Amazon Prime, and similar services to steal payment credentials or
  account logins.  Distinct from `subscription_lure` (generic subscription-expiry
  language): this signal keys on named streaming brands combined with
  payment-failure framing rather than expiry language.  APWG Q4 2024 streaming-
  service phishing surge; Netflix/Spotify official scam advisories.  Weight
  `W_STREAMING_BILLING_SCAM = 25`.  Category: `InterfaceInterference`.  MITRE:
  T1566.  10 confusables unit tests + 3 lib unit tests + 2 property tests + 4
  scoring scenarios.  (E42.)
- **Fake traffic / parking / toll violation scam** (`traffic_fine_scam`; E43).
  `has_traffic_fine_scam(s)` fires when the normalized title contains a
  *violation_type* ("parking violation", "parking ticket", "traffic fine",
  "speeding ticket", "red light violation", "traffic citation", "toll violation",
  "unpaid toll", "toll balance", "toll due", "outstanding toll", "road tax
  notice", "vehicle fine", "ezpass", "fastrak", "i-pass", 駐車違反, 交通違反,
  スピード違反, 信号無視, 反則金, 高速料金, 未払い料金) AND a *payment_urgency*
  ("pay within", "pay immediately", "final notice to pay", "overdue fine",
  "failure to pay", "warrant for non-payment", "immediate payment required",
  "pay online now", "penalty will increase", "your fine has increased", "vehicle
  registration hold", "license suspension", "license will be suspended", "avoid
  additional fees", すぐにお支払い, 至急お支払い, 期限内にお支払い, 未払いの場合,
  罰則金の支払い, 車両登録停止).  Scammers impersonate parking enforcement, traffic
  courts, and toll authorities (EZPass, FasTrak, 高速料金) to extract immediate
  payment for fabricated fines.  Distinct from `authority_lure` (requires a named
  law-enforcement agency) and `tax_authority_scam` (tax debt + arrest threat).
  FTC 2025 top-3 impersonator smishing/phishing category; FBI IC3 2025 EZPass/
  FasTrak smishing alert.  Weight `W_TRAFFIC_FINE_SCAM = 25`.  Category:
  `InterfaceInterference`.  MITRE: T1566.  10 confusables unit tests + 3 lib unit
  tests + 2 property tests + 4 scoring scenarios; 824 tests total.  (E43.)
- **Charity / disaster-relief scam** (`charity_scam_lure`; E46).
  `has_charity_scam_lure(s)` fires when the normalized title contains both a
  *charity/donation cue* (donate now, disaster/hurricane/earthquake/flood/wildfire
  relief, humanitarian aid, help the victims, emergency relief fund, 義援金, 募金,
  被災者支援, etc.) AND a *suspicious payment method* (gift card, iTunes/Google
  Play/Steam/Amazon gift card, wire transfer, Western Union, MoneyGram, bitcoin
  donation, crypto donation, money order only, prepaid card, ギフトカード,
  仮想通貨で寄付, etc.). Legitimate charities never solicit gift cards,
  cryptocurrency, or wire transfers for small-donor collections — this AND-pair
  is the definitive charity-fraud tell. FTC "Charity Scams" 2024; BBB Wise
  Giving Alliance advisory; FBI IC3 post-disaster alerts (Maui 2023, Hurricane
  Helene 2024). Weight `W_CHARITY_SCAM_LURE = 25`. Category: Sneaking. MITRE:
  T1566. 10 confusables unit tests + 3 lib unit tests + 2 property tests +
  4 scoring scenarios; 913 tests total. (E46.)
- **Rental / housing scam** (`rental_scam_lure`; E47). `has_rental_scam_lure(s)`
  fires when the normalized title contains both a *rental/housing cue* (apartment/
  room/house for rent, rental listing, studio apartment, no credit check rental,
  賃貸物件, アパート募集, 家賃, 入居者募集, etc.) AND an *advance-deposit demand*
  (send deposit, wire deposit, deposit before viewing, deposit to hold, gift card
  for deposit, deposit upfront, 内覧前に入金, 先に敷金, 振込で保証金, etc.). A
  legitimate landlord does not require irreversible advance payment before the
  tenant views the property. FTC Consumer Sentinel 2024 (housing fraud top-5 by
  complaint count); BBB 2024 rental scam advisory; CFPB housing fraud warnings.
  Weight `W_RENTAL_SCAM_LURE = 25`. Category: Sneaking. MITRE: T1566. 10
  confusables unit tests + 3 lib unit tests + 2 property tests + 4 scoring
  scenarios. (E47.)
- **Pet-sale transport advance-fee scam** (`pet_sale_scam`; E48).
  `has_pet_sale_scam(s)` fires when the normalized title contains both a
  *pet-listing cue* (puppy for sale, puppies for sale, kitten for sale, akc
  registered, purebred puppy, french bulldog pup, golden retriever pup, maltese
  puppy, 子犬販売, 子猫販売, ペット販売, etc.) AND an *advance-demand cue* (shipping
  deposit, transport fee required, crate deposit, insurance deposit, pay before
  delivery, deposit to reserve, reserve your puppy, 配送前に入金, ペット輸送費,
  etc.). A legitimate pet seller does not demand irreversible advance payment
  for transport before delivery. FTC Consumer Sentinel 2024 (online-shopping
  fraud, pet-transport scheme in top-10 by complaint count); BBB 2024 pet-scam
  advisory; IC3 2024 cyber crime report. Weight `W_PET_SALE_SCAM = 25`.
  Category: Sneaking. MITRE: T1566. 10 confusables unit tests + 3 lib unit
  tests + 2 property tests + 4 scoring scenarios; 951 tests total. (E48.)
- **Timeshare / vacation-prize advance-fee scam** (`timeshare_travel_scam`; E49).
  `has_timeshare_travel_scam(s)` fires when the normalized title contains both a
  *timeshare/vacation cue* (vacation club, timeshare, resort membership,
  complimentary vacation, free vacation offer, タイムシェア, リゾート会員,
  etc.) AND an *advance-fee demand* (activation fee, membership fee to activate,
  certificate fee, closing fee, pay to claim your vacation, resort activation
  fee, 会員費のお支払い, タイムシェア費用, etc.). Attackers target timeshare owners
  by offering to "resell" the timeshare or award a complimentary stay, then
  demand closing fees that never result in a transaction. FTC travel-prize fraud
  advisory 2024; FTC timeshare resale fraud advisory; IC3 2024 complaint data.
  Weight `W_TIMESHARE_TRAVEL_SCAM = 25`. Category: Sneaking. MITRE: T1566.
  10 confusables unit tests + 3 lib unit tests + 2 property tests + 4 scoring
  scenarios. (E49.)
- **Fake Windows / Office activation popup** (`windows_activation_scam`; E50).
  `has_windows_activation_scam(s)` fires when the normalized title contains
  both an *activation cue* (Windows is not activated, product key required,
  enter product key, Windows activation required, office activation, your copy
  of Windows is not genuine, ライセンス認証が必要, etc.) AND a *call-to-action*
  (call Microsoft support, contact Microsoft certified technician, Microsoft
  activation center, toll free activation, activation helpline,
  Microsoftサポートに電話, etc.). A legitimate Windows activation dialog never
  includes a "call us" instruction — that pairing is the defining tell of
  tech-support-fraud activation pop-ups. FTC Tech Support Fraud advisory 2024;
  Microsoft MSRC "fake activation" warnings. Weight `W_WINDOWS_ACTIVATION_SCAM
  = 30`. Category: InterfaceInterference. MITRE: T1566. 10 confusables unit
  tests + 3 lib unit tests + 2 property tests + 4 scoring scenarios; 951 tests
  total. (E50.)
- **Survey reward bait** (`survey_reward_scam`; E51). `has_survey_reward_scam(s)`
  fires when the normalized title contains both a *survey-invite cue* (take our
  survey, complete a survey, you have been selected for our survey, answer 3
  questions, quick survey, アンケートに答える, アンケートへのご参加, etc.) AND a
  *reward bait* (win a gift card, claim your gift card, amazon gift card, $500
  reward, claim your reward, free iPhone, ギフトカードをもらう,
  アンケート謝礼, etc.). Distinct from `prize_lure` (lottery-winner framing
  without the survey hook). Very high volume browser-overlay pattern. APWG Q4
  2024 "survey-lure phishing"; Google Safe Browsing blog 2024. Weight
  `W_SURVEY_REWARD_SCAM = 25`. Category: InterfaceInterference. MITRE: T1566.
  10 confusables unit tests + 3 lib unit tests + 2 property tests + 4 scoring
  scenarios. (E51.)
- **Fake antivirus brand renewal popup** (`av_brand_renewal_scam`; E52).
  `has_av_brand_renewal_scam(s)` fires when the normalized title contains both a
  *named AV brand* (mcafee, norton, avast, kaspersky, bitdefender, avg antivirus,
  malwarebytes, eset nod, webroot, trend micro, マカフィー, ノートン,
  カスペルスキー, etc.) AND a *renewal/expiry demand* (subscription has expired,
  license has expired, your protection has expired, renew now to stay protected,
  device is no longer protected, subscription renewal required, サブスクリプション
  が期限切れ, etc.). Distinct from `subscription_lure` (no brand name) and
  `fake_scanner_cue` (fake scan/threat count). FTC Consumer Sentinel 2024 Tech
  Support top-10; APWG Q4 2024 "branded AV pop-up" phishing category. Weight
  `W_AV_BRAND_RENEWAL_SCAM = 30`. Category: InterfaceInterference. MITRE: T1566.
  10 confusables unit tests + 3 lib unit tests + 2 property tests + 4 scoring
  scenarios. (E52.)
- **Fraud-recovery / secondary-victimization scam** (`recovery_scam`; E53).
  `has_recovery_scam(s)` fires when the normalized title contains both a
  *recovery-service cue* (recover your lost funds, lost money to a scam, scam
  recovery service, crypto recovery, chargeback specialist, funds recovery,
  asset recovery specialist, investment recovery, 詐欺被害金の回収, 被害金を取り
  戻す, etc.) AND a *fee/contact demand* (100% guaranteed, no recovery no fee,
  contact our specialist, free consultation, recovery expert, upfront fee,
  専門家に相談, 回収成功率100%, etc.). Recovery scams target prior fraud victims
  by promising to recover lost money for an upfront fee that is itself stolen —
  a growing secondary-victimization category. FBI IC3 2024; FTC "avoid recovery
  scams" advisory 2024; 消費者庁 "二次被害型詐欺" advisory 2024. Weight
  `W_RECOVERY_SCAM = 30`. Category: Sneaking (disguises fraud as legitimate
  service). MITRE: T1566. 10 confusables unit tests + 3 lib unit tests + 2
  property tests + 4 scoring scenarios; 1027 tests total. (E53.)
- **Student loan forgiveness scam** (`student_loan_scam`; E54).
  `has_student_loan_scam(s)` fires when the normalized title contains both a
  *loan-relief cue* (student loan forgiveness, student loan relief, loan
  cancellation, student debt forgiveness, federal loan forgiveness,
  学生ローン免除, 奨学金免除, etc.) AND a *fee/urgency demand* (processing fee,
  enrollment fee, administrative fee, limited time offer, apply now to qualify,
  one-time fee, 手数料が必要, 今すぐ申請, etc.). A legitimate federal forgiveness
  program charges no application fee; the fee demand is the defining scam tell.
  FTC Consumer Sentinel 2024 (student loan scams spiked post-DOE SAVE plan);
  CFPB student loan fraud advisory 2024. Weight `W_STUDENT_LOAN_SCAM = 25`.
  Category: Sneaking. MITRE: T1566. 10 confusables unit tests + 3 lib unit
  tests + 2 property tests + 4 scoring scenarios. (E54.)
- **Secret / mystery shopper money-mule scam** (`secret_shopper_scam`; E55).
  `has_secret_shopper_scam(s)` fires when the normalized title contains both a
  *shopper-job cue* (secret shopper, mystery shopper, secret shopping, paid
  mystery shopper, 覆面調査員, etc.) AND a *money-movement demand* (deposit a
  check, cash the check, wire the funds, wire money, purchase gift cards, keep
  your commission, 小切手を換金, 送金, etc.). Legitimate mystery shopping
  companies never ask workers to deposit checks and wire money; the check is
  fake and the victim loses the wired funds. FTC Consumer Sentinel 2024; BBB
  ScamTracker 2024 "employment" top-3 pattern. Weight `W_SECRET_SHOPPER_SCAM =
  30`. Category: Sneaking. MITRE: T1566. 10 confusables unit tests + 3 lib
  unit tests + 2 property tests + 4 scoring scenarios. (E55.)
- **MLM / pyramid-scheme recruitment** (`mlm_pyramid_recruitment`; E56).
  `has_mlm_pyramid_recruitment(s)` fires when the normalized title contains both
  an *MLM-framing cue* (earn per referral, residual income, downline bonus,
  tier bonus, recruit and earn, unlimited earning potential, multi-level,
  マルチ商法, ネットワークビジネス, 紹介料を稼ぐ, etc.) AND a *join/invest CTA*
  (join now, start earning today, invest to start, pay to activate, enroll now,
  register to earn, 今すぐ参加, 会員登録で収入, etc.). Distinct from
  `pig_butchering_lure` (romance/trading-platform framing) and `job_scam`
  (WFH with upfront fee). FTC Business Opportunity Rule complaints 2024; FBI
  IC3 2024 pyramid scheme sub-category; 消費者庁 マルチ商法 advisory 2024.
  Weight `W_MLM_PYRAMID_RECRUITMENT = 25`. Category: Sneaking. MITRE: T1566.
  10 confusables unit tests + 3 lib unit tests + 2 property tests + 4 scoring
  scenarios; 1084 tests total. (E56.)
- **Raw-IP URL host** (`ip_host_url`; E57). A structural URL check (like
  `data_uri_page`): when an alert-shaped window's `url` host is a bare IPv4 or
  IPv6 address rather than a hostname, the signal fires. No legitimate support,
  banking, or government page is served from a raw IP — attackers use raw IPs
  to avoid domain registration and per-domain blocklisting. Implemented as a
  pure `std::net::IpAddr` parse on the extracted host (IPv6 brackets stripped)
  inside the existing `alert_shaped` guard; no confusables.rs function needed.
  Weight `W_IP_HOST_URL = 35` (high — raw-IP infrastructure is a strong tell).
  Category: Sneaking. MITRE: T1566. 6 lib unit tests + 4 scoring scenarios.
  (E57; GAP_ANALYSIS_2026H2 area A.)
- **Veterans / military benefit scam** (`veterans_benefit_scam`; E58).
  `has_veterans_benefit_scam(s)` fires when the normalized title contains both a
  *veterans/benefit cue* (VA disability claim, veteran benefit, military pension,
  GI Bill, veterans compensation, service-connected disability, 退役軍人給付,
  傷病補償, etc.) AND a *fee/urgency demand* (processing fee, claim assistance
  fee, expedite your claim, apply now to qualify, unlock your benefits,
  申請手数料, 今すぐ申請, etc.). The VA charges no fee to file disability claims;
  any fee demand is the defining scam tell. FTC Consumer Sentinel 2024
  military/veterans fraud top-5; VA OIG 2024 advisory; BBB Military Line 2024.
  Weight `W_VETERANS_BENEFIT_SCAM = 30`. Category: Sneaking. MITRE: T1566. 10
  confusables unit tests + 3 lib unit tests + 2 property tests + 4 scoring
  scenarios. (E58.)
- **Fake copyright / DMCA violation scam** (`fake_copyright_scam`; E59).
  `has_fake_copyright_scam(s)` fires when the normalized title contains both a
  *violation-notice cue* (copyright violation, DMCA notice, piracy detected,
  illegal download detected, copyright infringement, your IP has been flagged
  for piracy, torrent violation, 著作権侵害, 違法ダウンロード検出, etc.) AND a
  *pay/resolve demand* (pay settlement, pay fine, pay penalty, click to settle,
  contact our legal team, avoid prosecution, prevent legal action, 罰金を支払う,
  示談金, 法的措置を避ける, etc.). A legitimate DMCA takedown targets the service
  provider, not the individual user via a browser overlay demanding immediate
  payment. Distinct from `tax_authority_scam` and `national_id_alarm`. FTC 2024
  "copyright impostor" advisory; APWG Q4 2024 "legal threat" phishing category.
  Weight `W_FAKE_COPYRIGHT_SCAM = 30`. Category: InterfaceInterference. MITRE:
  T1566. 10 confusables unit tests + 3 lib unit tests + 2 property tests + 4
  scoring scenarios; 1132 tests total. (E59.)
- **Signal-registry consistency guards** (F1 follow-up). Two new tests harden
  the `all_signals()` registry against the silent wiring-omission bug class that
  the per-signal boilerplate (7 edit points in `lib.rs` per content signal)
  makes easy to hit. (1) `all_signals_have_real_descriptions_not_name_echo`
  asserts every registered signal's `description` differs from its raw `name`
  — `signal_phrase()` has an `other => other` fallback, so a signal added to
  the NAMES array but missing its phrase arm would otherwise ship a bare machine
  name as its "description" and pass the older non-empty check. (2)
  `every_content_signal_is_in_registry` cross-checks every content/structural
  signal `classify()` can emit (E1–E59 + URL-structural) against the registry,
  so a `signals.push("x")` added without a NAMES entry — which would hide the
  signal from the operator-facing `signals` CLI subcommand — fails loudly.
  Both currently pass (no live bug); they are regression guards making the
  prior 16 additions and all future ones provably discoverable and documented.
  1134 tests total.
- **JP-normalization end-to-end coverage** (Socratic round 2). A self-review
  found the JP scoring scenarios asserted only `score >= 50` — which the window
  geometry (90% coverage + topmost + no-close + unsolicited ≈ 95) already
  satisfies, so they passed even if the Japanese content signal never fired:
  a test "passing for the wrong reason". An empirical probe confirmed the JP
  path is in fact sound (JP literals survive `normalize_for_match` unchanged
  and fire), so this is a test-coverage gap, not a live bug. Fixed by (1)
  strengthening the two JP scenarios to assert the specific signal appears in
  `Verdict.signals`, and (2) adding a 14-test `jp_normalization_invariant`
  module that asserts a representative Japanese scam phrase for every
  JP-bearing signal still fires its detector *after* passing through the full
  `normalize_for_match` pipeline (the exact path `classify()` uses). This
  guards against a future normalization change (e.g. extending
  `strip_symbols_and_emoji` into a Kana range, or a `fold_confusables` entry
  remapping a CJK codepoint) silently killing Japanese-market detection —
  which the raw-string unit tests could not catch. 1148 tests total.
- **Additive-scoring contract guard** (Socratic round 3). A third self-review
  found the same false-confidence pattern in the English scenarios: the 106
  `reaches_suspicious` / `reaches_block` tests assert only a score threshold,
  which the window geometry (≈95) plus an optional phone number (35) already
  clears — so a content signal whose `score += rules.weight_of(...)` was
  dropped (leaving only `signals.push(...)`) would still appear in
  `Verdict.signals` and contribute **zero** to the score without any test
  noticing. New `content_signal_contributes_exactly_its_weight` holds the
  window geometry constant and asserts that adding each content signal's
  trigger phrase raises the score by *exactly* that signal's weight — proving
  both that the weight is applied and that the phrase fires that one signal
  alone (a co-firing sibling inflates the delta and fails the test, which is
  how the survey/charity/AV trigger phrases were refined to single-firing
  variants). Covers 12 representative content signals across E44–E59. 1149
  tests total.
- **Operator-override coverage guard** (Socratic round 4). The existing
  `weight:` override tests proved the mechanism — but only for `fullscreen`, a
  geometry signal. The product's configurability promise is that operators can
  retune *any* signal, including the 59 content signals and the negative
  `user_initiated` relief (−40). A content block changed to add a hardcoded
  `W_X` instead of routing through `rules.weight_of("x", W_X)` would silently
  ignore the operator override, and no test would notice. Two new tests close
  this: `weight_override_honored_for_content_signals` asserts that overriding a
  representative content signal's weight to a sentinel moves the score by
  exactly `sentinel − default` (covers pet_sale / windows_activation / recovery
  / veterans / fake_copyright), and `weight_override_honored_for_negative_user_initiated`
  proves the override flows through for the negative relief weight too (with the
  window kept above the `score.max(0)` clamp so the delta is exact). 1151
  tests total.
- **Decision-threshold boundary guard** (Socratic round 5). The product's most
  important output — the Allow / Suspicious / Block verdict — is decided by
  `score >= BLOCK_THRESHOLD` / `>= SUSPICIOUS_THRESHOLD`. That inclusive `>=`
  semantics at the *exact* threshold value was untested: every existing
  decision test uses scores like 90 or 125, comfortably away from the edges,
  so flipping a `>=` to `>` (downgrading a score of exactly 50 to Allow, or
  exactly 100 to Suspicious) would pass CI silently. New
  `decision_thresholds_are_inclusive_at_exact_boundaries` drives a
  fullscreen-only window to exact scores via a `weight:` override and pins all
  four edges: 49→Allow, 50→Suspicious, 99→Suspicious, 100→Block (plus 0→Allow).
  1152 tests total.
- **`verify` CLI subcommand** (H6). `muten-overlay verify <log> [--json]`
  replays the SHA-256 hash chain of an audit log produced by `monitor`,
  verifies every link's `prev_hash` and `hash` field, and reports the event
  count + Merkle root. Text output shows `chain: OK` (green) or
  `chain: TAMPERED` (red) with the specific broken-link details. `--json`
  emits a structured object with `status`, `event_count`, `chain_head`, and
  `merkle_root`. Exit code 0 for intact logs, 1 for tampered or invalid ones.
  Operators can now verify log integrity from the CLI without writing Rust
  code — previously `verify_chain()` was public API but had no CLI entry
  point. (H6; GAP_ANALYSIS_2026H2 area H.)
- **Data-URI / file-scheme page detection** (`data_uri_page`; A9). An
  alert-shaped window whose `url` field starts with `data:` or `file://` /
  `file:///` is flagged as a tech-support-scam blocklist-bypass technique.
  Attackers serve full `<html>` payloads via `data:text/html,<html>…` to avoid
  per-domain blocklisting (the URL has no hostname). `file://` URLs in
  unsolicited alert-shaped windows indicate a locally-dropped HTML file from a
  prior dropper/installer stage. The detection is a pure scheme-prefix check
  on the URL field inside the existing `alert_shaped` guard; no confusables.rs
  function is needed. Weight `W_DATA_URI_PAGE = 25`. Category: Sneaking.
  MITRE: T1566. 5 lib unit tests + 4 scoring scenarios; 875 tests total.
  (A9; GAP_ANALYSIS_2026H2 area A.)
- **Pig-butchering / romance-investment lure** (`pig_butchering_lure`; E44).
  `has_pig_butchering_lure(s)` fires when the normalized title contains both a
  *romance/group cue* (VIP group, investment mentor, trading mentor, "join our
  trading", "i will teach you", ロマンス詐欺, sns型投資, 一緒に稼ごう, etc.) AND an
  *investment-platform cue* (trading platform, investment platform, guaranteed
  profit/return, crypto investment, forex trading, passive income opportunity,
  double your money, 仮想通貨投資, 高利回り投資, etc.). The AND-pair is the defining
  tell of pig-butchering (sha zhu pan / SNS型投資詐欺) fraud: social engineering
  via romantic or mentorship framing to lure victims into fake trading platforms.
  FBI IC3 2024 #1 fraud category by losses ($4.57B, +53% YoY); FTC 2024 social
  media + romance fraud advisory; IPA/消費者庁 SNS型投資詐欺 advisory 2024.
  Weight `W_PIG_BUTCHERING_LURE = 30`. Category: Sneaking (romance guise
  conceals investment fraud). MITRE: T1566. 10 confusables unit tests + 3 lib
  unit tests + 2 property tests + 4 scoring scenarios; 866 tests total. (E44.)
- **Advance-fee loan scam** (`loan_fee_scam`; E45). `has_loan_fee_scam(s)`
  fires when the normalized title contains both a *loan-approval cue*
  (pre-approved loan, instant loan, guaranteed loan, no credit check loan,
  審査不要ローン, 即日融資, etc.) AND a *fee gate* (processing fee, activation fee,
  upfront fee, "before disbursement", "to receive your loan", 前払い手数料,
  保証金が必要, etc.). A legitimate lender never requires an upfront fee before
  releasing funds; the fee gate is the scam's defining tell. FTC Consumer
  Sentinel 2024 advance-fee fraud top-10; BBB ScamTracker 2024; 消費者庁
  "架空請求・前払い詐欺". Weight `W_LOAN_FEE_SCAM = 30`. Category: Sneaking (fake
  approval conceals advance-fee extraction). MITRE: T1566. 10 confusables unit
  tests + 3 lib unit tests + 2 property tests + 4 scoring scenarios. (E45.)
- **`all_signals()` registry API + `signals` CLI subcommand** (F1). A new
  public function `all_signals() -> Vec<SignalInfo>` returns a machine-readable
  catalog of every built-in detection signal muten ships. Each `SignalInfo`
  carries `name`, `default_weight`, `category` (Gray et al. 2018
  `DarkPatternCategory`), `mitre_techniques` (ATT&CK IDs), `description`
  (the same human phrase used in `Verdict::explain`), and `high_fidelity`
  (whether the signal is text/rule-based vs geometry-based). The list
  currently contains 58 signals ordered by detection layer (geometry →
  blocklist/phone → Unicode evasion → domain intelligence → content). A new
  `signals [--json]` CLI subcommand surfaces this catalog: the default text
  output is a formatted table (signal name, weight, category, MITRE, truncated
  description); `--json` emits a pretty-printed JSON array suitable for SIEM
  lookup-table seeding, MDM console integration, or blocklist-template
  generation. Exit code always 0. This is a structural discoverability
  improvement (roadmap F1): MDM operators no longer need to read source code
  to know which signals exist, what weights they carry, or what dark-pattern
  category they belong to. 4 unit tests (non-empty + unique names, weight
  consistency with `signal_weight()`, nonempty descriptions, key signal
  presence); 828 tests total.
- **Sextortion / webcam-recording extortion lure** (`sextortion_lure`; E25).
  `has_sextortion_lure(s)` fires when the normalized title contains a *camera_cue*
  ("your camera" / "your webcam" / "we have recorded" / "have been recording" /
  "hacked your camera") AND an *extortion_word* (bitcoin/btc/cryptocurrency/crypto/
  payment/pay/your contacts/expose/send this/release this).  Browser-overlay
  sextortion is a significant and growing attack vector: FBI IC3 2024 reported
  sextortion complaints grew 42% YoY; overlays claim webcam footage and demand
  cryptocurrency to prevent release to the victim's contacts.  Weight `W_SEXTORTION =
  25` (slightly above other content signals — the AND-pair is very high specificity).
  Category: `InterfaceInterference`.  MITRE: T1566.  alert_shaped guard prevents
  legitimate webcam-permission dialogs from firing.  6 confusables unit tests +
  3 lib unit tests + 2 property tests + 3 scoring scenarios. (E25.)
- **Package / parcel customs-fee advance-fee lure** (`package_fee_lure`; E24).
  `has_package_fee_lure(s)` fires when the normalized title contains a *package_noun*
  ("your package/parcel/shipment/delivery/order") AND a *fee_demand* ("customs fee/
  duty/charge", "on hold", "release fee", "delivery fee", "unable to deliver", "failed
  delivery").  Delivery/customs advance-fee scam overlays impersonate DHL, FedEx,
  USPS, or customs authorities to extract a small payment.  FTC 2024 annual report:
  imposter-scam delivery variants ranked #2 in consumer-fraud complaints (1.1M
  complaints, $2.7B+ combined losses with prize/imposter category).  Weight
  `W_PACKAGE_FEE = 20`.  Category: `InterfaceInterference`.  MITRE: T1566.
  alert_shaped guard prevents legitimate e-commerce order notifications (user-initiated,
  closable) from firing.  4 positive + 4 negative confusables unit tests + 3 lib
  unit tests + 2 property tests + 3 scoring scenarios; 556 tests total. (E24.)
- **IP address alarm lure** (`ip_alarm_lure`; E23).
  `has_ip_alarm_lure(s)` fires when the normalized title contains an *ip_subject*
  ("ip address" or "your ip") AND an *alarm_word* (hack/infect/flag/report/stolen/
  expos/compromis/block/detect/trac/suspend/breach). Covers the "Your IP address has
  been hacked / flagged by authorities / reported" tech-support-scam staple; one of
  the most common TSS overlay templates (Malwarebytes 2025, Microsoft Security 2024).
  Victims are panicked into calling a fake support number.  Weight `W_IP_ALARM = 20`.
  Category: `InterfaceInterference`.  MITRE: T1566.  `alert_shaped` guard prevents
  legitimate IP-info pages ("Your IP address is 203.0.113.45") from firing.  5 positive
  + 4 negative confusables unit tests + 3 lib unit tests + 2 property tests + 3 scoring
  scenarios + 1 blocklist-coverage test + 1 MITRE taxonomy test; 524 tests total. (E23.)
- **QR code / quishing lure** (`qr_code_lure`; E22).
  `has_qr_code_lure(s)` fires when the normalized title contains a *qr_noun* ("qr code" /
  "qr-code" / "scan qr") AND a *verify_action* (verify/confirm/authenticate/access/scan to/
  scan now/continue/proceed/validate).  "Quishing" (QR phishing) is a major 2025-2026
  growth vector: scam overlays display a QR code directing victims to a malicious site
  that bypasses URL-filter controls (APWG Q4 2024 Phishing Activity Trends Report,
  FBI IC3 2025).  Weight `W_QR_CODE_LURE = 20`.  Category: `InterfaceInterference`.
  MITRE: T1566.  alert_shaped guard prevents legitimate QR displays (e-tickets, payment
  flows) from firing.  5 positive + 4 negative confusables unit tests + 3 lib unit tests
  + 2 property tests + 3 scoring scenarios + 1 blocklist-coverage test; 524 tests
  total. (E22.)
- **Emoji / symbol mid-word evasion stripping** (`strip_symbols_and_emoji`).
  Attackers insert decorative symbols or emoji mid-word to defeat substring
  matching: `"inf⚠️ected"` renders as "infected" to humans but `str::contains
  ("infected")` fails. A new `strip_symbols_and_emoji(s)` function (C8 evasion
  robustness, roadmap §7 — *絵文字/記号の正規化*) strips U+2600–U+27BF (Misc
  Symbols + Dingbats: ⚠️ ☎ ✗) and U+1F000–U+1FFFF (emoji blocks: 🔴 🚨), plus
  U+FE00–U+FEFF variation selectors, before other folding.  CJK/Kana
  (U+3000–U+9FFF+) is **not** stripped; Japanese titles pass through unaltered.
  Integrated as the first step of `normalize_for_match` (now 5 steps instead of 4).
  6 confusables unit tests + 2 property tests (never-panics, never-lengthens,
  idempotent; ASCII unchanged). 534 tests total.
- **MITRE ATT&CK mapping for `sudden_fullscreen_takeover`** added in `mitre.rs`:
  `"sudden_fullscreen_takeover" => &["T1036"]` (Masquerading — an unsolicited
  full-screen takeover imitates a legitimate system dialog). Previously unmapped,
  leaving ATT&CK-correlated threat-hunting queries incomplete.
- **Regression tests for `sudden_fullscreen_takeover` geometry-only bounds**
  in `scoring_scenarios.rs`: a geometry-only unsolicited full-screen window stays
  `Suspicious` (never `Block`) without a content tell; adding a phone number pushes
  it to `Block`. Guards the observe-first invariant against score-weight regressions.
- **SPECIFICATION.md and OVERLAY_BLOCKING.md signal-table updates**.
  Added E18-E21 rows (screen_share_lure / crypto_drain_lure / prize_lure /
  download_trap_lure) that were confirmed-implemented but undocumented in the normative
  spec (spec-drift found by audit).  Added E22-E23 rows alongside the implementation.
  Both docs now list all 27 named signals with weights, conditions, and MITRE tags.
- **Fake download / fake-update overlay gate** (`download_trap_lure`; E21).
  `has_download_trap_lure(s)` fires on two AND-pair patterns: (1)
  *install_demand* — a download/install/update verb + a required/needed/
  to-continue cue; (2) *fake_plugin_gate* — a plugin/extension/codec/flash/
  player/software/component/addon noun + an install verb or required cue.
  Catches the "install codec to view", "flash player update required", "browser
  extension required for this page", "download required to continue" overlay
  family used by drive-by-download malware. Distinguished from `clickfix_instruction`
  (which targets Win+R/clipboard) by requiring no keyboard shortcut. Weight
  `W_DOWNLOAD_TRAP = 20`. Category: `InterfaceInterference`. MITRE: T1566.
  Microsoft Edge security team (2025) and FBI IC3 2024 malware-delivery
  coverage. alert_shaped guard prevents legitimate browser extension install
  prompts from firing. 3 confusables unit test groups + 3 lib unit tests + 2
  property tests + 2 scoring scenarios + 1 MITRE taxonomy test; 492 tests
  total. (E21.)
- **Fake prize / lottery / gift-card overlay lure** (`prize_lure`; E20).
  `has_prize_lure(s)` fires when the normalized window title contains both a
  *prize word* ("won", "winner", "prize", "jackpot", "lottery", "reward",
  "gift card", "selected", "eligible") AND a *claim/collect action* ("claim",
  "collect", "redeem", "verify", "confirm", "click here", "expires",
  "expiring"). The AND-pair design prevents stand-alone congratulatory words
  ("congratulations on your promotion") from triggering. Grounded in FTC 2024
  annual report (imposter scams #1 complaints category, prize/sweepstakes scams
  a major sub-type, $2.7B+ combined losses). Weight `W_PRIZE_LURE = 20`.
  Category: `InterfaceInterference`. MITRE: T1566. alert_shaped guard prevents
  legitimate loyalty-program reward tabs from firing. 4 positive + 1 negative
  confusables unit test groups + 3 lib unit tests + 2 property tests + 2 scoring
  scenarios + 1 MITRE taxonomy test; 482 tests total. (E20.)
- **Crypto / Web3 wallet-drain overlay lure** (`crypto_drain_lure`; E19).
  `has_crypto_drain_lure(s)` fires when the normalized window title matches any
  of three Web3 social-engineering patterns: (1) *wallet_alarm* — a wallet-brand
  word ("wallet", "metamask", "coinbase", "web3", "defi", "nft") paired with a
  compromise token ("compromised", "hacked", "flagged", "suspended", "unauthorized",
  "suspicious activity"); (2) *wallet_coerce* — a coerce verb ("connect",
  "validate", "verify", "link") paired with a wallet-brand word; (3) *seed_harvest*
  — a seed/recovery/private-key phrase ("seed phrase", "recovery phrase", "secret
  recovery", "private key", "mnemonic") paired with a request token ("verify",
  "enter", "confirm", "required", "provide", "submit"). Grounded in FBI IC3 2025
  (crypto investment fraud #1 loss category, $4.57B), IC3 2024 crypto/Web3 fraud
  report, and FTC crypto scam bulletins. Weight `W_CRYPTO_DRAIN = 25`. Category:
  `InterfaceInterference`. MITRE: T1566. alert_shaped guard prevents news-article
  browser tabs ("Coinbase Wallet Compromised in $200M Hack") from firing.
  14 confusables unit tests + 3 lib unit tests + 2 property tests + 3 scoring
  scenarios + 1 MITRE taxonomy test; 471 tests total. (E19.)
- **Screen-share / remote-viewing instruction lure** (`screen_share_lure`; E18).
  `has_screen_share_lure(s)` fires when the normalized window title contains any
  of three social-engineering patterns used by TSS attackers to gain remote
  visibility: (1) *share_screen* — ("share" or "sharing") + ("screen", "desktop",
  or "display"); (2) *remote_enable* — ("allow" or "enable") + "remote" +
  ("view", "access", "control", or "fix"); (3) *grant_support* — "grant" +
  "access" + ("support", "agent", or "technician"). Unlike `remote_access_lure`
  (which requires a named tool such as AnyDesk/TeamViewer), this signal catches
  the broader social-instruction pattern that doesn't name a specific tool.
  Scoped to `alert_shaped` — legitimate Zoom/Teams "share screen" prompts are
  user-initiated and closable, so the guard prevents FPs. Weight `W_SCREEN_SHARE
  = 20`. Category: `InterfaceInterference`. MITRE: T1219 (Remote Access Software).
  Grounded in FTC 2025 remote-access scam advisories and IC3 2024 TSS pattern
  analysis. 9 positive + 5 negative confusables unit tests + 3 lib unit tests +
  2 property tests + 1 MITRE taxonomy test. (E18.)
- **Law-enforcement / authority impersonation signal** (`authority_lure`; E17).
  `has_authority_lure(s)` fires when the normalized window title contains both
  an *agency token* (fbi, cia, interpol, cybercrime, homeland security, department
  of justice, national security, metropolitan police, cyber police, law enforcement)
  AND a *coercion token* (warning, notice, locked, blocked, suspended, illegal,
  violation, fine, penalty, arrested). This covers the Reveton/Winlock ransomware-
  bluff overlay family and modern TSS spinoffs that impersonate law enforcement to
  coerce payment or a call. No existing signal catches this because
  `brand_impersonation` checks URL hosts, not titles, and `fake_scanner_cue` covers
  rogue-AV language. The `alert_shaped` guard prevents news-article browser tabs
  ("FBI Warning: New Phishing Campaign") from firing, as those are user-initiated
  and closable. Weight `W_AUTHORITY_LURE = 25` (higher than other cue signals —
  an LEA agency name in a locked, full-screen overlay is an extremely high-specificity
  combination). Category: `InterfaceInterference`. MITRE: T1566. Grounded in
  Symantec Reveton/Winlock analysis, FBI IC3 2024 LEA-impersonation warning, and
  Europol Operation Strikeback 2025. 3 confusables unit tests + 3 lib unit tests +
  2 property tests + 2 taxonomy tests; 430 tests total. (E17.)
- **Subscription/license expiry coercion signal** (`subscription_lure`; E16).
  `has_subscription_lure(s)` fires when the normalized window title contains all
  three word groups: (1) *subject* — "subscription", "license", "protection",
  "membership"; (2) *expiry* — "expired", "expiring", "expire", "expiration";
  (3) *action* — "renew", "activate", "purchase", "buy", "call", "click".
  This is the canonical softer-scareware pattern (THREAT_INTEL_2026 §3:
  "scareware subscription / prize scams — lower-intensity, often have a close
  button"). Because these windows sometimes have a close button, geometry signals
  alone may not reach Suspicious; the title text is the primary evidence. The
  three-group AND requirement prevents FPs from renewal-reminder emails reflected
  as browser tab titles. The `alert_shaped` guard remains active. Weight
  `W_SUBSCRIPTION_LURE = 15` (lower than other text signals — the pattern is
  lower-confidence than a scan-progress title or a phone number). Category:
  `InterfaceInterference`. MITRE: T1566. 3 confusables unit tests + 3 lib unit
  tests + 2 property tests + 2 taxonomy tests; 422 tests total. (E16.)
- **Fake-scanner / threat-count language signal** (`fake_scanner_cue`; E15).
  `has_fake_scanner_cue(s)` detects five rogue-AV overlay language patterns in
  the normalized window title: (1) *scanning lure* — "scanning for viruses/threats/
  malware/spyware"; (2) *threat count* — "N threats/viruses/infections detected/
  found/identified"; (3) *removal action* — "removing/removed malware/virus/
  spyware"; (4) *repair lure* — "repair/repairing your system/computer/pc"; (5)
  *system error* — "critical system error detected". Grounded in Microsoft Edge
  Scareware Blocker corpus, Malwarebytes rogue-AV samples, and SafetyDetectives
  2026 fake-antivirus guide. Real OS security scanners run as tray processes and
  never lock the desktop with a scan-progress window title; the `alert_shaped`
  guard eliminates FPs from legitimate AV software the user deliberately opened.
  Leet/homoglyph evasion ("v1rus", "thr34t") defeated via `normalize_for_match`.
  Weight `W_FAKE_SCANNER = 20`. Category: `InterfaceInterference` (false authority
  impersonation). MITRE: T1566 (Phishing — fake security alert). `is_high_fidelity`
  updated to include all new text-based signals (cloud_storage_abuse, url_path_lure,
  forced_retention_cue, credential_harvest_cue, fake_scanner_cue) so `Verdict::
  confidence()` correctly accounts for them. 3 confusables unit tests + 3 lib
  unit tests + 3 property tests + 2 taxonomy tests (MITRE + categories); 414 tests
  total. (E15.)

### Changed (breaking)
- **`Verdict.signals: Vec<String>`** (was `Vec<&'static str>`). Required to
  accommodate operator-named composite signals (which are `String` at runtime).
  Callers using `.contains(&"signal_name")` must switch to
  `.iter().any(|s| s == "signal_name")` or `.iter().any(|s| s.as_str() == "signal_name")`.
- **`EnforceOutcome.signals: Vec<String>`** (was `Vec<&'static str>`). Same
  reason; same migration path for callers.
- **`Verdict.mitre_techniques: Vec<String>`** (new field). Callers that
  construct `Verdict` directly (not via `classify()`) must add this field.
  `classify()` populates it automatically.
- **`categories_of` now generic** over `S: AsRef<str>`. Accepts
  `&[&'static str]`, `&[String]`, `&[&&str]`, etc. without type homogenization.
  Existing callers that passed `&[&str]` slices compile without change.

## [0.5.0] — unreleased

Evasion-resistant detection + explainability. Additive and
backward-compatible: the JSON verdict gains fields, no existing field
changes meaning. No new dependencies; still offline, pure,
`forbid(unsafe_code)`.

### Added
- **Merkle anchoring for the audit log** (`merkle` module; RFC 6962 / RFC
  9162). On top of the linear SHA-256 hash chain, the log can now produce a
  single 32-byte **Merkle root** committing to the whole ordered event set, and
  `O(log n)` **inclusion proofs** that a specific event is committed by that
  root. The root is publishable/signable out-of-band as an external **anchor**
  (the Certificate-Transparency / Trillian / Sigstore-Rekor model), so later
  tampering is provable against the anchored root without the original file.
  RFC 6962 leaf/node domain separation (`0x00`/`0x01`) and `SHA-256("")` empty
  tree; verified against the RFC empty-tree and single-leaf known-answer
  vectors plus exhaustive inclusion-proof round-trips for tree sizes 1–33. New
  public API `merkle::{merkle_root, inclusion_proof, verify_inclusion}` and
  `sink::{log_leaves, merkle_root_of_log, inclusion_proof_for_seq}`; the
  `monitor --audit-log` summary now carries `merkle_root`. Pure, offline, no
  new dependency (reuses `sha2`/`hex`). Consistency proofs between tree sizes
  (RFC 9162 §2.1.4) deferred until a rotation workflow needs them. (C6-2/3.)
- **`phone:` blocklist rule type + `blocklist_phone` signal** (weight 40,
  `InterfaceInterference` category). IT can now push a curated list of *known*
  scam phone numbers (`phone: 1-800-555-0100`) via MDM. A number on that list
  appearing in a window is high-confidence evidence wherever it shows up, so —
  unlike the shape-based `phone_number` heuristic — it does **not** require the
  alert shape; it remains additive (not an auto-block), consistent with
  `title:`. Matching is digits-only on the confusable-folded title (so full-
  width / look-alike digits and any separator formatting still match), and an
  11-digit NANP `1` country code is normalized away so `1-800-555-0100` matches
  both `1 800 555 0100` and `(800) 555-0100`. Rules with `< 7` digits are
  dropped as over-broad. New `Ruleset::{match_phone, phone_count}`; grammar in
  `SPECIFICATION.md` §5; illustrative (commented) entries in the example
  blocklist. (C2-2; mradamdavies/number-skid, FTC/IC3.)
- **Crypto-recovery / refund re-victimization blocklist family** (C2-3). Added
  14 title patterns to `examples/overlay-blocklist.txt` — wallet-compromise,
  fund/crypto recovery, refund-eligibility, and seed-phrase-verification lures —
  grounded in FBI IC3 2024 (crypto fraud drove the largest reported losses;
  "recovery" operators re-target prior victims) and scamsniffer's Web3 phishing
  data. Covered by a new `covers_crypto_recovery_refund_scam` regression test;
  confusable-folded matching catches homoglyph variants automatically.
- **Fine-grained gap analysis** (`docs/GAP_ANALYSIS_2026H2.md`): a sub-system
  decomposition (14 areas A–N) of the product, auditing each module directly
  and tracking concrete improvement points with status — finer than the
  themed `IMPROVEMENT_CATALOG_2026H2.md`.

### Fixed
- **IPv6 literal hosts mangled.** The unified `host_str` extractor split on
  `:` for the port, turning `http://[::1]:8080/` into `[`. It now special-cases
  a leading `[` and returns the whole bracketed literal, so the rule and URL
  sides extract identically; regression test added.
- **Audit-chain hash-formula docs corrected.** The `sink.rs` module header and
  `docs/OVERLAY_BLOCKING.md` documented the link hash *without* `timestamp_ms`
  (and the doc without the `\0` separators), disagreeing with the code
  (`link_hash`) and the normative `SPECIFICATION.md` §8. For a tamper-evidence
  primitive the documented byte layout must match exactly — both corrected.
  (No behaviour change; the implementation was already correct.)
- **URL host-extraction drift (`signature()`).** Three copies of URL→host
  parsing had diverged: `signature()` used `split("://").last()` and kept the
  `:port`, so a `://` inside a query string hijacked the host
  (`…/r?next=http://bank.com` → `bank.com`) and ports split the scareware
  repeat-signature. Unified all sites onto one borrowing extractor
  `rules::host_str` (first `://`, authority stops at `/?#`, drops userinfo +
  port); `rules::host_of` lower-cases/`Option`-wraps it; `lib::url_host`
  aliases it; `signature()` now uses it so the repeat-signature host matches
  the classifier's host exactly. Regression test added.
- **`explain()` phrase coverage.** `clickfix_instruction`, `combosquat_brand`,
  and `remote_access_lure` now render human phrases instead of leaking their
  raw signal name into the explanation sentence.

### Added (signals)
- **`remote_access_lure` signal** (weight 20, `InterfaceInterference` category).
  Tech-support scammers walk the victim through installing a legitimate
  remote-access tool — AnyDesk, TeamViewer, UltraViewer, LogMeIn, RustDesk,
  ScreenConnect… — to seize the machine (FTC / FBI IC3 2024). Because these
  tools are legitimate, the name alone is **not** a scam tell; the signal is
  pure **context amplification**: it fires only when the normalized title names
  a tool from `REMOTE_ACCESS_TOOLS` **and** independent fake-alert evidence has
  already fired (`blocklist_title`, `phone_number`, or `clickfix_instruction`).
  A legitimate remote-support session has the tool name but none of those alert
  tells, so it never fires; the signal can only *add* to an already-suspicious
  window and never blocks on its own. New private helper
  `mentions_remote_access_tool()`; 4 new unit tests + category + `explain()`
  phrase. (C2-5.)
- **`combosquat_brand` signal** (weight 30, `InterfaceInterference` category).
  Detects **combosquatting** (Kintis et al., "Hiding in Plain Sight", ACM CCS
  2017): a host label that joins a built-in known brand and a scam-lure word
  (`support`, `secure`, `verify`, `login`, `account`, `billing`…) as distinct
  hyphen-delimited tokens — `apple-support.com`, `paypal-secure-login.net`,
  `microsoft-verify.org`. This is the blind spot of `brand_impersonation`,
  which only fires when a label's confusable *skeleton equals a brand exactly*
  (one token, no lure); a combosquat skeleton (`apple-support`) never collides.
  Combosquatting is more prevalent than typosquatting in the wild and is what
  dnstwist's dictionary / hyphenation fuzzers generate. **FP guard:** requiring
  a hyphen delimiter and exact-token matches means legitimate concatenations
  (`windowsupdate.com`, one token), bare brands, and subdomains
  (`support.apple.com`, separate DNS labels) never fire. Each token is folded
  to its confusable skeleton first, so homoglyph combosquats (`аpple-support`,
  Cyrillic `а`) still match. Additive, never an auto-block — consistent with
  `brand_impersonation`. `explain()` and the signal-phrase table updated for
  both `combosquat_brand` and `clickfix_instruction`. (C2-4.)
- **`clickfix_instruction` signal** (weight 20, `ForcedAction` category). Fires
  when a window is `alert_shaped` (full-screen, modal, or no-close) **and** its
  normalized title contains ClickFix / fake-CAPTCHA instruction tokens: keyboard-
  shortcut references (`win+r`, `ctrl+v`), run-dialog phrases (`open run`,
  `paste the command`), or CAPTCHA / human-verification framing (`captcha`,
  `verify`+`human`, `not a robot`). The blocklist's `title:` entries already
  catch known exact phrases; this structural signal catches novel variants that
  haven't been blocklisted yet (defense-in-depth). The `alert_shaped` guard
  prevents false positives on legitimate reCAPTCHA browser tabs (not fullscreen /
  modal / no-close). Leet-substitution and homoglyph evasion (`c4ptcha`,
  `v3rify`) are defeated by `normalize_for_match` before the check. Example
  blocklist updated in an earlier commit (lines 69–92) with 18 known ClickFix
  / fake-CAPTCHA phrase families. New public function
  `confusables::has_clickfix_instruction()`. (C1-5; MS Security Blog 2025:
  +517 % ClickFix surge, ~47 % of intrusions.)
- **Subprocess-test race fix.** A per-module mutex serializes the four
  `SubprocessController` unit tests within the lib binary, eliminating the
  intermittent ETXTBSY ("Text file busy") failure that appeared when the Rust
  test runner spawned helper scripts in parallel under high concurrency.
- **NO_COLOR-compliant colored CLI output.** The human-readable
  `classify` and `enforce` decisions are now tinted (Block=red,
  Suspicious=yellow, Allow=green) so an operator spots a Block at a
  glance. Color is emitted only when stdout is a real terminal and
  `$NO_COLOR` is unset (https://no-color.org); piped output, redirected
  output, and `--json` stay plain, so machine consumers are unaffected.
  Dependency-free (hand-written ANSI + `std::io::IsTerminal`). The
  `should_colorize`/`paint`/`decision_color` helpers are unit-tested.
  (C4-6.)
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
