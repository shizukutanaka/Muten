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

### Added
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

### Fixed
- **Canonical JSON for `link_hash`** (C6-4). The audit-chain link hash used
  `serde_json::to_vec(detail)` to serialize the `AuditEvent.detail` payload,
  relying on serde_json's BTreeMap ordering. A new private `canonical_json()`
  function now sorts object keys explicitly via a recursive visitor, making the
  hash deterministic against any future serde_json representation change.
  Existing log hashes are unchanged (serde_json without `preserve_order` already
  uses BTreeMap). Two new tests confirm determinism and key-insertion-order
  stability.

### Added (this pass)
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
