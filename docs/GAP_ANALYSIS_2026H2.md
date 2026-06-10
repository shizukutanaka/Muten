# muten-overlay — Fine-Grained Gap Analysis (2026-H2)

> A **sub-system-level** decomposition of the product, finer than the
> 10-category [`IMPROVEMENT_CATALOG_2026H2.md`](IMPROVEMENT_CATALOG_2026H2.md).
> The catalog groups by *theme* (scareware, TSS, Unicode…); this document
> walks the **actual code surface** module by module, enumerates concrete
> improvement points found by direct audit, and tracks their status.
>
> Target: `muten-overlay` v0.6.0 · audited 2026-06 · 312 tests.
> Status: ✅ done · 🔧 fixed-this-pass · 🔻 planned · 🆕 newly-found · ⛔ out-of-scope (I3)
> Invariants (every item respects): offline · pure functions over window
> metadata · no ML/CV · `#![forbid(unsafe_code)]` · explainable additive
> score · false-positive-averse (observe-first) · detect-&-audit only.

This pass **split the product into 14 sub-systems** (A–N), audited each,
and fixed the concrete defects marked 🔧. The remainder are tracked here
with priority (★–★★★).

---

## A. Domain types (`lib.rs`: `OverlayWindow`, `Origin`, `Verdict`)

| # | Pt | Improvement | Status |
|---|----|-------------|--------|
| A1 | ★★★ | `#[serde(default)]` so partial helper JSON parses | ✅ v0.5.0 |
| A2 | ★★ | All public fields/variants documented (`deny(missing_docs)`) | ✅ v0.5.0 |
| A3 | ★ | `#[non_exhaustive]` on `Decision`/`Origin`/`DarkPatternCategory` | ⛔ closed enums; forces `_` arms downstream (deferred, tracked C3-10) |
| A4 | ★ | `coverage_percent > 100` saturates to full-screen, never errors | ✅ documented in spec §2.2 |
| A5 | ★ | `OverlayWindow` validation builder (reject NaN-ish combos) | 🔻 low value; serde defaults suffice |

## B. Classifier core (`lib.rs`: `classify`, score model)

| # | Pt | Improvement | Status |
|---|----|-------------|--------|
| B1 | ★★★ | Additive explainable score with named weights | ✅ baseline |
| B2 | ★★★ | Hard host block short-circuits; title is additive not auto-block | ✅ baseline |
| B3 | ★★★ | Bounded-composite cap (lock 95 / takeover 85 < BLOCK) | ✅ v0.5.0 |
| B4 | ★★ | Monotonicity + threshold property tests | ✅ baseline |
| B5 | ★★★ | Composite **AND**-condition rules as first-class config (YARA/Sigma-style) | ✅ v0.6.0 (C5-2) |
| B6 | ★★ | Confidence-weighted signals (decay low-fidelity helper fields) | ✅ v0.6.0 — `ConfidenceLevel` enum + `Verdict::confidence()` + `signal_weight()` + `score_breakdown()`; 6 tests |
| B7 | ★★ | Threshold rationale doc + audit-log-driven A/B of firing rates | ✅ v0.6.0 `signal_firing_stats()` in sink.rs |
| B8 | ★ | Per-signal FP-rate aggregation from audit log | ✅ v0.6.0 `SignalStats { blocks, suspicious }` |

## C. Text normalization (`confusables.rs`: pipeline)

| # | Pt | Improvement | Status |
|---|----|-------------|--------|
| C1 | ★★★ | `strip_invisibles → fold_confusables → fold_leet_in_words → lower` | ✅ v0.5.0 |
| C2 | ★★ | Symmetric normalization of stored patterns + match titles | ✅ v0.5.0 |
| C3 | ★★ | Idempotence + never-grow-length invariants property-tested | ✅ v0.5.0 |
| C4 | ★ | Migrate hand-rolled fold to `icu4x` full UTS#39 | ⛔ dependency/binary cost vs I3; revisit only if subset proves insufficient |

## D. Confusable / homoglyph signals (`confusables.rs` + `classify`)

| # | Pt | Improvement | Status |
|---|----|-------------|--------|
| D1 | ★★★ | `mixed_script` (Latin × Cyrillic/Greek within token) | ✅ v0.5.0 |
| D2 | ★★★ | `whole_script_confusable` (UTS#39 §5 blind spot) | ✅ v0.5.0 |
| D3 | ★★★ | `brand_impersonation` (UTS#39 skeleton vs known brands) | ✅ v0.5.0 |
| D4 | ★★ | `compat_chars_present` (enclosed/circled letters) | ✅ v0.5.0 |
| D5 | ★★ | `mixed_number_systems` (ICU MIXED_NUMBERS) | ✅ v0.5.0 |
| D6 | ★★ | `excessive_combining_marks` (Zalgo) | ✅ v0.5.0 |
| D7 | ★★ | `bidi_override` (Trojan Source LRO/RLO) | ✅ v0.5.0 |
| D8 | ★★★ | `combosquat_brand` (brand + lure hyphen tokens; CCS 2017) | ✅ v0.5.0 |
| D9 | ★★★ | Restriction-Level continuous scoring (UTS#39 §5.2) | 🔻 C8-4 — mostly subsumed by D1/D2/D8 |
| D10 | ★ | dnstwist omission/insertion/transposition neighbour gen | 🔻 C2-4 remainder (combosquat shipped) |

## E. Threat-family signals (`classify` + blocklist)

| # | Pt | Improvement | Status |
|---|----|-------------|--------|
| E1 | ★★★ | `phone_number` in alert-shaped window (NDSS 2017) | ✅ baseline |
| E1b | ★★ | `phone:` blocklist rule + `blocklist_phone` (curated known scam numbers, no alert-shape needed) | 🔧 added (C2-2) |
| E2 | ★★ | `clickfix_instruction` (fake-CAPTCHA / Win+R; +517% 2025) | ✅ v0.5.0 |
| E3 | ★★ | `remote_access_lure` (AnyDesk/TeamViewer, context-amplified) | ✅ v0.5.0 |
| E4 | ★★ | Crypto-recovery / refund re-victimization families (IC3 2024) | 🔧 added to example blocklist + coverage test |
| E5 | ★★ | Full-width digit phone numbers (JP 0120 フリーダイヤル) | ✅ folded before scan (verified) |
| E6 | ★ | International phone formats → per-country weight (0120/+44) | ✅ v0.6.0 |
| E7 | ★ | Countdown/timer urgency cue (`\d+:\d{2}` + urgency word) | 🔻 C1-8 — FP-prone (media players); needs strong gating |
| E8 | ★ | Remote-access tool as `process:` family (not just title) | 🔻 needs collector process attribution |

## F. Blocklist engine (`rules.rs`)

| # | Pt | Improvement | Status |
|---|----|-------------|--------|
| F1 | ★★★ | host/title/process rules; bare-line = host; comments | ✅ baseline |
| F2 | ★★ | Malformed line skipped, never aborts load | ✅ baseline |
| F3 | ★★ | host match folds confusables + strips invisibles | ✅ v0.5.0 |
| F4 | ★★★ | **Single** URL→host extractor (was 3, had drift) | 🔧 unified to `host_str`/`host_of` |
| F5 | ★ | IPv6 literal hosts (`http://[::1]/`) were mangled by `:port` split | 🔧 `host_str` now keeps the bracketed literal; regression test |
| F6 | ★ | Regex/glob title patterns (bounded, ReDoS-safe) | 🔻 C5-8 |
| F7 | ★ | Distill large community lists → focused offline list (MDM) | 🔻 C1-2/C1-6 (transformer tool, offline) |

## G. Scareware detection (`scareware.rs`)

| # | Pt | Improvement | Status |
|---|----|-------------|--------|
| G1 | ★★★ | repeat-flood + rogue-AV process signals | ✅ baseline |
| G2 | ★★ | Sliding-window `RepeatTracker` with prune | ✅ baseline |
| G3 | ★★★ | Repeat-signature host now matches classifier host exactly | 🔧 via F4 (was port/`://`-in-query drift) |
| G4 | ★ | Expand rogue-AV families from CCCS-Yara FakeAV names | 🔻 C1-1 data |

## H. Dark-pattern taxonomy (`categories.rs`)

| # | Pt | Improvement | Status |
|---|----|-------------|--------|
| H1 | ★★ | Gray et al. (2018) 5-strategy mapping on every verdict | ✅ baseline |
| H2 | ★★ | All v0.5.0 signals mapped (Sneaking/ForcedAction/InterfaceInterference) | ✅ v0.5.0 |
| H3 | ★ | MITRE ATT&CK technique tags on audit events (T1566/T1656) | ✅ v0.6.0 |

## I. Explainability (`Verdict::explain`)

| # | Pt | Improvement | Status |
|---|----|-------------|--------|
| I1 | ★★★ | Deterministic plain-language sentence from signals | ✅ v0.5.0 |
| I2 | ★★ | Every shipped signal has an `explain()` phrase (no raw-name leak) | 🔧 added clickfix/combosquat/remote_access phrases |
| I3 | ★ | Composite-rule wording in explain() | ✅ v0.6.0 (with B5) |

## J. Audit chain (`sink.rs`)

| # | Pt | Improvement | Status |
|---|----|-------------|--------|
| J1 | ★★★ | Linear SHA-256 hash chain, format-compatible w/ muten-audit-chain | ✅ baseline |
| J2 | ★★★ | Detects edit/delete/reorder/backdate; refuses append onto broken log | ✅ baseline |
| J3 | ★★★ | Torn-final-line crash recovery (vs tamper) | ✅ v0.5.0 |
| J3b | ★★ | Hash-formula docs (`sink.rs` header, OVERLAY_BLOCKING.md) omitted `timestamp_ms` / separators — drift from code & spec §8 | 🔧 both corrected to match `link_hash` |
| J4 | ★★★ | Merkle tree: inclusion proofs + anchorable root (RFC 6962/9162) | 🔧 added (`merkle` module + `monitor` summary `merkle_root`) |
| J4b | ★★★ | Merkle **consistency** proofs between tree sizes (RFC 9162 §2.1.4) | ✅ v0.6.0 — `merkle::{consistency_proof, verify_consistency}` + `sink::consistency_proof_for_range`; 8 tests |
| J5 | ★★ | Signed checkpoints (Ed25519 device key over the root) | 🔻 C6-3/10 (root now exists to sign) |
| J6 | ★ | Multi-file rotation w/ chain continuity | 🔻 C6-9 |

## K. OS controller / helpers (`controller.rs` + `installer/`)

| # | Pt | Improvement | Status |
|---|----|-------------|--------|
| K1 | ★★★ | Trait + Null/Subprocess controllers; 3-verb helper protocol | ✅ baseline |
| K2 | ★★ | Win32/macOS/X11/Wayland reference helpers | ✅ baseline |
| K3 | ★★ | Subprocess unit tests race-free under parallelism (ETXTBSY) | ✅ fixed (per-module mutex) |
| K4 | ★★ | Honest `has_close_button` / `blocks_input` / `origin` / `age_ms` via a11y/UIA | 🔻 C7-2..6 — needs real OS work (outside pure crate) |

## L. Monitor loop (`monitor.rs`)

| # | Pt | Improvement | Status |
|---|----|-------------|--------|
| L1 | ★★★ | `sweep`/`run` with injected clock + stop flag; per-outcome audit events | ✅ baseline |
| L2 | ★★ | Allow is not audited (quiet log) | ✅ baseline |
| L3 | ★ | Dynamic sweep-interval shortening on detection | ✅ v0.6.0 — `SweepOutcome {dismissed, detections}`, `RunConfig::alert_interval_ms`; 3 tests |
| L4 | ★ | Prometheus textfile metrics (offline pull) | ✅ v0.6.0 |

## M. CLI (`bin/cli.rs`)

| # | Pt | Improvement | Status |
|---|----|-------------|--------|
| M1 | ★★ | `--json` on all decision subcommands; stdin `-`; stable exit codes | ✅ v0.5.0 |
| M2 | ★★ | NO_COLOR-compliant colored decisions | ✅ v0.5.0 |
| M3 | ★★ | Exit codes documented in `--help` | ✅ v0.5.0 |
| M4 | ★★ | NDJSON streaming classify (1 window/line) | ✅ v0.6.0 |
| M5 | ★ | Shell completions / man page | ⛔ needs `clap_complete`/`clap_mangen` deps (no-new-deps) |
| M6 | ★ | `--version` with commit/date build info | ✅ v0.6.0 |

## N. Supply chain / packaging (`Cargo.toml`, CI, `deny.toml`)

| # | Pt | Improvement | Status |
|---|----|-------------|--------|
| N1 | ★★ | cargo-deny + cargo-audit + gitleaks + MSRV build + clippy -D | ✅ baseline |
| N2 | ★★ | `deny(missing_docs)` doc gate | ✅ v0.5.0 |
| N3 | ★★★ | cargo-semver-checks (API-break gate) | 🔻 C3-3 (CI only — needs workflow push permission) |
| N4 | ★★★ | feature flags (cli/monitor/sink optional) + cargo-hack combos | ✅ v0.6.0 — `cli` feature gates binary + clap; `[[test]] cli_contract required-features=["cli"]`; `no-default-features` builds library-only |
| N5 | ★★★ | `no_std` pure-core split (`muten-core`) | 🔻 C3-5 |
| N6 | ★★ | cargo-fuzz on parsers (blocklist/window JSON) | 🔻 C3-6 |
| N7 | ★ | cargo-mutants effectiveness; cargo-public-api snapshot | 🔻 C3-7/8 |

---

## Fixed in this pass (🔧)

1. **F4 / G3 — host-extractor drift (correctness).** `signature()` used
   `split("://").last()` + kept `:port`, so a `://` in a query string
   hijacked the host and ports split repeat-signatures. Unified all three
   sites onto one borrowing `rules::host_str` (first `://`, authority to
   `/?#`, drop userinfo+port); `host_of` lower-cases it; regression test
   added.
2. **E4 — crypto-recovery / refund families.** Added 14 title patterns
   (wallet-compromise, fund-recovery, refund-eligibility, seed-phrase
   verification) grounded in FBI IC3 2024 + scamsniffer, with a
   `covers_crypto_recovery_refund_scam` coverage test.
3. **I2 — explain() phrase coverage.** `clickfix_instruction`,
   `combosquat_brand`, `remote_access_lure` now have human phrases instead
   of leaking their raw signal name into the explanation.

## Newly found, all fixed this pass (🔧)

- **F5 — IPv6 literal hosts.** `host_str` split on `:` for the port, which
  mangled `http://[::1]:8080/` into `[`. Now special-cases a leading `[`
  and keeps the bracketed literal; regression test added.
- **J3b — hash-formula doc drift.** The `sink.rs` module header and
  `OVERLAY_BLOCKING.md` documented the link hash *without* `timestamp_ms`
  (and the latter without the `\0` separators), disagreeing with both the
  code (`link_hash`) and the normative spec §8 — a real hazard for a
  tamper-evidence primitive. Both corrected to the exact byte layout.

## Highest-leverage next steps (cross-cutting)

1. **B5 / C5-2** — composite AND-condition rules (the one large detection
   feature not yet built; would let `coercive_overlay` and friends be
   expressed declaratively with explainability preserved).
2. **J4b / J5 / C6-3** — Merkle **consistency** proofs + an Ed25519-signed
   checkpoint over the now-available root (completes the anchor story:
   central truncation/tamper detection from signed checkpoints).
3. **N4 / C3-4** — feature flags + `no_std` core split (broadens the
   library's consumers without touching detection logic).
