# muten

**Endpoint environment enforcement for managed Windows / macOS / Linux fleets.**

muten keeps managed PCs in a known-good state. It started as a forced-mute
tool and now enforces two things:

- **Audio** — keeps endpoints quiet per policy.
- **Screen** — detects and dismisses **scam overlays** (fake "your computer is
  infected / call support / verify you are human" windows) and **rogue
  antivirus / scareware**.

This repository currently contains the **screen** half:
[`crates/muten-overlay`](crates/muten-overlay) (v0.6.0).

## Design principles

- **Explainable, not ML.** Transparent additive scoring with named signals —
  no black-box model, no per-frame computer vision. Every verdict lists *why*.
- **Offline.** No network calls in the detection path. Pure functions over
  window metadata.
- **`#![forbid(unsafe_code)]`.** All OS/FFI work lives in small, swappable
  per-OS helper scripts, never in the crate.
- **Observe-first / false-positive-averse.** Only a confirmed blocklist hit or
  an unmistakable score is dismissed; everything else is audited and left
  alone. False positives break the environments muten protects.
- **Detect & audit, don't destroy.** muten never kills processes or edits the
  registry — removal is the EDR's job.

## What's in `muten-overlay`

| Piece | What it does |
|---|---|
| `classify()` | Explainable overlay scorer → Allow / Suspicious / Block |
| scareware detection | Repeat-flood + rogue-AV process signals |
| confusable folding | Defeats homoglyph/typosquat evasion (title **and** host) |
| 10-lens signal analysis | Dark-pattern category (Gray et al. 2018), MITRE ATT&CK technique, Cialdini persuasion principle, extraction vector + recoverability, kill-chain stage, victim-targeting profile, loss magnitude, campaign fingerprint, response-priority triage, abused-authority impersonation |
| `Monitor` | Daemon sweep loop + tamper-evident SHA-256 audit chain (RFC 6962 Merkle root + inclusion proofs) |
| OS helpers | Windows (Win32), macOS (osascript), X11 (wmctrl), **Wayland** (wlroots) |
| CLI | `classify` / `scareware` / `rules` / `enforce` / `triage` / `monitor` / `daemon` / `verify` / `signals` |

Detection is informed by published threat intel and the security literature
(FBI IC3 2025, Microsoft Edge Scareware Blocker, IPA/消費者庁 for Japanese
support-scam, and arXiv work on TSS, dark patterns, and homoglyph evasion) —
see [`docs/THREAT_INTEL_2026.md`](docs/THREAT_INTEL_2026.md).

## Quick start

```bash
cd crates/muten-overlay
cargo build --release

# Classify one observed window against a blocklist:
cargo run -- classify window.json --rules ../../examples/overlay-blocklist.txt

# Run the sweep loop, writing a verifiable tamper-evident audit log:
cargo run -- monitor windows.json --rules ../../examples/overlay-blocklist.txt \
    --sweeps 3 --audit-log overlay-audit.log
```

A window is described as JSON (see
[`examples/overlay-sample.json`](examples/overlay-sample.json)); on a real host
an OS helper in [`installer/overlay-helper/`](installer/overlay-helper)
produces these.

## Documentation

- [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md) — normative spec: types,
  classifier contract, blocklist grammar, audit chain, controller & CLI contract.
- [`docs/OVERLAY_BLOCKING.md`](docs/OVERLAY_BLOCKING.md) — scoring, controllers,
  helper protocol, monitor loop, audit chain.
- [`docs/SCAREWARE_DETECTION.md`](docs/SCAREWARE_DETECTION.md) — rogue-AV
  detection and scope.
- [`docs/THREAT_INTEL_2026.md`](docs/THREAT_INTEL_2026.md) — the threat
  landscape and research grounding.
- [`docs/IMPROVEMENT_ROADMAP.md`](docs/IMPROVEMENT_ROADMAP.md) — 10-category
  improvement roadmap.
- [`docs/RESEARCH_IMPROVEMENTS_2026H1.md`](docs/RESEARCH_IMPROVEMENTS_2026H1.md) —
  2026-H1 follow-up survey (comparable software + arXiv) of new improvement
  points across detection, Unicode/dark-patterns, audit integrity, and supply chain.
- [`docs/IMPROVEMENT_CATALOG_2026H2.md`](docs/IMPROVEMENT_CATALOG_2026H2.md) —
  2026-H2 catalog: 10 categories × 10 improvement points, each grounded in
  arXiv + GitHub, with status vs v0.5.0 and a cross-cutting shortlist.
- [`docs/GAP_ANALYSIS_2026H2.md`](docs/GAP_ANALYSIS_2026H2.md) — fine-grained,
  sub-system-level (14 areas A–N) audit of the actual code surface, with
  concrete per-module improvement points and live status.
- [`docs/MODEL_PLAYBOOK.md`](docs/MODEL_PLAYBOOK.md) — which Claude model
  (Haiku/Sonnet/Opus/Fable 5) and which skill to use for which kind of
  work on this repo, grounded in actual session history.
- [`docs/SPECIFICATION_V2.md`](docs/SPECIFICATION_V2.md) — **historical
  only** (Round 19–30 snapshot, superseded by `SPECIFICATION.md` above);
  kept for its detailed per-script Unicode-confusable fold table and
  strengths/weaknesses/improvement-areas analysis of that era.
- [`docs/WORK_ORDERS.md`](docs/WORK_ORDERS.md) — executable work orders
  for future Claude (Opus/Sonnet) sessions: per-task procedures,
  prerequisites, verification protocols, and hard prohibitions, bridging
  the audit doc (*what*) and the model playbook (*who*).

## Status

**`muten-overlay` v0.6.0 — complete.** 1,333 unit tests + 26
`cli_contract` integration tests + 7 further integration suites;
`clippy -D warnings` clean.

> **Why "complete", and how it was verified.** 1,331 of those unit tests
> and every integration suite were measured green by an end-to-end
> `cargo test` at the baseline commit `549df29`. Since then exactly one
> *source* file changed — `src/confusables.rs` (+44/−2) — and its full
> suite grew 673 → 675 and runs green via standalone `rustc`, with the
> new DR-12 tests teeth-proven. The other 15 modules are byte-identical
> to that baseline. The touched *test* files are compile-verified with
> their behaviour checked against the real detectors and the real shipped
> helper scripts. Full evidence chain: the **Completion Verdict** in
> [`docs/FEATURE_AUDIT_2026H2.md`](docs/FEATURE_AUDIT_2026H2.md).
>
> Re-running `cargo test` end-to-end on the current tree re-certifies
> that chain rather than filling a gap in it; CI runs it on every push
> once [`docs/ci/ci.yml`](docs/ci/ci.yml) is installed.

> **MSRV 1.75 restored (DR-23 fixed).** An auto-merged Dependabot bump to
> `clap 4.6.6` (MSRV **1.85**) had broken the advertised
> `rust-version = "1.75.0"`, and `clap` is a default feature, so
> `cargo build` failed on the promised toolchain. `clap` is pinned back
> to `=4.5.20` (MSRV 1.74) with `Cargo.lock` re-resolved consistently
> (`anstream` 0.6.21, MSRV 1.66; `clap_lex` 0.7.7), and a Dependabot
> `ignore` for `clap >=4.6.0` prevents recurrence. No direct dependency
> now declares an MSRV above 1.74. *Caveat:* this was verified from
> crates.io `rust_version` metadata — a full `cargo build` on a 1.75
> toolchain still needs `static.crates.io`, which this environment's
> egress policy blocks (403).

Run `./scripts/verify.sh` for the checks that need no toolchain (helper
syntax, blocklist lint, `Cargo.lock`↔`Cargo.toml` pin sync,
`dependabot.yml` validity). It reports skipped checks explicitly — a skip
is never counted as a pass. `docs/ci/ci.yml`'s `verify` job runs the same
script, so local and CI verification cannot drift apart.
[`docs/WORK_ORDERS.md` §1.5](docs/WORK_ORDERS.md) states precisely what
blocks a release and what does not.
A ready-to-install CI workflow (format/lint/test, an MSRV build, and a
supply-chain gate: cargo-audit + cargo-deny + gitleaks) is provided at
[`docs/ci/ci.yml`](docs/ci/ci.yml); it is **not yet active** — the
GitHub App used by automated sessions cannot push workflow files, so
the repository owner must install it once (instructions at the top of
the file).

## License

[MIT](crates/muten-overlay/LICENSE).
