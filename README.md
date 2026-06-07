# muten

**Endpoint environment enforcement for managed Windows / macOS / Linux fleets.**

muten keeps managed PCs in a known-good state. It started as a forced-mute
tool and now enforces two things:

- **Audio** — keeps endpoints quiet per policy.
- **Screen** — detects and dismisses **scam overlays** (fake "your computer is
  infected / call support / verify you are human" windows) and **rogue
  antivirus / scareware**.

This repository currently contains the **screen** half:
[`crates/muten-overlay`](crates/muten-overlay) (v0.5.0).

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
| dark-pattern categories | Tags verdicts with Gray et al. (2018) strategies |
| `Monitor` | Daemon sweep loop + tamper-evident SHA-256 audit chain |
| OS helpers | Windows (Win32), macOS (osascript), X11 (wmctrl), **Wayland** (wlroots) |
| CLI | `classify` / `rules` / `scareware` / `enforce` / `monitor` |

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

## Status

`muten-overlay` v0.5.0 — 191 tests, `clippy -D warnings` clean, MSRV 1.75.0.
CI runs format/lint/test, an MSRV build, and a supply-chain gate
(cargo-audit + cargo-deny + gitleaks) on every PR.

## License

[MIT](crates/muten-overlay/LICENSE).
