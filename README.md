# muten

**Endpoint environment enforcement for managed Windows / macOS / Linux fleets.**

muten keeps managed PCs in a known-good state. It started as a forced-mute
tool and now enforces two things:

- **Audio** — keeps endpoints quiet per policy.
- **Screen** — detects and dismisses **scam overlays** (fake "your computer is
  infected / call support / verify you are human" windows) and **rogue
  antivirus / scareware**.

This repository contains both halves:

- **Audio** — [`crates/muten-audio`](crates/muten-audio) (v0.1.0) plus
  the portable agent folder [`agent/`](agent/): the endpoint
  is muted at sign-in, volume raises are re-muted within a second, and
  only an admin PIN can grant a temporary unmute that expires on its
  own. Windows is the primary target; the same binary also runs on
  Linux (wpctl/pactl backend). See the quick start below.
- **Screen** — [`crates/muten-overlay`](crates/muten-overlay) (v0.6.0).

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

## Quick start — audio (Windows)

The deployable unit is the portable folder [`agent/`](agent/) — no
installer, no registry writes:

1. Put `muten-audio.exe` in `agent/` (`agent/Build.bat` builds it from
   source; `docs/ci/build-windows.yml` builds one in CI).
2. Run `agent/Set-Pin.bat` — creates `policy.json`, sets the admin PIN.
3. Optionally edit the schedule in `agent/policy-editor.html`
   (offline, EN/JA).
4. Run `agent/Start-Muten.bat` and keep its window open.

Temporary sound for a legit need: `agent/Unmute.bat` + the PIN; the
grant expires and the endpoint re-mutes automatically. Everything is
written to a tamper-evident audit log (`audit.log`).

On **Linux** the same binary enforces the same policy through the
desktop's own audio tools — `wpctl` (PipeWire/WirePlumber) or
`pactl` (PulseAudio): build with cargo, run `./muten-audio init`,
then launch [`agent/start-muten-linux.sh`](agent/start-muten-linux.sh)
(`watch --backend linux`). With neither tool usable the agent prints
the reason and stops before enforcing anything. The Linux backend is
tested against a scripted fake machine; a run controlling volume on
a real Linux desktop is still pending verification.

For more than a few machines, the policy can be distributed
centrally: host one master `policy.json` on a shared folder or an
HTTPS URL and each agent pulls it (`--policy-source` on `watch`, or
the one-shot `fetch-policy` command). Only policies that parse and
validate are applied; a failed pull changes nothing and is logged,
and every applied policy is recorded in the audit log with the
SHA-256 of its bytes. The read side of that trail is
`muten-audio fleet-status`: point it at the collected per-machine
audit logs and the master policy, and it lists which policy each
machine last applied, from where, its most recent failure, and
whether its agent last started or STOPPED on an error — machines
running a different policy are flagged STALE. There is
deliberately no signature scheme — protect the distribution
location like an admin credential (details and honest limits in
[`agent/README.md`](agent/README.md)).

**Honest limits** (full text in [`agent/README.md`](agent/README.md)):
the agent is user-mode software — a user with local administrator
rights can stop or remove it, so the PIN/watchdog pair deters casual
unmuting rather than defeating a determined admin; hard enforcement
needs a service under a separate admin account, ACLs, or Group
Policy/MDM. Only the default playback endpoint is controlled. A run
on a real Windows machine is still pending verification, as is
volume control on a real Linux machine.

## Quick start — screen

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

`muten-audio` v0.1.0 — 49 unit tests + 6 property tests + 3 CLI
contract tests, `clippy -D warnings` clean, MSRV 1.75.0. The full
watchdog behaviour is tested against a fake backend; the Windows
helper and a real-machine run are pending verification.

`muten-overlay` v0.6.0 — 1331 unit tests + 26 `cli_contract` integration
tests, `clippy -D warnings` clean, MSRV 1.75.0.
A ready-to-install CI workflow (format/lint/test, an MSRV build, and a
supply-chain gate: cargo-audit + cargo-deny + gitleaks) is provided at
[`docs/ci/ci.yml`](docs/ci/ci.yml); it is **not yet active** — the
GitHub App used by automated sessions cannot push workflow files, so
the repository owner must install it once (instructions at the top of
the file).

## License

[MIT](crates/muten-overlay/LICENSE).
