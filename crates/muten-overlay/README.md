# muten-overlay

The "screen" half of [muten](../../README.md) v0.4.0 — endpoint
environment enforcement. While the rest of muten keeps managed PCs
quiet (audio), this crate detects and dismisses **scam overlays**
(fake "your computer is infected / call support / verify you are
human" windows) and **rogue antivirus** (scareware that floods the
desktop with fake-threat pop-ups).

Pure domain logic: no OS calls, no network, `#![forbid(unsafe_code)]`.
The OS-specific window enumerator/dismisser lives behind the
`OverlayController` trait (like muten's audio backends), so the
classifier is fully testable without a desktop.

## What it does

- **`classify(window, rules) -> Verdict`** — explainable additive
  score over signals (full-screen, topmost, no close button, modal,
  unsolicited, blocklisted host/title …). Returns Allow / Suspicious /
  Block. User-initiated windows get a relief so legitimate full-screen
  apps (video, presentations, exams, kiosks) aren't dismissed.
- **scareware detection** — a sliding-window `RepeatTracker` catches
  the rogue-AV flood (same alert re-popping), and a `process:`
  blocklist catches installed fake-AV by name. Detect & audit only —
  no process killing (that's the EDR's job).
- **`Monitor`** — the daemon loop: enumerate → classify → dismiss
  Block → assess scareware → emit audit events into a tamper-evident
  SHA-256 hash chain.

## Design posture

Observe-first and false-positive-averse. Only a confirmed blocklist
host hit or an unmistakable score (>=100) is dismissed; everything in
between is flagged Suspicious for IT review and left alone. False
positives break the very environments muten protects, so the bias is
deliberate.

## CLI

```bash
# Classify one observed window (JSON) against a blocklist:
muten-overlay classify window.json --rules blocklist.txt   # exit 0/5/6

# Assess scareware from a process + repeat count:
muten-overlay scareware --process PCProtectorPlus.exe --repeats 1 --rules blocklist.txt

# Dry-run the full loop, writing a verifiable chained audit log:
muten-overlay monitor windows.json --rules blocklist.txt --sweeps 3 \
    --audit-log /var/lib/muten/overlay-audit.log
```

## Docs

- `docs/OVERLAY_BLOCKING.md` — scoring, controllers, helper protocol,
  monitor loop, chained audit log.
- `docs/SCAREWARE_DETECTION.md` — rogue-AV detection, scope, the
  origin-gating fix.
- `docs/THREAT_INTEL_2026.md` — the threat landscape the blocklist is
  seeded from.

## License

MIT.
