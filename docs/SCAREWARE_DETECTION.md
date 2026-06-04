# Scareware / Rogue-Antivirus Detection (v0.4.0)

Building on overlay classification, muten detects **rogue security
software** ("fake antivirus" / scareware) — software that, once
installed, floods the desktop with fake-threat pop-ups and demands
payment to "fix" nonexistent infections.

## Why it needs separate logic from overlay classification

A single web overlay is handled by `classify()`. Rogue AV is
different (per 2026 threat intel — NordVPN, SafetyDetectives,
Malwarebytes, PolicyBazaar corporate guide):

- It **persists**: re-launches via Run-key / scheduled-task autostart
  and re-pops the same alert repeatedly.
- It **floods**: the defining behaviour is the *same* fake-threat
  modal appearing over and over, not one clever page.
- It runs as a **local process**, often named to mimic a real product
  ("PC Protector Plus", "Advanced Mac Cleaner", a registry cleaner).
- 2026 escalation: the "fix" download disables real AV and installs a
  rootkit / ransomware; AI localizes the alerts to specific corporate
  software to raise believability.

## Two detection signals

| Signal | What it catches |
|---|---|
| `repeated_flood` | The same overlay signature appears ≥ `REPEAT_THRESHOLD` (3) times within a sliding window (default 2 min). Legitimate apps don't re-pop an identical modal every few seconds. |
| `rogue_av_process` | The owning process matches a known rogue-AV name in the blocklist (`process:` rules). Space/separator-insensitive, so `pc protector plus` matches `PCProtectorPlus.exe`. A single appearance is enough — the software is already installed. |

Either signal yields `Scareware`; both together raise confidence and
both appear in the audit log.

## Scope — detect & audit only (CLAUDE.md I9, least privilege)

muten **does not** kill processes, edit the registry, or delete
files. Removal needs privileges and `unsafe` we refuse to take, and is
the job of an EDR / real antivirus. muten's value is *early,
explainable, offline* detection across a managed fleet: it surfaces

> "PC-07 has shown the same fake-virus pop-up 9× in 2 min and is
> running pcprotectorplus.exe"

into the tamper-evident audit log / SIEM so IT acts before the user
pays. Blocking the download/execution belongs to the OS/EDR layer; the
clipboard/PowerShell side of ClickFix is likewise out of scope.

## API

```rust
use muten_overlay::{RepeatTracker, assess, ScarewareDecision};

let mut tracker = RepeatTracker::default();        // 2-min window
let count = tracker.record(&signature, now_ms);    // appearances in window
let verdict = assess(count, Some(process_name), &ruleset);
if verdict.decision == ScarewareDecision::Scareware {
    // emit an audit event; do NOT kill anything
}
```

`RepeatTracker` is pure and bounded: `prune(now_ms)` drops stale
signatures so memory stays proportional to *recently distinct*
overlays. All of it is `forbid(unsafe_code)`, offline, and covered by
unit + property tests (window counting, idempotent `count`, monotone
`assess`, never-panic).

## CLI (dry-run)

```bash
muten-overlay scareware --process PCProtectorPlus.exe --repeats 1 --rules blocklist.txt
muten-overlay scareware --process chrome.exe --repeats 9 --rules blocklist.txt
# exit: 0 benign, 7 scareware
```

## Blocklist `process:` rules

```text
process: pc protector plus      # matches PCProtectorPlus.exe, pc-protector-plus, ...
process: advanced mac cleaner
process: registrysmart
```

Kept small, auditable, and deployment-specific; IT pushes updates via
MDM. We deliberately exclude contested/borderline tools to honour the
false-positive-averse design.

## Sources
NordVPN "What is a fake antivirus?" (Jan 2026); SafetyDetectives 2026
guide; Malwarebytes Rogue.* detections; PolicyBazaar corporate
scareware brief (Feb 2026); AV-Comparatives rogue-AV reference;
Splunk / Nextron persistence (Run-key / scheduled-task) research.

## Fix: user-initiated windows no longer flagged as floods (v0.4.0)

An earlier smoke test surfaced a false positive: a user-opened video
kept on screen across sweeps tripped the `repeated_flood` signal,
because the monitor recorded *every* appearance into the repeat
tracker regardless of origin.

Rogue-AV floods are by definition **unsolicited** (the software
re-pops the alert without user action). So the monitor now records an
appearance toward the flood tracker **only when the window is not
user-initiated**; user-initiated windows merely probe the existing
count without incrementing it. The rogue-AV *process* signal is
unaffected — a known fake-AV process is still scareware on the first
sweep, even for a user-initiated-looking window.

Covered by `user_initiated_window_not_flagged_as_flood`,
`unsolicited_repeats_still_flood`,
`user_initiated_window_with_rogue_process_still_flagged`, and the
property tests `user_initiated_never_floods` /
`unsolicited_repeats_always_flood`.
