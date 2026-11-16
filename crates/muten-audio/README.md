# muten-audio

The "audio" half of [muten](../../README.md) — forced-mute enforcement
for managed Windows PCs (company PCs, libraries, schools, kiosks,
call centres): the endpoint is muted at sign-in, any volume raise is
re-muted within a poll interval, and only an administrator holding the
PIN can grant a *temporary* unmute that expires on its own.

Pure policy/watchdog logic plus the agent CLI: no OS audio calls and
`#![forbid(unsafe_code)]` in this crate. The actual Core Audio work
lives in a PowerShell helper (`agent/audio-helper.ps1`) behind the
`AudioBackend` trait — the same brain/hands split muten-overlay uses —
so every enforcement decision is unit-tested without a Windows machine
or a sound device.

## Pieces

| Piece | What it does |
|---|---|
| `Policy` | `policy.json`: master switch, enforcement schedule (weekday + HH:MM windows, overnight supported), UTC offset, unmute permission + per-grant cap, PIN record. Unknown fields are rejected |
| `decide()` | The watchdog decision: policy + observed state + grant → `MuteNow` / `LeaveMuted` / `UnmuteForGrant` / `LeaveUnmuted` / `Standby` |
| `PinRecord` | Admin PIN as a salted, iterated SHA-256 record (100k rounds, constant-time verify). The PIN is never stored or logged |
| `Grant` | A temporary unmute with an expiry; re-read from disk every poll, honoured only while active *and* permitted by policy |
| `Watch` | The poll loop state machine: observe → decide → act → log transitions |
| `AuditLog` | Append-only JSONL with a SHA-256 hash chain (tamper-evident; `verify_chain` checks it) |
| CLI | `init` / `set-pin` / `unmute` / `status` / `verify-log` / `watch` |

## Quick start (development)

```bash
cargo build --release
cargo test            # unit + property + CLI contract tests
```

Deployment on Windows is the portable folder in
[`agent/`](../../agent) — see its README, including the honest-limits
section (user-mode agent; a local admin can stop it; hard enforcement
needs a service account / ACLs / Group Policy).

## Status

v0.1.0 — 61 unit tests + 6 property tests + 4 CLI contract tests,
`clippy -D warnings` clean, MSRV 1.75. The watchdog's full behaviour
(startup mute, re-mute after a raise, grant honoured, expiry re-mute,
corrupt-grant fail-closed) is covered against a fake backend; the
PowerShell helper's Core Audio calls are verified by protocol smoke
test only — **a run on a real Windows machine is still pending**.

Central policy distribution (the `distribute` module): the watchdog
can pull `policy.json` from a shared folder or an HTTPS URL and
applies only what parses and validates; failed pulls are logged and
change nothing, and every applied policy is recorded in the audit
log with the SHA-256 of its bytes. No signature scheme — the trust
boundary is the distribution location itself (see
[`agent/README.md`](../../agent/README.md)).

Fleet status (the `fleet` module, the `fleet-status` command): the
read side of that trail. It aggregates collected per-machine audit
logs — last applied policy hash, source, time, most recent failure —
and flags machines whose policy differs from the master's SHA-256.
Machines are labelled by the log file names the administrator
collected them under; the command reads only the files it is handed
and counts (never silently drops) lines it cannot recognise.
