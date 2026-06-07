# Overlay Blocking (v0.4.0)

muten v0.4.0 extends the product from audio-only enforcement to
**endpoint environment enforcement**: in addition to keeping managed
PCs quiet, it detects and (optionally) dismisses scam overlays — the
full-screen "your computer is infected / call support / you have won"
windows that plague library, school, kiosk, and call-center PCs.

## Design posture: observe first, block conservatively

False positives are catastrophic. Wrongly dismissing a video player,
a presentation, an exam app, or a kiosk's own UI breaks the
environments muten exists to protect. So:

- The default ruleset is empty and the classifier only **Blocks** on
  a confirmed blocklist host match or an unmistakable heuristic score
  (≥ 100).
- Everything between `SUSPICIOUS_THRESHOLD` (50) and `BLOCK_THRESHOLD`
  (100) is **Suspicious** — audited for IT review, not dismissed.
- Below 50 is **Allow**.

This mirrors the audio side's `pilot-observe` mode.

## How it scores (explainable, per CLAUDE.md I6)

`muten_overlay::classify` sums named signal weights and records which
fired in the `Verdict.signals` list, so every decision is traceable
in the audit log:

| Signal | Weight | Rationale |
|---|---:|---|
| fullscreen (≥85% coverage) | +30 | scams grab the whole screen |
| topmost | +15 | always-on-top to stay in your face |
| no_close_button | +25 | scams hide/fake the close affordance |
| blocks_input | +20 | modal capture traps the user |
| unsolicited | +25 | appeared with no user action |
| very_new (<1s) | +10 | just popped up |
| blocklist_title | +40 | title matches a known scam phrase |
| phone_number | +35 | a support number in an alert-shaped window (NDSS 2017) |
| mixed_script | +30 | title/host mixes Latin with Cyrillic/Greek (homoglyph disguise) |
| whole_script_confusable | +30 | title/host label is all-Cyrillic or all-Greek but every letter folds to a Latin look-alike (blind spot of mixed_script; UTS#39 §5) |
| compat_chars_present | +20 | title/host uses enclosed/circled Latin letters Ⓐ-Ⓩ/ⓐ-ⓩ (U+24B6-U+24E9) — evades plain-text matching; normalized automatically so blocklist matching still works |
| bidi_override | +30 | title/host uses an LRO/RLO directional override (Trojan Source) |
| brand_impersonation | +40 | host label is a UTS#39 skeleton homograph of a known brand |
| input_trap | +5 | full-screen + topmost + modal "screen lock" (bounded; see below) |
| sudden_fullscreen_takeover | +5 | unsolicited window seizes full screen instantly (bounded) |
| user_initiated | −40 | the user opened it → trust more |
| blocklist_host | → hard Block | confirmed scam host |

A benign user-opened full-screen video scores ~5 (Allow). A classic
fake-virus overlay scores ~125 (Block).

The `input_trap` composite fires when a window is **full-screen AND
topmost AND input-grabbing** — the shape of a browser/screen *locker*
(Keyboard-Lock / Pointer-Lock abuse, and scareware kits like CypherLoc
whose encrypted in-browser payload evades content scanners but not the
window-level lock shape). Its bonus is deliberately small: the bare lock
shape with no content or provenance tell tops out at 95 — still
`Suspicious`, never an automatic `Block` — so a legitimately locked-down
full-screen app (a kiosk shell, an exam lockdown browser) with
unknown origin is observed, not dismissed. Any real scam evidence
(unsolicited origin, a phone number, a blocklist hit) still blocks it.

The `sudden_fullscreen_takeover` composite fires when an **unsolicited**
window seizes the **full screen, on top, the instant it appears** (a
real, small, nonzero age). This is the behavioural tell Microsoft's Edge
Scareware Blocker keys on, and muten's no-CV way to flag brand-new scam
domains the blocklist hasn't caught yet — from their shape over time
rather than their content. Its bonus is likewise bounded (the bare
pattern tops out at 85, `Suspicious`); a content or provenance tell
still decides a `Block`.

### Text normalization (defeating evasion)

Before a title is matched against the blocklist it is run through
`confusables::normalize_for_match`, which composes four offline,
dependency-free passes:

1. **strip invisibles** — drop zero-width and BiDi-control characters
   (`U+200B…200D`, `U+FEFF`, soft hyphen, `U+202A…202E`, …) that split a
   word past a naive substring match.
2. **fold confusables** — Cyrillic/Greek/full-width look-alikes → ASCII
   skeleton (e.g. Cyrillic `і` → `i`).
3. **fold leetspeak in words** — `0→o 1→i 3→e 4→a 5→s 7→t`, but only
   inside tokens that already contain a letter, so phone numbers and
   counts (pure-digit runs) are left intact.
4. **lowercase**.

The `mixed_script` signal is computed on the **raw** title and host
*before* folding (folding erases the evidence). It deliberately ignores
CJK/Kana, so a legitimate Japanese+Latin title is never flagged — the
project's false-positive-averse posture for the JP market. The
phone-number scan runs on the original (non-leet-folded) text so digits
survive.

## Blocklist format (offline)

Plain text, one rule per line, pushed via MDM and read offline:

```text
host: win-prize-now.example      # block host + any subdomain
title: your computer is infected # title substring contributes to score
bare-host.example                # bare line == host rule
# comments after '#'
```

See `examples/overlay-blocklist.txt`. Kept small and
deployment-specific — auditable by eye, not a 100k-entry ad filter.

## CLI (dry-run)

```bash
muten-overlay rules examples/overlay-blocklist.txt
muten-overlay classify examples/overlay-sample.json --rules examples/overlay-blocklist.txt
# exit: 0 Allow, 5 Suspicious, 6 Block
echo '{...OverlayWindow JSON...}' | muten-overlay classify -
```

## What's pure vs OS-specific

`muten-overlay` is pure domain logic (`forbid(unsafe_code)`, no OS, no
network), exactly like `muten-core`. The OS-specific pieces — a window
enumerator that produces `OverlayWindow` snapshots, and a dismisser
that acts on `Verdict::Block` — live alongside the audio backends and
are wired in by the daemon. That keeps the classifier fully testable
without a desktop, and it's covered by unit + property tests
(monotonicity, threshold consistency, never-panic on arbitrary input).

## Privacy (CLAUDE.md I5)

The classifier runs entirely on-device. No URL, title, or window
metadata leaves the machine. The blocklist is a local file. There is
no runtime network surface — consistent with muten's offline-first
guarantee.

## Enforcement loop (v0.4.0 update)

The classifier's `Block` verdict is now actionable via the
`OverlayController` trait (the overlay-side analogue of
`muten-audio`'s `AudioBackend`):

```rust
pub trait OverlayController {
    fn enumerate(&self) -> Result<Vec<EnumeratedWindow>, ControllerError>;
    fn dismiss(&self, id: &WindowId) -> Result<bool, ControllerError>;
    // + name(), available()
}
```

`enforce(controller, rules)` runs one full sweep: enumerate every
window, `classify` each, and `dismiss` only the ones scoring `Block`.
`Suspicious` and `Allow` windows are reported (for the audit log) but
never dismissed. A dismiss error on one window folds into
`dismissed = false` rather than aborting the sweep.

`NullController` is the dry-run implementation used in CI, tests, and
observe-mode rollouts: it enumerates a seeded list and "dismisses" by
recording the id, so the entire detect→decide→act loop runs and is
auditable without touching a real desktop. Real OS controllers
(Win32 / macOS / X11-Wayland) implement the same trait and are wired
in by the daemon — the loop logic does not change.

`signature(&OverlayWindow)` gives the crate-defined repeat-detection
key (normalized title + source host) so the scareware `RepeatTracker`
sees "the same pop-up" consistently across callers.

### CLI

```bash
# Dry-run the whole loop over a JSON array of {id, ...OverlayWindow}:
muten-overlay enforce windows.json --rules blocklist.txt
# exit: 0 if nothing blocked, 6 if any window blocked
```

## OS controllers (v0.4.0 update 2)

Two `OverlayController` implementations now ship:

- **`NullController`** — dry-run; enumerates a seeded list and records
  dismiss requests. Used in CI, tests, and observe-mode rollouts.
- **`SubprocessController`** — real-host controller that shells out to
  a per-OS helper, the same pattern as `muten-audio`'s pactl backend.
  muten never links a window-manager API, so the crate keeps
  `#![forbid(unsafe_code)]`; any FFI lives in the swappable helper.

### Helper protocol

The helper is invoked with one of:

| Invocation | Behaviour |
|---|---|
| `<helper> --probe` | exit 0 if usable on this host, non-zero otherwise |
| `<helper> enumerate` | print a JSON array of `{id, window}` (each an `EnumeratedWindow`) to stdout, exit 0 |
| `<helper> dismiss <id>` | exit 0 = acted, exit 2 = window already gone, any other = failure (stderr = reason) |

Override the helper path with `$MUTEN_OVERLAY_HELPER`.

A reference Linux/X11 helper using `wmctrl` + `xprop` ships at
`installer/overlay-helper/muten-overlay-helper-linux.sh`. It closes
windows gracefully (WM_DELETE_WINDOW) and never kills processes —
process/registry cleanup is the EDR's job (CLAUDE.md I9). Windows
(PowerShell) and macOS (osascript/Swift) helpers follow the same
three-verb contract.

Where a field can't be determined (X11 doesn't expose "unsolicited vs
user-initiated"), the helper defaults conservatively so the classifier
biases toward `Suspicious` (review) over `Block` (dismiss) — the safe
direction for a false-positive-averse design.

## The monitor loop (v0.4.0 update 3)

`Monitor` is the daemon-side driver that runs overlay enforcement over
time and emits audit events. One `sweep()` call:

1. `enumerate()` the windows on screen (via any `OverlayController`).
2. `classify()` each; `dismiss()` the `Block` ones.
3. Record each appearance in the `RepeatTracker` and `assess()` for
   scareware (repeat flood + rogue-AV process).
4. Emit one `AuditEvent` per notable outcome:
   `overlay_blocked`, `overlay_suspicious`, `scareware_detected`,
   `overlay_sweep_error`. `Allow` outcomes are **not** audited — a
   quiet log keeps the signal visible.

The monitor holds the repeat-tracker state across sweeps, so a rogue
AV that re-pops the same window every few seconds crosses the flood
threshold and gets a `scareware_detected` event even when each
individual window is only `Suspicious`.

### Audit sink

`Monitor` depends only on a tiny `AuditSink` trait, not on a concrete
IO type — the same "depend on a trait" rule as the rest of muten. In
the full workspace the daemon wires a sink that writes to
`muten-events` JSONL and chains each line through the
`muten-audit-chain` SHA-256 hash chain, so overlay/scareware events
become tamper-evident alongside the audio enforcement events. Tests
use the in-memory `MemorySink`.

A controller error during a sweep emits `overlay_sweep_error` and the
loop continues — a transient window-manager hiccup never crashes the
daemon (same posture as the audio backend's `BackendError`).

## Tamper-evident audit log (v0.4.0 update 4)

The overlay monitor can now write a self-contained, tamper-evident
audit log via `ChainedFileSink` — a minimal SHA-256 hash chain whose
on-disk format matches `muten-audit-chain` exactly, so when the full
workspace is reassembled the two are interchangeable (a log written by
one verifies in the other).

Each event line carries `{seq, prev_hash, kind, window_id, detail,
hash}` where `hash = SHA-256(prev_hash ‖ kind ‖ window_id ‖ detail ‖
seq)`. Editing or deleting any line except the last breaks the chain
at a detectable line number — the defense for threat-model **S3**
(audit-log tampering). `ChainedFileSink::open` *refuses to append onto
an already-tampered log*, and resumes cleanly from a valid one.

`Monitor::run(controller, sink, &RunConfig{interval_ms, max_sweeps},
clock, process_of, should_stop)` drives periodic sweeps. The clock and
stop-flag are injected, so the loop is fully testable without real
sleeps or signal handlers (the file-based stop flag keeps the crate
`forbid(unsafe_code)`).

### CLI

```bash
# Run 3 sweeps, write + verify a chained audit log:
muten-overlay monitor windows.json --rules blocklist.txt --sweeps 3 \
    --audit-log /var/lib/muten/overlay-audit.log
# Re-running on a tampered log refuses to append (exit 1).
```

## Helper signal fidelity (v0.4.0 update 5)

A contract-test suite (`tests/helper_contract.rs`) pins the exact JSON
each OS helper emits and asserts it deserializes and classifies
sensibly. Writing it surfaced a real limitation and a fix:

**Limitation.** The helpers can't cheaply determine every field. On a
real host, `origin` is `unknown` (no `unsolicited` +25) and `age_ms`
is `0` (no `very_new`, after the earlier fix). So a borderless
full-screen scam scores only `fullscreen + topmost = 45` on the
*heuristic alone* → Allow. **The blocklist (host/title) is therefore
the reliable detection path on real hosts**, not the soft heuristic; a
title hit lifts the same window to Suspicious/Block. This is now
documented and locked by `known_limitation_*` tests.

**Fix.** `has_close_button` was hard-coded `true` by the helpers,
silently suppressing the `no_close_button` (+25) signal — the single
strongest behavioural tell of a scam overlay. The Linux and Windows
helpers now *detect* it:

- Windows: `WS_SYSMENU` window-style bit (no system menu ⇒ no close).
- Linux/X11: EWMH `_NET_WM_ALLOWED_ACTIONS` lacking
  `_NET_WM_ACTION_CLOSE`.

Both default to `true` only when the property is genuinely absent, to
avoid over-flagging legitimate windows. With a real `has_close_button:
false` from a borderless scam, the heuristic gains the +25 it needs to
reach Suspicious without any blocklist entry.

## Wayland support (v0.4.0 update 6)

A fourth reference helper,
`installer/overlay-helper/muten-overlay-helper-wayland.sh`, covers the
2026 Linux default (Wayland on Ubuntu/Fedora/GNOME/KDE). It uses the
wlroots `wlr-foreign-toplevel-management` protocol via `lswt` or
`wlrctl`.

**Honest scope.** Wayland deliberately restricts window enumeration:

- **wlroots compositors** (Sway, Hyprland, river, Wayfire, labwc):
  the helper lists toplevel **title + app-id**, so muten's title
  blocklist works. `wlrctl` can also request a graceful close
  (dismiss).
- **GNOME (Mutter) / KDE (KWin)**: do *not* implement
  wlr-foreign-toplevel as of 2026 (KDE bug 502647 open). The helper
  PROBES FALSE there, so muten falls back to observe/NullController
  rather than pretending to see windows — same conservative posture as
  every other "can't determine it" case.

Wayland exposes no geometry/stacking to foreign clients, so the helper
reports `coverage_percent: 0`, `topmost: false`, `age_ms: 0`. The
behavioural heuristic therefore has little to work with on Wayland and
the **title blocklist is the detection path** — which is muten's
reliable real-host path regardless. `tests/helper_contract.rs` pins
the Wayland output shape and confirms a known scam title is still
caught with geometry zeroed out.

The `SubprocessController` picks the helper via `$MUTEN_OVERLAY_HELPER`
or platform default; deployments on Wayland point it at the Wayland
helper. X11 sessions (including XWayland-hosted) continue to use the
wmctrl helper.
