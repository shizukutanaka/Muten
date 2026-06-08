# muten-overlay — Specification (v0.5.0)

Normative specification of the `muten-overlay` pure-domain layer: the
types, the classifier contract, the offline blocklist grammar, the
text-normalization pipeline, scareware detection, the monitor/enforce
loop, the tamper-evident audit chain, the OS-controller/helper protocol,
and the CLI contract. Keywords **MUST / SHOULD / MUST NOT** are used in
the RFC 2119 sense. Where the implementation diverged from this spec, the
gap is listed in [§13](#13-conformance-gaps) and fixed in the same change.

## 1. Scope & invariants

muten-overlay decides, **offline and deterministically**, whether an
observed window is a scam/scareware overlay, and emits a tamper-evident
audit trail. Global invariants (hold for every public function):

- **Pure & offline.** No network, no clock, no filesystem in the
  detection path (`classify`, `assess`, normalization). Time is injected.
- **`#![forbid(unsafe_code)]`.** All OS/FFI work lives in helper scripts.
- **No ML, no computer vision.** Reasoning is over window *metadata* and
  text only, via a transparent additive score with named weights (I6).
- **Total / never-panic.** Every public function MUST return for any
  input (property-tested). Parsers MUST NOT abort on malformed input.
- **False-positive-averse (observe-first).** Only a confirmed host
  blocklist hit, or accumulated evidence reaching `BLOCK_THRESHOLD`,
  yields `Block`. No single behavioural signal — and no bounded
  composite — auto-blocks on its own.
- **Detect & audit, don't destroy.** No process kill, no registry edits.

## 2. Domain types

### 2.1 `Origin` (serde `snake_case`)
`unknown` (default) | `user_initiated` | `unsolicited`.

### 2.2 `OverlayWindow`
A best-effort observation. **The enumerator fills what it can and leaves
the rest at type defaults; therefore deserialization MUST supply defaults
for any missing field** (a helper that cannot determine a field omits it).

| field | type | meaning / spec |
|---|---|---|
| `title` | String | window/document title, lower-cased by the enumerator |
| `url` | Option\<String\> | source URL/host if a browser surface, lower-cased |
| `coverage_percent` | u8 | percent of active display covered; domain `0..=100`; `≥ 85` counts as full-screen. Values `> 100` are treated as full-screen (saturating), never as an error |
| `topmost` | bool | always-on-top |
| `has_close_button` | bool | a usable close affordance exists |
| `blocks_input` | bool | modal / input-grab |
| `origin` | Origin | how it appeared |
| `age_ms` | u64 | ms on screen; **`0` means "unknown"**, not "brand new" |

### 2.3 `Verdict`
`{ decision, score: i32 (≥0), signals: [&str], categories: [DarkPatternCategory] (sorted, deduped), matched_rule: Option<String> }`.
`Decision` ∈ `allow | suspicious | block`. `Verdict::explain()` MUST return
a deterministic, non-empty, period-terminated sentence for any verdict.

## 3. Classifier contract (`classify(&OverlayWindow, &Ruleset) -> Verdict`)

Precedence:
1. **Hard host block.** If `url`'s host matches the blocklist, return
   `Block`, `score = BLOCK_THRESHOLD`, `signals = [blocklist_host]`,
   `matched_rule = Some(rule)`. (Highest trust; short-circuits.)
2. Otherwise compute the **additive score** from the signals below and
   threshold it.

### 3.1 Signal weights (named constants, I6)

| signal | weight | condition |
|---|--:|---|
| `fullscreen` | +30 | `coverage_percent ≥ 85` |
| `topmost` | +15 | `topmost` |
| `no_close_button` | +25 | `!has_close_button` |
| `blocks_input` | +20 | `blocks_input` |
| `unsolicited` | +25 | `origin = unsolicited` |
| `user_initiated` | −40 | `origin = user_initiated` |
| `very_new` | +10 | `0 < age_ms < 1000` |
| `blocklist_title` | +40 | normalized title contains a `title:` pattern |
| `phone_number` | +35 | alert-shaped **and** a 7–15-digit phone number in the title |
| `mixed_script` | +30 | raw title or host token mixes Latin with Cyrillic/Greek |
| `whole_script_confusable` | +30 | raw title or host **label** (dot-split for URLs) is entirely Cyrillic or Greek where every letter folds to an ASCII Latin look-alike (UTS#39 §5 whole-script confusable; blind spot of `mixed_script`). The FP guard: legitimate Cyrillic/Greek text uses letters without ASCII folds (п, θ…), which fail the fold-to-ASCII check |
| `compat_chars_present` | +20 | raw title or host contains enclosed/circled Latin letters (U+24B6–U+24E9, Ⓐ–Ⓩ / ⓐ–ⓩ); used in phishing to bypass plain-text filters. `normalize_for_match` now folds these to ASCII for blocklist matching; this signal fires on their mere presence in the raw text |
| `mixed_number_systems` | +20 | a single whitespace-delimited token in the raw title or host mixes decimal digits from two numbering systems, e.g. ASCII `5` and Arabic-Indic `٥` (ICU `SpoofChecker.MIXED_NUMBERS`). No legitimate number mixes systems. ASCII and full-width digits are the **same** system, so legitimate Japanese full-width numerals beside ASCII do not fire (JP FP guard) |
| `excessive_combining_marks` | +20 | the raw title or host stacks **3 or more** combining marks on one base character ("Zalgo" obfuscation). The threshold-of-3 is the FP guard: legitimate scripts (Vietnamese, Arabic, Indic, IPA) stack at most one or two combining marks, so they never fire |
| `bidi_override` | +30 | raw title or host contains an LRO/RLO BiDi directional override (Trojan Source); isolates/marks used by legit RTL text do not fire |
| `brand_impersonation` | +40 | a host label's UTS#39 skeleton equals a built-in known brand but is not the literal brand (homograph/typosquat); the real brand domain never fires |
| `clickfix_instruction` | +20 | `alert_shaped` AND normalized title contains ClickFix/fake-CAPTCHA instruction tokens: keyboard-shortcut references (`win+r`, `ctrl+v`), run-dialog phrases (`open run`, `paste the command`), or CAPTCHA framing (`captcha`, `verify`+`human`, `not a robot`). The `alert_shaped` guard prevents firing on legitimate reCAPTCHA pages (not fullscreen/modal). Leet and homoglyph evasion are defeated by `normalize_for_match` before the check. ForcedAction category. (MS Security Blog 2025: +517 % ClickFix surge) |
| `input_trap` | +5 | `fullscreen ∧ topmost ∧ blocks_input` (bounded composite) |
| `sudden_fullscreen_takeover` | +5 | `unsolicited ∧ fullscreen ∧ topmost ∧ 0<age_ms<1000` (bounded composite) |

`alert_shaped` ≜ `coverage ≥ 85 ∨ blocks_input ∨ !has_close_button`.
Final `score = max(0, Σ weights)`.

### 3.2 Thresholds & monotonicity
`score ≥ BLOCK_THRESHOLD (100)` → Block; `≥ SUSPICIOUS_THRESHOLD (50)` →
Suspicious; else Allow. The score MUST be **monotone non-decreasing** in
each "more suspicious" signal. **Bounded-composite cap (FP-aversion):** a
window with no content/provenance tell MUST NOT reach `Block` from a
bounded composite alone — the lock shape caps at 95, the takeover shape at
85, both `< BLOCK_THRESHOLD`.

## 4. Text normalization (`confusables`)

`normalize_for_match(s)` ≜ `strip_invisibles ∘ fold_confusables ∘
fold_leet_in_words ∘ to_ascii_lowercase`, idempotent. Used **symmetrically**
for both stored `title:` patterns (at parse) and titles (at match), so the
two sides cannot drift. `strip_invisibles` removes zero-width / BiDi
controls and MUST NOT lengthen the string. `fold_leet_in_words` folds leet
digits only inside tokens containing a letter (pure-digit runs — phone
numbers — survive). The phone-number scan runs on `fold_confusables` only
(it needs the original digits). `has_confusable_mixed_script` is evaluated
on the **raw** string (folding erases the evidence) and ignores CJK/Kana.

## 5. Blocklist grammar (`Ruleset::parse`)

Plain text, one rule per line; `#` starts a comment. A malformed line MUST
be skipped, never abort the load. Prefixes: `host:` (host + any
subdomain), `title:` (substring on the normalized title), `process:`
(separator-insensitive substring). A bare line is a `host:` rule. Host
matching strips invisibles and folds typosquat/homoglyph confusables; the
**original** authored rule text is returned as `matched_rule`.

## 6. Scareware (`assess(repeat_count, process_name, &Ruleset)`)

Returns `Scareware` iff a known rogue-AV **process** matches
(`rogue_av_process`) **or** `repeat_count ≥ REPEAT_THRESHOLD`
(`repeated_flood`); else `Benign`. `RepeatTracker` is a sliding window
(default 2 min). `signature(&OverlayWindow)` = normalized title + host,
the stable key for repeat counting across re-pops.

## 7. Monitor / enforce loop

`enforce(controller, rules)` = enumerate → classify each → `dismiss` only
on `Block` → one `EnforceOutcome` per window. `Monitor::sweep(now_ms,
process_of)` additionally folds in scareware and emits one audit event per
notable outcome: `overlay_blocked`, `overlay_suspicious`,
`scareware_detected`, `overlay_sweep_error`. **`Allow` is not audited.**
The clock and `process_of` are injected (determinism). A single dismiss or
controller error MUST NOT abort the sweep.

## 8. Audit chain (`sink`, format-compatible with `muten-audit-chain`)

One JSON object per line. Link hash:
`hash = SHA256(prev_hash ‖ 0x00 ‖ be(timestamp_ms) ‖ 0x00 ‖ kind ‖ 0x00 ‖
window_id ‖ 0x00 ‖ json(detail) ‖ 0x00 ‖ be(seq))`. First event's
`prev_hash` = `GENESIS` (64 `0`). `verify_chain(text) -> (count, head)`
detects any edit, deletion, reordering, or back/forward-dating, and the
sink MUST refuse to append onto an already-broken log. `timestamp_ms` is
part of the hash (events cannot be backdated). A **torn final line** (a
crash mid-`emit`, i.e. content with no trailing newline) is the one
recoverable break: `open` drops the unverifiable partial tail and
resumes from the surviving prefix **iff that prefix itself verifies**;
any tampered *complete* line (which ends in a newline) still refuses.

## 9. OS controller / helper protocol

`OverlayController { name, enumerate() -> Result<[EnumeratedWindow]>,
dismiss(&WindowId) -> Result<bool> }`. `dismiss` MUST be called only for
`Block`. `NullController` is the dry-run default (records, touches no real
window). `SubprocessController` spawns a per-OS helper that emits the
window JSON (so partial JSON per §2.2 MUST parse). `ControllerError` ∈
`Enumerate | Dismiss | Unsupported`.

## 10. CLI contract

Subcommands: `classify`, `rules`, `scareware`, `enforce`, `monitor`.
All decision subcommands accept `--json`: `classify`/`scareware` emit a
verdict object (the `classify` JSON additionally carries `explanation`);
`enforce` emits a JSON array of per-window outcomes; `monitor` emits the
audit-event document (or a verifiable summary `{sweeps, dismissals,
event_count, head, verified}` when `--audit-log` is set). Window input
accepts `-` for stdin. Human-readable `classify`/`enforce` decisions are
color-coded (Block=red, Suspicious=yellow, Allow=green) **only** when
stdout is a TTY and `$NO_COLOR` is unset (https://no-color.org); piped
output and `--json` MUST stay plain so machine consumers are unaffected.

**Exit codes (stable):** `0` Allow / benign / OK · `5` Suspicious · `6`
Block (or any window blocked) · `7` Scareware · `1` error. These MUST be
documented in `--help`.

## 11. JSON output schema (`classify --json`)
`{ decision: "allow|suspicious|block", score: int, signals: [string],
categories: [string], matched_rule: string|null, explanation: string }`.

## 12. Non-goals (I3)
ML/CV black boxes; network/certificate/WHOIS signals; process termination
or registry edits; blockchain audit. See `docs/IMPROVEMENT_CATALOG_2026H2.md`
for researched future work (Merkle anchoring, signed config, UTS#39
skeleton, etc.).

## 13. Conformance gaps (found by this spec; fixed in the same change)

1. **§2.2 partial-window deserialization.** The doc contract said fields
   are best-effort with defaults, but `OverlayWindow` had no
   `#[serde(default)]`, so any JSON missing a field (a helper that can't
   determine one; a minimal hand-written sample) failed to parse. **Fixed:**
   `#[serde(default)]` on the struct + a regression test that partial JSON
   deserializes to type defaults.
2. **§10 exit codes undocumented.** The stable exit codes existed only in
   code. **Fixed:** added an `after_help` exit-code table to the CLI so
   `--help` documents `0/5/6/7/1`.
3. **§10 `--json` only on `classify`/`scareware`.** `enforce` and
   `monitor` had no machine-readable output, an inconsistent CLI
   contract for SIEM use. **Fixed:** `enforce --json` (array of outcomes)
   and `monitor --json` (events document / verifiable summary), plus
   `tests/cli_contract.rs` end-to-end tests of the JSON schema and exit
   codes for all four decision subcommands.
4. **§8 a crash mid-write bricked the log.** A torn final line made
   `ChainedFileSink::open` refuse forever — a single crash, not an
   attack, denied all further appends. **Fixed:** `open` recovers a torn
   final line (no trailing newline) by dropping it and resuming from the
   surviving prefix iff that prefix verifies; a tampered complete line
   still refuses. Tests cover recovery, lone-torn-line→empty, and
   tampered-prefix-still-refuses.

Open (tracked in the catalog, not in this change): `#[non_exhaustive]` on
public enums (C3-5) — deferred (forces `_` arms downstream; the enums are
conceptually closed).
