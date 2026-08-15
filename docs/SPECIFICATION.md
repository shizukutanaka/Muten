# muten-overlay — Specification (v0.6.0)

Normative specification of the `muten-overlay` pure-domain layer: the
types, the classifier contract, the offline blocklist grammar, the
text-normalization pipeline, scareware detection, the monitor/enforce
loop, the tamper-evident audit chain, the OS-controller/helper protocol,
and the CLI contract. Keywords **MUST / SHOULD / MUST NOT** are used in
the RFC 2119 sense. Where the implementation diverged from this spec, the
gap is listed in [§13](#13-conformance-gaps) and fixed in the same change.

This is the current, actively-maintained spec. `docs/SPECIFICATION_V2.md`
is a frozen historical snapshot (Round 19–30) kept only for its detailed
Unicode-confusable fold table and strengths/weaknesses analysis of that
era — it is not updated and should not be treated as authoritative.

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
`{ decision, score: i32 (≥0), signals: Vec<String>, categories: Vec<DarkPatternCategory> (sorted, deduped), matched_rule: Option<String>, mitre_techniques: Vec<String>, explanation: String }`.
`Decision` ∈ `allow | suspicious | block`.

- `Verdict::explain()` MUST return a deterministic, non-empty, period-terminated sentence for any verdict, including the confidence level (e.g. `"Block (score 130, high confidence): …"`).
- `Verdict::confidence() -> ConfidenceLevel` returns `High` (≥2 content-tell signals), `Medium` (exactly 1), or `Low` (geometry signals only).
- `Verdict::score_breakdown() -> Vec<(String, i32)>` returns the default weight per fired signal (compile-time constants; active weight overrides are reflected in `score` but not here).
- `mitre_techniques` is a sorted, deduplicated list of MITRE ATT&CK for Enterprise v16 technique IDs implied by the signals (e.g. `["T1036","T1566"]`).

### 2.4 `ConfidenceLevel` (serde `snake_case`)
`high` | `medium` | `low`. Populated by `Verdict::confidence()`.

## 3. Classifier contract (`classify(&OverlayWindow, &Ruleset) -> Verdict`)

Precedence:
1. **Hard host block.** If `url`'s host matches the blocklist, return
   `Block`, `score = BLOCK_THRESHOLD`, `signals = [blocklist_host]`,
   `matched_rule = Some(rule)`. (Highest trust; short-circuits.)
2. Otherwise compute the **additive score** from the signals below and
   threshold it.

### 3.1 Signal weights (named constants, I6)

Default weights are compile-time constants. Any can be overridden at runtime
via `weight:` lines in the pushed blocklist (§5.2); `classify()` calls
`Ruleset::weight_of(signal, default)` for every signal, so the actual score
reflects active overrides.

| signal | default weight | condition |
|---|--:|---|
| `fullscreen` | +30 | `coverage_percent ≥ 85` |
| `topmost` | +15 | `topmost` |
| `no_close_button` | +25 | `!has_close_button` |
| `blocks_input` | +20 | `blocks_input` |
| `unsolicited` | +25 | `origin = unsolicited` |
| `user_initiated` | −40 | `origin = user_initiated` |
| `very_new` | +10 | `0 < age_ms < 1000` |
| `blocklist_title` | +40 | normalized title matches a `title:` pattern (substring) or a `glob:` pattern (§5.1) |
| `phone_number` | +35 | alert-shaped **and** a 7–15-digit phone number in the title |
| `blocklist_phone` | +40 | the title contains a number on the curated `phone:` blocklist (known scam number). High-confidence, so unlike `phone_number` it does **not** require the alert shape; additive, not an auto-block (like `blocklist_title`). Matched digits-only on the folded title |
| `mixed_script` | +30 | raw title or host token mixes Latin with Cyrillic/Greek |
| `whole_script_confusable` | +30 | raw title or host **label** (dot-split for URLs) is entirely Cyrillic or Greek where every letter folds to an ASCII Latin look-alike (UTS#39 §5 whole-script confusable) |
| `compat_chars_present` | +20 | raw title or host contains enclosed/circled Latin letters (U+24B6–U+24E9) |
| `mixed_number_systems` | +20 | a single whitespace-delimited token mixes decimal digits from two numbering systems |
| `excessive_combining_marks` | +20 | the raw title or host stacks **3 or more** combining marks on one base character ("Zalgo") |
| `bidi_override` | +30 | raw title or host contains an LRO/RLO BiDi directional override (Trojan Source) |
| `brand_impersonation` | +40 | a host label's UTS#39 skeleton equals a built-in known brand but is not the literal brand |
| `combosquat_brand` | +30 | a host label joins a known brand and a scam-lure word as hyphen-delimited tokens |
| `typosquat_brand` | +25 | host label skeleton is edit-distance 1 from a known brand (deletion/substitution/transposition; mutually exclusive with `brand_impersonation`) |
| `clickfix_instruction` | +20 | `alert_shaped` AND normalized title contains ClickFix/GlitchFix/fake-CAPTCHA instruction tokens |
| `urgency_countdown` | +15 | `alert_shaped` AND title contains `M:SS`/`MM:SS` + urgency keyword |
| `cloud_storage_abuse` | +20 | `alert_shaped` AND URL host is a blob-storage tenant subdomain (`*.blob.core.windows.net`, `*.s3.amazonaws.com`, `*.storage.googleapis.com`, …) |
| `url_path_lure` | +20 | `alert_shaped` AND URL path contains a known-brand token within 2 positions of a known lure token |
| `forced_retention_cue` | +20 | `alert_shaped` AND normalized title contains a retention instruction. English ("do not close / do not turn off / keep this window open / stay on this page") and Japanese (この画面を閉じないで / 電源を切らないで / 再起動しないで / ウィンドウを閉じないで) — the latter is the most iconic IPA-documented サポート詐欺 phrase. |
| `credential_harvest_cue` | +20 | `alert_shaped` AND normalized title contains account-alarm or credential-entry language. English (account suspended/locked, verify account, confirm password) and Japanese (アカウントが停止/凍結/ロック, 不審なログイン, パスワードを確認, 本人確認). |
| `fake_scanner_cue` | +20 | `alert_shaped` AND normalized title contains fake rogue-AV scan-progress language. English (scanning for threats, N threats found, removing malware, system repair) and Japanese (スキャン中+脅威, 脅威が見つかりました, ウイルスを検出, マルウェアを削除しています, システムを修復しています). |
| `subscription_lure` | +15 | `alert_shaped` AND normalized title contains subject (subscription/license) + expiry (expired) + action (renew/call) |
| `authority_lure` | +25 | `alert_shaped` AND normalized title contains an LEA-agency token + coercion token. Agencies: English (fbi/cia/interpol/europol/hmrc/cybercrime/…) and Japanese (警察庁/警視庁/国税庁/消費者庁/サイバー警察). Coercion: English (warning/locked/illegal/fine/arrested) and Japanese (警告/違反/ロック/罰金/逮捕/不正アクセス/凍結). JP coverage targets IPA-documented 警察なりすまし詐欺 / サポート詐欺. MITRE T1566. |
| `remote_access_lure` | +20 | normalized title names a remote-access tool AND independent fake-alert evidence already fired |
| `screen_share_lure` | +20 | `alert_shaped` AND normalized title contains screen-share social-engineering cues (share-screen + remote-enable + grant-support language; FBI IC3 2025). MITRE T1219. |
| `crypto_drain_lure` | +25 | `alert_shaped` AND normalized title contains wallet-alarm + coercion + seed-harvest language ("your wallet was drained / verify / enter seed phrase"). Covers 2025-2026 crypto-drain overlay surge. MITRE T1566. |
| `prize_lure` | +20 | `alert_shaped` AND normalized title contains a prize/lottery word (winner/prize/reward/jackpot) AND a claim-action phrase (claim/collect/redeem). Covers lottery-scam overlays common on library and kiosk PCs. MITRE T1566. |
| `download_trap_lure` | +20 | `alert_shaped` AND normalized title demands a software install (install demand OR fake-plugin gate: plugin noun + action verb or "required"). Covers fake-plugin overlays distributing malware. MITRE T1566. |
| `qr_code_lure` | +20 | `alert_shaped` AND normalized title contains a QR-noun ("qr code" / "qr-code" / "scan qr") AND verify-action (verify/confirm/access/proceed/…). Detects "quishing" overlays that redirect victims via QR to bypass URL filters (APWG Q4 2024, FBI IC3 2025). MITRE T1566. |
| `ip_alarm_lure` | +20 | `alert_shaped` AND normalized title contains ip-subject ("ip address" / "your ip") AND alarm-word (hack/infect/flag/report/block/compromis/…). Covers the "Your IP address has been hacked" tech-support-scam staple (Malwarebytes 2025, Microsoft Security 2024). MITRE T1566. |
| `package_fee_lure` | +20 | `alert_shaped` AND normalized title contains package-noun ("your package/parcel/shipment/delivery") AND fee-demand (customs fee/duty, "on hold", release fee, "unable to deliver"). Covers delivery/customs advance-fee overlays impersonating DHL/FedEx/USPS (FTC 2024: imposter-scam delivery variants #2 category, 1.1M complaints). MITRE T1566. |
| `sextortion_lure` | +25 | `alert_shaped` AND normalized title contains camera-cue ("your camera/webcam", "we have recorded") AND extortion-word (bitcoin/btc/cryptocurrency/payment, "your contacts", expose). Covers browser-overlay sextortion attacking victims via webcam-recording threats with cryptocurrency payment demands (FBI IC3 2024: +42% YoY). MITRE T1566. |
| `gift_card_demand` | +30 | `alert_shaped` AND normalized title contains gift-card-noun ("gift card/gift cards", "itunes card", "google play card", "amazon/apple/ebay/steam gift card", "prepaid card") AND payment-instruction (buy/purchase gift card, send codes, send the codes, read the codes, scratch the card, pay with/using/in gift card, go to the store, nearest store). No legitimate software directs users to purchase gift cards via an overlay; FTC reports gift cards as the #1 payment method in tech-support fraud losses. MITRE T1566. |
| `input_trap` | +5 | `fullscreen ∧ topmost ∧ blocks_input` (bounded composite) |
| `sudden_fullscreen_takeover` | +5 | `unsolicited ∧ fullscreen ∧ topmost ∧ 0<age_ms<1000` (bounded composite) |

`alert_shaped` ≜ `coverage ≥ 85 ∨ blocks_input ∨ !has_close_button`.
Final `score = max(0, Σ weights)` (using effective weights from §5.2 overrides).

### 3.2 Thresholds & monotonicity
`score ≥ BLOCK_THRESHOLD (100)` → Block; `≥ SUSPICIOUS_THRESHOLD (50)` →
Suspicious; else Allow. The score MUST be **monotone non-decreasing** in
each "more suspicious" signal. **Bounded-composite cap (FP-aversion):** a
window with no content/provenance tell MUST NOT reach `Block` from a
bounded composite alone — the lock shape caps at 95, the takeover shape at
85, both `< BLOCK_THRESHOLD`.

## 4. Text normalization (`confusables`)

`normalize_for_match(s)` ≜ `strip_symbols_and_emoji ∘ strip_invisibles ∘ fold_confusables ∘
fold_leet_in_words ∘ to_ascii_lowercase`, idempotent. Used **symmetrically**
for both stored `title:` / `glob:` patterns (at parse) and titles (at match),
so the two sides cannot drift.

- `strip_symbols_and_emoji` removes emoji and decorative symbols (U+2600–U+27BF,
  U+FE00–U+FEFF, U+1F000–U+1FFFF) that may be inserted mid-word to defeat substring
  matching (e.g. `"inf⚠️ected"` → `"infected"`). MUST NOT strip CJK/Kana.
- `strip_invisibles` removes zero-width / BiDi controls and MUST NOT lengthen the string.
- `fold_leet_in_words` folds leet digits only inside tokens containing a letter
  (pure-digit runs — phone numbers — survive).
- The phone-number scan runs on `fold_confusables` only (it needs the original digits).
- `has_confusable_mixed_script` is evaluated on the **raw** string (folding erases the
  evidence) and ignores CJK/Kana.

## 5. Blocklist grammar (`Ruleset::parse`)

Plain text, one rule per line; `#` starts a comment. A malformed line MUST
be skipped, never abort the load. Prefixes:

| Prefix | Match semantics |
|---|---|
| `host:` | host + any subdomain; strips invisibles + folds confusables |
| `title:` | substring (contains) on the normalized title |
| `glob:` | full-string wildcard on the normalized title (§5.1) |
| `phone:` | known scam number, digits-only on the folded title; NANP/JP/UK/AU prefixes normalized; rules with `< 7` digits dropped as over-broad |
| `process:` | separator-insensitive substring on process name |
| `composite:` | declarative AND-condition rule (§5.2) |
| `weight:` | per-signal weight override (§5.3) |
| *(bare)* | treated as `host:` |

The **original authored** rule text is returned as `matched_rule` for audit
readability.

**Authoring hazards (normative).** Three loader behaviours fail *silently*,
so a mis-authored rule yields no diagnostic and simply never matches:

- **Prefixes are matched case-sensitively with no space before the colon.**
  The parser is a `strip_prefix("title:")` chain ending in
  `else { /* bare → host */ }`, so `Title:`, `TITLE:` and `title :` are
  **not** title rules — each is reinterpreted as a bare `host:` rule,
  which `normalize_host` then almost certainly rejects.
- **`#` is reserved and cannot appear literally in a pattern.** Comment
  stripping cuts at the *first* `#` regardless of surrounding whitespace,
  and there is no escape. A TOAD-style rule
  `title: your case #4821 is under review` is silently truncated to
  `your case`. Express such lures with `glob:` wildcards instead
  (`glob: * your case * is under review *`).
- **Patterns that normalize to empty are dropped**, as are `phone:`
  rules under the 7-digit floor. (The empty-key guard is also what
  prevents an empty `title:` key from matching *every* window via
  substring search.)

Implementations SHOULD provide a way to surface these. Today
`muten-overlay rules <file>` reports rule *counts* only; the bundled
`installer/overlay-helper/lint-blocklist.sh` names the offending line
and exits non-zero, and is the recommended pre-deployment check.

### 5.1 Glob title patterns (`glob:`)

Grammar: `glob: <pattern>` where `*` matches any run of code points
(including none) and `?` matches exactly one code point. Matching is
**full-string** (both anchored). Use `*` at either end for prefix/suffix/contains
semantics (e.g. `glob: *infected*` is equivalent to `title: infected`).

The pattern is normalized through the same pipeline as `title:` at parse
time; `*` and `?` are non-alphanumeric separators and pass through
`normalize_for_match` unchanged. The matcher is O(m × n) worst-case, O(1)
space (backtrack-pointer algorithm, no regex dep, no ReDoS risk). Both
`title:` and `glob:` rules contribute the `blocklist_title` signal; at most
one fires per window (the first match wins).

### 5.2 Composite AND-condition rules (`composite:`)

Grammar: `composite: <name> <weight> <cond1> [<cond2> …]`

When **all** listed conditions hold simultaneously, `<weight>` is added to
the suspicion score and `<name>` is appended to `Verdict.signals`. The name
appears in `explain()` and the audit log. Rules with zero recognized conditions
are silently dropped. Available condition tokens:

| Token | Meaning |
|---|---|
| `fullscreen` | `coverage_percent ≥ FULLSCREEN_COVERAGE (85)` |
| `topmost` | `topmost == true` |
| `no_close_button` | `has_close_button == false` |
| `blocks_input` | `blocks_input == true` |
| `unsolicited` | `origin == Unsolicited` |
| `user_initiated` | `origin == UserInitiated` |
| `very_new` | `age_ms > 0 && age_ms < 1000` (age 0 = unknown, does not satisfy) |
| `alert_shaped` | `fullscreen ∨ blocks_input ∨ no_close_button` |
| `has_blocklist_title` | `blocklist_title` signal fired earlier in this `classify()` call |
| `has_phone_number` | `phone_number` signal fired earlier in this `classify()` call |
| `has_blocklist_phone` | `blocklist_phone` signal fired earlier in this `classify()` call |

**Bounded-weight convention (FP-aversion):** a composite covering only
geometry/origin (no content tell) SHOULD keep the total score below
`BLOCK_THRESHOLD` (100). The built-in `input_trap` and
`sudden_fullscreen_takeover` use weight 5 for this reason. Add content-tell
conditions to justify higher weights.

### 5.3 Per-signal weight overrides (`weight:`)

Grammar: `weight: <signal_name> <i32_value>`

Overrides the default compile-time weight for any named signal. Operators
who observe — via `signal_firing_stats()` (§8.2) — that a signal has a high
FP rate in their fleet can lower its weight in the MDM-pushed blocklist
without recompiling. Negative values are allowed (softening or negating
relief signals). Unknown signal names are stored for future compatibility.
Malformed values (non-numeric, missing) are silently dropped. Accessed via
`Ruleset::weight_of(signal, default)`, which `classify()` uses for every
heuristic signal.

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

`sweep()` returns `SweepOutcome { dismissed: u32, detections: u32 }`.
`detections` counts Block + Suspicious verdicts; the caller (`run()`) uses it
to shorten the inter-sweep sleep when threats are actively re-spawning:
if `RunConfig::alert_interval_ms` is set and the previous sweep had
`detections > 0`, `run()` sleeps for `alert_interval_ms` instead of
`interval_ms`. The default (`alert_interval_ms = None`) restores prior behavior.

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

### 8.1 Merkle anchoring (`merkle`, RFC 6962 / RFC 9162)

On top of the linear chain, `merkle_root_of_log(text)` computes the
RFC 6962 **Merkle Tree Hash** over the ordered per-event link hashes
(after `verify_chain` gates integrity), with leaf/node domain separation
(`0x00`/`0x01` prefixes) and `SHA-256("")` as the empty-tree hash. The
root is a single 32-byte commitment to the whole ordered event set;
publishing or signing it out-of-band **anchors** the log's state at a
point in time, so later tampering is provable against the anchored root
without the original file.

`inclusion_proof_for_seq` yields an `O(log n)` audit path proving a specific
event is committed by the root, verified by `merkle::verify_inclusion`
(RFC 9162 §2.1.3.2).

`consistency_proof(first, leaves)` generates an `O(log n)` proof that
`leaves[..first]` is a prefix of the full leaf set (RFC 9162 §2.1.4, the
SUBPROOF recursive algorithm). `verify_consistency(first, n, proof, old_root,
new_root)` verifies the proof against two published roots without the
original leaves — any holder of two Merkle roots from different time points
can prove no events were inserted or reordered between the snapshots.
`sink::consistency_proof_for_range(text, first)` wraps both over a verified
audit log.

The `monitor --audit-log` summary carries `merkle_root`.

### 8.2 Signal firing statistics (`sink::signal_firing_stats`)

`signal_firing_stats(text: &str) -> Result<HashMap<String, SignalStats>, ChainError>`
parses a verified audit log (chain integrity checked first) and aggregates
the `detail.signals` array of each `overlay_blocked` / `overlay_suspicious`
event into a `HashMap<String, SignalStats>`. `SignalStats { blocks: u64,
suspicious: u64 }` with `total()`. This closes the loop with §5.3: operators
rank signals by `total()` to find which drive the most alerts, compare
`blocks / total` ratios to spot review-queue noise, and adjust `weight:`
overrides accordingly.

## 9. OS controller / helper protocol

`OverlayController { name, enumerate() -> Result<[EnumeratedWindow]>,
dismiss(&WindowId) -> Result<bool> }`. `dismiss` MUST be called only for
`Block`. `NullController` is the dry-run default (records, touches no real
window). `SubprocessController` spawns a per-OS helper that emits the
window JSON (so partial JSON per §2.2 MUST parse). Every helper call is
bounded by a per-call timeout (default 5 s; `daemon --helper-timeout-ms`);
a helper that does not exit in time is killed and surfaced as
`ControllerError::Timeout`. `ControllerError` ∈
`Enumerate | Dismiss | Unsupported | Timeout`.

Each `EnumeratedWindow` on the wire is `{id, process?, window}`:

| field | type | meaning / spec |
|---|---|---|
| `id` | String | the controller's opaque, stable window handle (HWND, X11 id, `app::title`, …), passed back to `dismiss` |
| `process` | Option\<String\> | owning process / application name, **best-effort**; a helper that cannot attribute one for a window MUST omit the field (deserializes as `None` = unknown). Matched against blocklist `process:` rules via `match_process`'s squash semantics (case-, space-, separator-insensitive substring), so a Wayland app-id `org.mozilla.firefox` matches a rule written `firefox`. Feeds `assess()`'s `rogue_av_process` signal; the daemon prefers this enumeration-atomic value over any out-of-band `process_of` lookup |
| `window` | OverlayWindow | the observed metadata per §2.2 |

**`dismiss` exit codes (normative).** A helper MUST exit `0` when it
acted on the window, `2` when the window was already gone, and any other
non-zero code only when the dismissal itself failed. These map to
`Ok(true)` / `Ok(false)` / `Err(ControllerError::Dismiss)`. The `2` case
and the failure case MUST NOT be conflated: *already-gone* is a normal
outcome (the overlay closed on its own between enumerate and dismiss),
whereas a *failure* means the endpoint's dismissal path is broken while a
scam window may still be on screen — an operator reading the audit log
has to be able to tell those apart. A helper that returns e.g. `1` for an
unknown window id turns every benign self-closed window into an error and
buries real failures in noise.

**Control characters (normative).** A helper MUST NOT emit raw ASCII
control characters (U+0000–U+001F) inside any JSON string it produces.
RFC 8259 forbids them in string literals, and the daemon parses a
helper's `enumerate` output as **one** document — so a single window
whose title carries one makes the entire array fail to parse, and *every*
window in that sweep goes unclassified. Since a hostile overlay chooses
its own title, this is an attacker-controlled evasion vector, not a
theoretical edge case. Helpers MUST fold tab/CR/LF to spaces and
**delete** any other control character before emitting (deleting rather
than substituting also collapses `vi<ESC>rus` back to `virus`, so the
evasion attempt does not survive into the title either — the same thing
`normalize_for_match` does on muten's side). All four shipped reference
helpers implement this in their `json_escape` (the three POSIX helpers
via `tr -d '[:cntrl:]'`, the PowerShell helper via
`-replace '[\x00-\x1F\x7F]', ''`); a custom or third-party helper MUST do
the same.

Per-OS `process` source: X11 `_NET_WM_PID` → `/proc/PID/comm`; Windows
`GetWindowThreadProcessId` → `Get-Process .ProcessName`; macOS the System
Events process name; Wayland the foreign-toplevel `app-id` (PIDs are not
exposed to foreign clients).

## 10. CLI contract

Subcommands: `classify`, `rules`, `scareware`, `enforce`, `triage`,
`monitor`, `daemon`, `verify`, `signals`. (`enforce`/`monitor` are
dry-run/demo over a static window list; `daemon` is the real continuous
loop via `SubprocessController` — see its `--help` for the stop-flag,
single-instance lock, and metrics contracts.)
All decision subcommands accept `--json`: `classify`/`scareware` emit a
verdict object (the `classify` JSON additionally carries `explanation`,
`confidence`, `score_breakdown`, `mitre_techniques`);
`enforce` emits a JSON array of per-window outcomes; `monitor` emits the
audit-event document (or a verifiable summary `{sweeps, dismissals,
event_count, head, merkle_root, verified}` when `--audit-log` is set,
where `merkle_root` is the RFC 6962 anchor per §8.1). Window input
accepts `-` for stdin. Human-readable `classify`/`enforce` decisions are
color-coded (Block=red, Suspicious=yellow, Allow=green) **only** when
stdout is a TTY and `$NO_COLOR` is unset (https://no-color.org); piped
output and `--json` MUST stay plain so machine consumers are unaffected.

**Exit codes (stable):** `0` Allow / benign / OK · `5` Suspicious · `6`
Block (or any window blocked) · `7` Scareware · `1` error. These MUST be
documented in `--help`.

The `rules` subcommand prints counts for all rule types:
`hosts`, `titles`, `globs`, `phones`, `processes`, `composites`,
`weight overrides`.

### 10.1 `cli` feature flag

The binary and `clap` dependency are gated behind the `cli` Cargo feature
(default enabled). Library-only consumers can add `default-features = false`
to skip clap. The `tests/cli_contract.rs` integration tests are also gated
with `required-features = ["cli"]`.

### 10.2 NDJSON streaming classify (`classify --stream`)

`classify <path|-> --stream` reads one `OverlayWindow` JSON object per line
from the given file or stdin (`-`). Each non-empty line produces one verdict
JSON object on stdout (the same schema as `--json`, §11, including the
`explanation` field). Empty lines MUST be skipped. A malformed line exits 1
immediately. Exit code is the **worst** verdict seen across all lines: `0` if
all Allow, `5` if any Suspicious and none Block, `6` if any Block. An entirely
empty input stream exits 0 with no output. `--stream` implies JSON output;
combining `--stream --json` is legal and has the same effect.

### 10.3 `--version` build info

`muten-overlay --version` prints `<version> (commit <hash>)` where `<hash>`
is the short git commit hash embedded at compile time by `build.rs`. Falls
back to `(commit unknown)` in environments without git.

## 11. JSON output schema (`classify --json` / `--stream`)
```json
{
  "decision": "allow|suspicious|block",
  "score": 130,
  "signals": ["fullscreen", "blocklist_title", "phone_number"],
  "categories": ["interface_interference"],
  "matched_rule": "your computer is infected",
  "mitre_techniques": ["T1036", "T1566"],
  "explanation": "Block (score 130, high confidence): a full-screen window…",
  "confidence": "high",
  "score_breakdown": [
    {"signal": "fullscreen", "weight": 30},
    {"signal": "blocklist_title", "weight": 40},
    {"signal": "phone_number", "weight": 35}
  ]
}
```

`signals` is a `Vec<String>` (named signal keys plus any operator-defined
composite rule names from §5.2). `categories` values are snake_case strings
from the Gray et al. (2018) dark-pattern taxonomy. `confidence` is one of
`"high"`, `"medium"`, `"low"` (§2.4). `score_breakdown` lists the default
compile-time weight per fired signal; the sum may differ from `score` when
active `weight:` overrides are in play. `mitre_techniques` is sorted and
deduplicated.

## 12. Non-goals (I3)
ML/CV black boxes; network/certificate/WHOIS signals; process termination
or registry edits; blockchain audit. See `docs/IMPROVEMENT_CATALOG_2026H2.md`
for researched future work.

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
5. **§8.1 Merkle consistency proofs "deferred".** v0.5.0 said consistency
   proofs between two tree sizes were deferred until a rotation workflow
   needs them. **Implemented in v0.6.0:** `merkle::consistency_proof` /
   `merkle::verify_consistency` / `sink::consistency_proof_for_range`.
