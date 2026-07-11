# muten-overlay Feature Excess/Deficiency Audit (2026-07)

> **How to read this document** (for any Claude instance picking this up
> cold, with no prior conversation context): this is a running audit of
> `muten-overlay` (a pure, offline, `forbid(unsafe_code)` scam-overlay /
> scareware classifier for managed Windows/macOS/Linux fleets, in
> `/home/user/Muten`, crate at `crates/muten-overlay`). Every item below
> was **verified against actual code, tests, or a real compiled-binary
> run** — none are speculation. Each item has one of four STATUS values:
> `RESOLVED` (fixed, in a specific commit — see `git log` on branch
> `claude/deepresearch-ultrathink-improvement-yp5Y2`), `OPEN` (confirmed
> real, not yet fixed — this is your TODO list, ordered by priority stars
> `★★★` > `★★` > `★`), `VERIFIED-HEALTHY` (checked and found NOT to be a
> problem — do not re-investigate without new evidence), or `WONTFIX`
> (deliberately out of scope, with the reason given). Japanese prose
> below explains context for a human reader; identifiers, file paths,
> and code snippets are the load-bearing, language-neutral part — trust
> those over any paraphrase. "過剰" (excess) = code/docs that cost more
> than they're worth (bug, duplication, staleness). "不足" (deficiency)
> = something the product's own stated purpose (detect and dismiss scam
> overlays on a real managed fleet) needs but lacks.

---

## 1. Excess (過剰) — RESOLVED

### [RESOLVED] E-1: `crypto_drain_lure` false-positive on bare "Connect Wallet"
- **Evidence**: `has_crypto_drain_lure`'s `wallet_coerce` sub-pattern fired
  on bare `"connect"` + any wallet-brand word (wallet/metamask/coinbase/
  web3/defi/nft), with no alarm or reward context required.
- **実害**: "Connect Wallet" is the universal, always-benign primary CTA
  on every legitimate Web3 dApp (Uniswap, OpenSea, MetaMask itself) —
  guaranteed false positive, caught by the `benign_corpus` adversarial
  test harness.
- **Fix**: removed `"connect"` from the coercion-verb list in
  `src/confusables.rs`. Real wallet-drainer patterns remain caught by
  `wallet_alarm` (connect + alarm word) and the newer
  `wallet_connect_popup_lure` signal (connect + reward hook).

### [RESOLVED] E-2: `cloud_quota_lure` false-positive on real Apple/Google notification text
- **Evidence**: generic capacity vocabulary ("storage is full" /
  "storage almost full") was word-for-word identical to Apple's actual
  "iCloud Storage Almost Full" notification and Google's real quota
  notice.
- **Fix**: redesigned as a two-tier AND-pair in `src/confusables.rs`: an
  explicit deletion-threat phrase fires alone; generic capacity language
  now additionally requires sign-in/urgency pressure a passive OS
  notification never applies.

### [RESOLVED] E-3: `docs/IMPROVEMENT_ROADMAP.md` staleness
- **Evidence**: 6 items marked "not implemented" were already shipped
  (`#![deny(missing_docs)]`, Merkle tree anchoring, stdin streaming,
  fuzzing, docs.rs metadata, `#[non_exhaustive]`).
- **実害**: a future planning session could re-research or re-implement
  already-shipped work.
- **Fix**: markers updated to `✓DONE` with a one-line verification note
  each.

## 2. Excess (過剰) — OPEN, low priority, needs a human judgment call

These are not bugs; they're candidates for future cleanup that trade off
against backward compatibility or documentation churn. Not blocking.

### [OPEN ★] EC-1: `enforce` / `monitor` subcommand overlap
`enforce` and `monitor` are both dry-run demo tools over `NullController`
+ a static JSON window list; `monitor` is nearly a superset (adds
`--sweeps`/`--audit-log`/`--metrics`). Only real difference: `enforce`'s
exit-code contract (6 on any Block). Merging would need a deprecation
notice for scripts depending on `enforce` specifically.

### [OPEN ★] EC-2: 4 overlapping research/survey docs
`IMPROVEMENT_ROADMAP.md`, `RESEARCH_IMPROVEMENTS_2026H1.md`,
`IMPROVEMENT_CATALOG_2026H2.md`, `GAP_ANALYSIS_2026H2.md` track
overlapping items with separate progress markers — structurally prone to
re-staleness (see E-3). Recommend a one-line header on each: "current =
ROADMAP; the others are dated point-in-time archives, do not update."

### [OPEN ★] EC-3: `MECHANIC_EXEMPT` duplicated in two tests in `lib.rs`
Two tests independently hardcode the same signal-name list; updating one
without the other silently desyncs. Low-risk, low-effort: consolidate
into one `const`.

## 3. Verified Healthy (適正) — checked, confirmed NOT a problem

- **Zero orphaned detector functions**: every `has_*` function in
  `confusables.rs` is wired into `classify()` (confirmed via diff of
  defined-vs-called function names).
- **Every `OverlayWindow` field is consulted**: all 8 fields feed
  `classify()`.
- **All 10 analysis lenses surface in both text and `--json` CLI
  output**: categories / MITRE / persuasion / extraction / lifecycle /
  targeting / magnitude / fingerprint / triage / impersonation — verified
  by running `cargo run -- classify` against a real crafted window.
- **All 4 platform helpers are real, substantial implementations**
  (100–180 lines each), not stubs.
- **The coverage-guard meta-tests actually catch wiring gaps**: proven
  when adding signal E66 (`notification_permission_bait`) — the guards
  failed loudly until every lens was wired.

## 4. Deficiency (不足) — RESOLVED this audit cycle

| ID | Title | What was missing | Fix |
|---|---|---|---|
| D-1 | No production entry point | `SubprocessController` + `Monitor::run` were complete and tested, but the compiled binary never wired them together — `enforce`/`monitor` only ever used `NullController`. No way to run real protection on a real machine. | Added `daemon` subcommand: probe → real sweep loop → stop-flag → verified audit log. |
| D-2 | No helper hang protection | `Command::output()` blocks forever; one hung helper call freezes the entire daemon, including its own stop-flag check. | spawn+poll+kill with a timeout (default 5s, `--helper-timeout-ms`); new `ControllerError::Timeout`; also avoids a pipe-buffer deadlock. |
| D-3 | No single-instance guard | Two daemon processes on the same `--audit-log` would race and corrupt the tamper-evident hash chain. | `<audit-log>.lock` (`create_new`/`O_EXCL`) + `Drop`-based release; 3 service-manager templates auto-clear it only in their own supervisor-guaranteed startup step. |
| D-4 | Crash on zero-event runs | `ChainedFileSink` creates its file lazily; an all-benign run made `monitor`/`daemon` exit 1 instead of 0. | 3 call sites now treat "file doesn't exist" as "empty, valid chain." |
| D-5 | Metrics only written at shutdown | A daemon running for weeks would show `node_exporter` **nothing** until its first graceful stop (which might never happen). | `CountingSink` wrapper tallies counts in O(1) per event; metrics file rewritten every sweep. |
| D-6 | Metrics-write failure killed the loop | A missing metrics directory made the very first sweep's `?`-propagated error exit the whole daemon. | Best-effort: warn once per failure streak, keep protecting. |
| D-7 | Zero MDM deployment artifacts | Docs claimed "pushed via MDM" but no systemd/launchd/Task Scheduler files existed. | Added `installer/overlay-helper/{muten-overlay.service, com.muten.overlay.plist, muten-overlay-task.xml}` + a README covering Intune/Jamf/GPO/Ansible. |
| D-8 | Notification-permission-bait scams undetected | "Click Allow to continue watching" (Matrix Push C2-style) matched neither `clickfix_instruction` (needs CAPTCHA vocabulary) nor `download_trap_lure` (needs install vocabulary). | New signal `notification_permission_bait` (E66), fully wired across all 10 lenses. |
| D-9 | `--helper-timeout-ms` CLI flag untested | Only the underlying library call was tested; a refactor could silently drop the CLI wiring back to the library default with nothing noticing. | Regression test with a threshold tight enough to distinguish "flag worked" from "flag silently ignored"; verified by deliberately breaking the wiring and watching the test fail. |
| ~~DR-1~~ | Helper process-name reporting missing | `cmd_daemon` hard-wired `process_of` to `None` — the `rogue_av_process` signal and all 49 shipped `process:` blocklist rules were dead in production `daemon` mode. | `EnumeratedWindow.process` (optional, `#[serde(default)]`) reported best-effort by all 4 helpers (X11: `_NET_WM_PID`→`/proc/PID/comm`; Windows: `GetWindowThreadProcessId`→`Get-Process`; macOS: System Events process name; Wayland: foreign-toplevel app-id). `Monitor::sweep` prefers the embedded value over the `process_of` fallback. e2e-verified: a benign-titled window with a blocklisted process name produces `scareware_detected` + `rogue_av_process` + a non-zero `muten_scareware_total`. |
| ~~DR-11~~ | **Long-lived benign windows falsely flagged as repeat-flood** | `Monitor::sweep` (src/monitor.rs) called `tracker.record()` for **every** enumerated window on **every** sweep — conflating "still present" with "just appeared." `signature()` (`src/lib.rs`) is content-only (`title\|host`), so a static window produces the same signature every sweep; `REPEAT_THRESHOLD=3` (`src/scareware.rs`) meant any long-lived window fired `scareware_detected` continuously from its 3rd sweep onward. The `Origin::UserInitiated` carve-out never helped in practice because every real helper reports `origin:"unknown"`. Found and reproduced (2 spurious events / 4 sweeps) during D-1's e2e verification; deliberately deferred to its own fix. | `Monitor` gained `present_last_sweep: HashSet<Signature>` (the prior sweep's signature set, replaced wholesale each sweep — bounded memory). A signature already in that set is probed (`count`, non-incrementing); a signature absent from it (first sight, or a genuine re-appearance after disappearing) is recorded (`record`, incrementing) — this is exactly the presence-vs-appearance distinction the bug lacked. Verified in both directions with a real running daemon binary: a static benign window produced 0 `scareware_detected` across 6 sweeps; an appear/disappear/appear helper (genuine re-pop) still produced 3 `scareware_detected` events across 10 sweeps. 3 pre-existing tests that had baked in "same static controller swept repeatedly = a flood" were rewritten to alternate present/gone controllers, matching real re-pop behavior instead of the bug. **Real-world confirmation (2026-07 threat refresh)**: CypherLoc (Barracuda 2026-05) re-locks the browser immediately on any escape attempt — a present→gone→present loop — which is exactly the appearance-not-presence pattern this fix counts, validating the design against a live 2.8M-victim campaign. |
| ~~DR-2a~~ | **`age_ms` always 0 → `very_new` signal dead on every real host** | All 4 helpers unconditionally report `age_ms:0` ("unknown"), so the `very_new` (+10) signal and `sudden_fullscreen_takeover` composite (both gated on `age_ms > 0 && age_ms < 1000`) never fired on a real machine, even though the classifier logic for both was already correct and tested. Split out of DR-2 as the one sub-piece fixable without any helper changes. | `Monitor` infers `age_ms` from how long *it* has tracked a window (`first_seen_ms: HashMap<WindowId, u64>`, pruned to present ids each sweep) whenever the helper reports 0. First draft had a real bug (caught before any test run, not by a test): gating the `first_seen_ms` *insert* on "not the first sweep" meant a window present since sweep 1 got no entry during sweep 1, so on sweep 2 it looked brand-new and was scored `very_new` a few sweeps later anyway — the exact false positive the fix was meant to prevent, just delayed by one sweep. Corrected: `first_seen_ms` is now recorded unconditionally every sweep including the first; a separate `untrusted_from_startup: HashSet<WindowId>` marks every id present during the daemon's very first sweep, and only ids *not* in that set get their inferred age trusted; the set is pruned to present-ids each sweep, so a startup-cohort window that is ever absent even once permanently regains trust on any later reappearance. 3 new unit tests + 1 real-binary/real-wall-clock `cli_contract.rs` e2e test; proved the unit test and the e2e test both have teeth by reverting to the flawed design and confirming both failed (the e2e test caught the real daemon firing `overlay_suspicious` with `very_new` on every sweep after the first) before restoring the fix. |
| ~~DR-5~~ | **Stop-flag response latency on long `--interval-ms`** | `cmd_daemon`'s loop checked the stop flag once per sweep, then slept the *entire* configured interval in one unbroken `thread::sleep` — a daemon tuned with a long interval to keep idle CPU near zero could take up to that whole interval to actually stop after a service manager's `ExecStop` touched the flag file. | Sleep is now chunked into 250ms slices with a stop-flag check between each; breaks out the moment the flag appears instead of waiting for the chunked sleep to run out naturally. No new dependency or CLI flag. e2e-verified: `daemon_stop_flag_takes_effect_promptly_on_a_long_interval` runs the real binary with `--interval-ms 5000`, requests a stop after 200ms, and asserts exit within 2s; proved it has teeth by reverting to the single unbroken sleep first and confirming the unfixed binary took 4.87s to exit under the identical test. |
| ~~DR-3~~ | **No blocklist hot-reload** | `--rules` was only ever read once at startup — pushing an updated blocklist to a fleet running `daemon` required a coordinated restart of every instance, a real availability gap for routine policy updates (e.g. adding a newly discovered scam host). | `Monitor::set_rules(&mut self, rules: Ruleset)` swaps the active blocklist without disturbing repeat/age/presence tracking state. `cmd_daemon` stats `--rules`'s mtime once per sweep (one cheap syscall) and re-reads/re-parses/`set_rules`s it when the mtime advances; a transient read failure is best-effort (warn once per failure streak, keep protecting on the last-good ruleset, auto-retry next sweep) — the same pattern already used for the metrics writer. e2e-verified: `daemon_reloads_rules_file_edited_while_running` edits `--rules` in place on a running daemon and confirms a previously-non-matching window is `overlay_blocked` afterward; proved it has teeth by reverting to load-once behavior and confirming the test failed first (no audit log was ever created). |
| ~~DR-2b~~ | **`blocks_input` hard-coded `false` on X11** | Every helper hard-coded `blocks_input: false` unconditionally, silently suppressing the `blocks_input` (+20) signal for a genuinely modal scam dialog on every platform. Also corrected a stale claim in this doc's own previous DR-2 text: `has_close_button` was NOT hard-coded on X11/Windows — both already derive it from real EWMH/`WS_SYSMENU` signals (see `docs/OVERLAY_BLOCKING.md`'s "Fix" section, predates this audit cycle). Only macOS and Wayland still hard-code `has_close_button: true`. | X11/`muten-overlay-helper-linux.sh` now derives `blocks_input` from `_NET_WM_STATE_MODAL`, reusing the same `_NET_WM_STATE` fetch already done for `topmost` (one X11 round-trip covers both — no extra `xprop` call). Verified end-to-end by stubbing `xprop`/`wmctrl`/`xdotool` on `PATH` and running the real shipped shell script (`tests/linux_helper_reference.rs`, `enumerate_reports_blocks_input_from_net_wm_state_modal`); proved it has teeth by reverting to the hard-coded `false` and confirming a modal test window's `blocks_input` silently reverted to `false` under the identical harness. **Caveat**: `cargo test`/`clippy`/`fmt` could not be run this round — the sandbox's egress policy blocked `static.crates.io` crate downloads on a cache-less container, so this Rust test file's compilation is unverified pending the next session with a working `cargo` (the shell-script change itself was fully verified directly, independent of cargo). |
| ~~DR-2c~~ | **`has_close_button` hard-coded `true` on macOS** | The macOS helper hard-coded `has_close_button: true` unconditionally, silently suppressing the `no_close_button` (+25) signal for a genuinely borderless/frameless scam window (e.g. an Electron `BrowserWindow` with `frame:false`) on macOS. | `muten-overlay-helper-macos.sh`'s AppleScript now checks `exists (button 1 of w)` per window — the same `button 1` accessor `dismiss()` already relies on to click the close button, so "no `button 1`" and "`dismiss()` can't gracefully close this window" are consistent by construction, not two independently-drifting assumptions. Verified end-to-end by stubbing `osascript` on `PATH` (both the `-e` single-expression form and the heredoc/stdin multi-line form the script uses) and running the real shipped shell script (`tests/macos_helper_reference.rs`, `enumerate_reports_has_close_button_from_button_1_existence`); proved it has teeth by reverting to the hard-coded `true` and confirming a borderless test window's `has_close_button` silently reverted to `true` under the identical harness. Same `cargo` caveat as DR-2b: the new Rust test file's compilation is unverified this round. |
| ~~DR-2d~~ | **`blocks_input` hard-coded `false` on macOS** | The macOS helper hard-coded `blocks_input: false` unconditionally, silently suppressing the `blocks_input` (+20) signal for a genuinely modal scam dialog on macOS. | `muten-overlay-helper-macos.sh`'s AppleScript now checks `subrole of w` per window and treats `"AXDialog"`/`"AXSystemDialog"` as modal — the standard macOS Accessibility API signal for a dialog window, corroborated by 3 independent sources (Apple Developer Forums, MacScripter, a dedicated AppleScript-modal-detection writeup) found via web search before implementing, unlike the Wayland `lswt` investigation below where only a single secondary source was available and the change was deliberately NOT made. Verified end-to-end the same way as DR-2c (stubbed `osascript`, real shipped script, `tests/macos_helper_reference.rs`'s `enumerate_reports_blocks_input_from_axdialog_subrole`); proved it has teeth by reverting to the hard-coded `false` and confirming a modal test window's `blocks_input` silently reverted to `false`. Same `cargo`-unverified caveat as DR-2b/DR-2c. |

## 5. Deficiency (不足) — OPEN, priority order

### [OPEN ★★★] DR-2: Helper geometry-field fidelity — `origin` (all 4 platforms), `blocks_input` (Wayland/Windows), `has_close_button` (Wayland only)
Per-field, per-platform status as of this cycle (✅ = computed from a
real signal, ✗ = hard-coded default):

| Field | X11/Linux | macOS | Wayland | Windows |
|---|---|---|---|---|
| `has_close_button` | ✅ `_NET_WM_ALLOWED_ACTIONS` | ✅ `button 1` existence (DR-2c, this cycle) | ✗ always `true` | ✅ `WS_SYSMENU` |
| `blocks_input` | ✅ `_NET_WM_STATE_MODAL` (DR-2b, this cycle) | ✅ `AXDialog`/`AXSystemDialog` subrole (DR-2d, this cycle) | ✗ always `false` | ✗ always `false` |
| `origin` | ✗ always `unknown` | ✗ always `unknown` | ✗ always `unknown` | ✗ always `unknown` |
| `age_ms` | n/a — inferred Monitor-side for all platforms uniformly, see DR-2a | | | |
| `topmost` | ✅ `_NET_WM_STATE_ABOVE` | ✗ always `false` | ✗ always `false` | ✅ `WS_EX_TOPMOST` |
| `coverage_percent` | ✅ geometry vs. root window | ✅ geometry vs. desktop bounds | ✗ always `0` | ✅ geometry vs. screen |

`origin` has no real signal on any platform today (all four hard-code
`unknown`) — real-host detection for a window whose only tell would be
"appeared with no user action" still relies entirely on title/URL
blocklist matching. This fails safe (under-detects rather than
false-blocks). Fixing `origin` requires focus-history tracking across
helper invocations (the helper is currently a stateless per-call
subprocess) on every platform — genuinely the largest remaining piece.
The remaining single-field gaps (`blocks_input` on Wayland/Windows,
`has_close_button` on Wayland only now) are comparatively small,
single-platform patches (same shape as DR-2b/DR-2c/DR-2d) and are the
better next increments; `origin` is the multi-file, cross-call
state-tracking undertaking that still warrants its own dedicated
session.

**Investigated this cycle, deliberately NOT changed: Wayland
`has_close_button`/`blocks_input`.** Web research (not primary-source
confirmed — the actual manpage and the sourcehut source both returned
HTTP 403 when fetched; findings rest on secondary search-result
summaries only) suggests the `wlr-foreign-toplevel-management-unstable-v1`
protocol does carry more state than the helper's own comment claims:
a `state` field including `fullscreen` (not just maximized/minimized/
activated), and a `parent` event marking a toplevel as a child of
another — the closest Wayland analogue to X11's `_NET_WM_STATE_MODAL`.
`lswt` reportedly exposes both via `-j` (JSON) and `-t <format>` (custom
CSV) flags, rather than the multi-line `title:`/`app-id:` block format
`muten-overlay-helper-wayland.sh`'s current parser assumes for plain
`lswt` output — which, if the search summaries are accurate, would mean
that parsing path has never actually matched a real `lswt` invocation
and the script has likely always fallen through to the `wlrctl` branch
in practice on any host where `lswt` is the available tool. This was
**not acted on**: neither `lswt` nor a Wayland compositor is available
in this sandbox to verify against a real binary, the only two primary
sources (manpage, protocol source) both 403'd, and secondhand summaries
are not solid enough ground to rewrite a shipped parser touching a
security-relevant detection path. Flagged here so the next session with
real access to `lswt`/a Wayland session can verify directly rather than
re-discovering this from scratch — check `lswt -j` and `lswt -t` output
against the parser in `muten-overlay-helper-wayland.sh`'s `enumerate()`
`lswt` branch before touching anything.

### [OPEN ★★] DR-4: No log rotation across a multi-week run
The audit log is a single ever-growing file. `verify_chain_continued` (in
`src/sink.rs`) already supports verifying a chain that spans a rotation
boundary — only the rotation mechanism itself (when/how to cut a new
file) is missing.

### [OPEN ★★] DR-6: Merkle-root external anchoring is manual
Root computation and HMAC signing (`src/sink.rs`) are implemented; the
periodic out-of-band publication step (syslog, immutable storage) is a
manual operator task, not automated.

### [OPEN ★] DR-7: No config file
No `~/.config/muten/overlay.toml` — every invocation needs explicit
flags. Lower priority for `daemon` specifically since the service-manager
templates (systemd/launchd/Task Scheduler) already pin the flags in one
place per deployment.

### [OPEN ★] DR-8: Detection vocabulary is EN + JP only
Published phishing corpora show lures spread across ~22 languages
(arXiv:2306.05816); this product currently detects English and Japanese
only.

### [OPEN ★] DR-9: No Browser-in-the-Browser (BITB) detection
`OverlayWindow` (title + url only) cannot represent BITB attacks by
construction — would need the helper protocol extended with DOM-derived
signals, a larger scope change.

### [OPEN ★] DR-10: No signed builds / semver-checks / benchmarks
Authenticode/Sigstore signing, `cargo-semver-checks` CI gate, and
`criterion` throughput benchmarks are all unimplemented (tracked
previously as roadmap C10-1 and the remainder of category C3).

### [OPEN ★★★] DR-12: ClickFix variant vocabulary gap — FileFix / TerminalFix
**Evidence**: `has_clickfix_instruction` (`src/confusables.rs:1746`)
covers Win+R / Ctrl+V shortcut framing, run-dialog phrases (`open run`,
`paste the command`, `into the run box`), CAPTCHA framing,
GlitchFix/CrashFix browser-error framing, and JP-localised variants —
but has NO vocabulary for the two newest high-prevalence variants
(threat intel refresh 2026-07, see `THREAT_INTEL_2026.md` §2026-H2):
- **FileFix**: pastes into the **Windows Explorer address bar** (no
  Mark-of-the-Web → bypasses SmartScreen). Tells: "paste into the
  address bar", "file explorer", the **Win+E** shortcut, "open file
  explorer and paste".
- **TerminalFix**: "open terminal / PowerShell and paste", "paste in
  the terminal".

**Fix** (spec for next session — not implemented this round, `cargo`
unavailable in this sandbox to verify): add `win+e` to the compact
shortcut list; add an `address_bar` / `terminal` compound branch to
`run_cmd` (require the paste/execution verb AND the surface noun, e.g.
`(contains("address bar") && contains("paste"))`, mirroring the
existing AND-compound precision discipline). The `alert_shaped` guard
in `classify()` stays as-is; no new signal id needed — these extend the
existing `clickfix_instruction` signal. Add unit tests alongside the
existing ClickFix tests in `confusables.rs`, and a `scoring_scenarios.rs`
end-to-end case. Prove teeth by reverting.

### [OPEN ★★] DR-13: No signal for a literal IP address shown in an alert
**Evidence**: CypherLoc (Barracuda 2026-05) displays the victim's public
IP on the lure page for false authenticity. muten's existing `ip_alarm`
signal (`src/lib.rs`, `W_IP_ALARM`) requires alarm vocabulary
("your IP has been hacked/flagged") — it does NOT fire on a bare IP
literal presented in an otherwise alert-shaped window, which is the
CypherLoc pattern (the IP is shown as "proof", not as an alarm phrase).
**Fix** (spec): a new `ip_address_displayed` signal — scan the
normalized title for a dotted IPv4 literal (four 1–3 digit octets, each
≤255) via a hand-written octet scan (no regex dependency, consistent
with the crate's no-new-deps rule), gated by `alert_shaped` to avoid
firing on legitimate network-config windows. Low weight (≈15) since an
IP alone is weak; it stacks with fullscreen/no-close. FP guard: a
router admin page or a real network dialog is `user_initiated`
(suppressed) or not alert-shaped.

### [OPEN ★★] DR-14: No "internal IT helpdesk" impersonation vocabulary
**Evidence**: CypherLoc funnels victims to a fake **IT helpdesk**. The
abused-authority lens (`src/` authority-impersonation signals) targets
government / big-brand impersonation (FBI, Microsoft, banks) — it has no
vocabulary for *internal*-authority framing ("contact your IT
helpdesk / IT department / system administrator to unlock"). This is a
distinct, growing social-engineering angle (impersonating the victim's
own org rather than an external authority).
**Fix** (spec): add a compound title pattern — an IT-support noun
(`it helpdesk`, `it department`, `system administrator`, `help desk`)
combined with an unlock/urgency verb — as a new low/medium-weight
signal or a `composite:` rule. AND-compound to keep precision (a benign
"IT helpdesk ticket #123" window must not fire).

### [OPEN ★] DR-15: AI-facilitated fraud — watch item, not yet actionable
**Evidence**: FBI IC3 2025 (released 2026-04) breaks out AI-facilitated
fraud as its own category for the first time (>22k complaints, ~$893M).
For an overlay/window classifier this is currently a *delivery/content*
trend (AI tailors the lure text to the victim's OS/brand) rather than a
new window-metadata tell, so there is no concrete detector to add yet —
tracked so the next threat refresh re-checks whether distinctive
AI-scam overlay vocabulary has emerged.

---

## Current State Summary (as of this audit's last commit)

- **Version**: `muten-overlay` v0.6.0.
- **Tests**: 1331 unit tests + 26 `cli_contract` integration tests + 7
  other integration suites (helper_contract, linux_helper_reference,
  macos_helper_reference, monitor_properties, scoring_scenarios,
  benign_corpus, composed_evasion, scareware_properties). All previously
  green as of commit `549df29`; the two new `*_helper_reference` suites
  (DR-2b/DR-2d in `linux_helper_reference.rs` and
  `macos_helper_reference.rs`) are each verified end-to-end at the
  shell-script level but their Rust compilation is **unverified** this
  round — see the DR-2b/DR-2c/DR-2d caveats above. Zero new dependencies
  added across this entire audit cycle. MSRV 1.75 preserved throughout.
- **What changed this cycle**: production readiness (D-1..D-9), the
  process-attribution gap (DR-1), the repeat-flood false-positive
  (DR-11), the `age_ms`/`very_new` dead-signal gap (DR-2a), the stop-flag
  response latency (DR-5), blocklist hot-reload (DR-3), the X11
  `blocks_input` gap (DR-2b), the macOS `has_close_button` gap (DR-2c),
  and the macOS `blocks_input` gap (DR-2d) are all closed. The detection
  engine (66 signals / 10 lenses / confusable-normalization pipeline) and
  the audit-integrity infrastructure (hash chain + Merkle proofs) were
  already mature before this cycle began.
- **Recommended next action**: run `cargo test`/`clippy`/`fmt` on
  `tests/linux_helper_reference.rs` and `tests/macos_helper_reference.rs`
  at the start of the next session (the sandbox's egress policy blocked
  crate downloads this round — see the DR-2b/DR-2c/DR-2d caveats) before
  trusting either as a green regression guard. After that, the DR-2
  per-field table above shows the next-smallest increment is
  `has_close_button` or `blocks_input` on Wayland — but see the Wayland
  investigation note above first (uncertain `lswt` output format);
  Windows `blocks_input` is untested territory since no `pwsh` is
  available in this sandbox to verify a `.ps1` change end-to-end.
  `origin` on any platform is the largest remaining piece (needs
  cross-invocation focus-history state) and still warrants its own
  dedicated session. DR-4 (log rotation) remains a ★★ self-contained
  single-session fix if preferred instead.
- **New this refresh (2026-07)**: **DR-12** (ClickFix FileFix/TerminalFix
  vocabulary) is now the top ★★★ *code* gap — pure `src/confusables.rs`
  vocabulary additions with an existing test harness to extend, no helper
  or protocol change, so it is the highest-leverage first task once
  `cargo` is available again. DR-13/DR-14 (CypherLoc IP-display and
  IT-helpdesk signals) follow. The blocklist/docs half of the 2026-H2
  refresh is already landed (needs no compilation); only the detector
  code is deferred.
