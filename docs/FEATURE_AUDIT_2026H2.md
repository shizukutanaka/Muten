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
| ~~DR-11~~ | **Long-lived benign windows falsely flagged as repeat-flood** | `Monitor::sweep` (src/monitor.rs) called `tracker.record()` for **every** enumerated window on **every** sweep — conflating "still present" with "just appeared." `signature()` (`src/lib.rs`) is content-only (`title\|host`), so a static window produces the same signature every sweep; `REPEAT_THRESHOLD=3` (`src/scareware.rs`) meant any long-lived window fired `scareware_detected` continuously from its 3rd sweep onward. The `Origin::UserInitiated` carve-out never helped in practice because every real helper reports `origin:"unknown"`. Found and reproduced (2 spurious events / 4 sweeps) during D-1's e2e verification; deliberately deferred to its own fix. | `Monitor` gained `present_last_sweep: HashSet<Signature>` (the prior sweep's signature set, replaced wholesale each sweep — bounded memory). A signature already in that set is probed (`count`, non-incrementing); a signature absent from it (first sight, or a genuine re-appearance after disappearing) is recorded (`record`, incrementing) — this is exactly the presence-vs-appearance distinction the bug lacked. Verified in both directions with a real running daemon binary: a static benign window produced 0 `scareware_detected` across 6 sweeps; an appear/disappear/appear helper (genuine re-pop) still produced 3 `scareware_detected` events across 10 sweeps. 3 pre-existing tests that had baked in "same static controller swept repeatedly = a flood" were rewritten to alternate present/gone controllers, matching real re-pop behavior instead of the bug. |
| ~~DR-2a~~ | **`age_ms` always 0 → `very_new` signal dead on every real host** | All 4 helpers unconditionally report `age_ms:0` ("unknown"), so the `very_new` (+10) signal and `sudden_fullscreen_takeover` composite (both gated on `age_ms > 0 && age_ms < 1000`) never fired on a real machine, even though the classifier logic for both was already correct and tested. Split out of DR-2 as the one sub-piece fixable without any helper changes. | `Monitor` infers `age_ms` from how long *it* has tracked a window (`first_seen_ms: HashMap<WindowId, u64>`, pruned to present ids each sweep) whenever the helper reports 0. First draft had a real bug (caught before any test run, not by a test): gating the `first_seen_ms` *insert* on "not the first sweep" meant a window present since sweep 1 got no entry during sweep 1, so on sweep 2 it looked brand-new and was scored `very_new` a few sweeps later anyway — the exact false positive the fix was meant to prevent, just delayed by one sweep. Corrected: `first_seen_ms` is now recorded unconditionally every sweep including the first; a separate `untrusted_from_startup: HashSet<WindowId>` marks every id present during the daemon's very first sweep, and only ids *not* in that set get their inferred age trusted; the set is pruned to present-ids each sweep, so a startup-cohort window that is ever absent even once permanently regains trust on any later reappearance. 3 new unit tests + 1 real-binary/real-wall-clock `cli_contract.rs` e2e test; proved the unit test and the e2e test both have teeth by reverting to the flawed design and confirming both failed (the e2e test caught the real daemon firing `overlay_suspicious` with `very_new` on every sweep after the first) before restoring the fix. |
| ~~DR-5~~ | **Stop-flag response latency on long `--interval-ms`** | `cmd_daemon`'s loop checked the stop flag once per sweep, then slept the *entire* configured interval in one unbroken `thread::sleep` — a daemon tuned with a long interval to keep idle CPU near zero could take up to that whole interval to actually stop after a service manager's `ExecStop` touched the flag file. | Sleep is now chunked into 250ms slices with a stop-flag check between each; breaks out the moment the flag appears instead of waiting for the chunked sleep to run out naturally. No new dependency or CLI flag. e2e-verified: `daemon_stop_flag_takes_effect_promptly_on_a_long_interval` runs the real binary with `--interval-ms 5000`, requests a stop after 200ms, and asserts exit within 2s; proved it has teeth by reverting to the single unbroken sleep first and confirming the unfixed binary took 4.87s to exit under the identical test. |
| ~~DR-3~~ | **No blocklist hot-reload** | `--rules` was only ever read once at startup — pushing an updated blocklist to a fleet running `daemon` required a coordinated restart of every instance, a real availability gap for routine policy updates (e.g. adding a newly discovered scam host). | `Monitor::set_rules(&mut self, rules: Ruleset)` swaps the active blocklist without disturbing repeat/age/presence tracking state. `cmd_daemon` stats `--rules`'s mtime once per sweep (one cheap syscall) and re-reads/re-parses/`set_rules`s it when the mtime advances; a transient read failure is best-effort (warn once per failure streak, keep protecting on the last-good ruleset, auto-retry next sweep) — the same pattern already used for the metrics writer. e2e-verified: `daemon_reloads_rules_file_edited_while_running` edits `--rules` in place on a running daemon and confirms a previously-non-matching window is `overlay_blocked` afterward; proved it has teeth by reverting to load-once behavior and confirming the test failed first (no audit log was ever created). |

## 5. Deficiency (不足) — OPEN, priority order

### [OPEN ★★★] DR-2: Helper geometry-field fidelity — `origin`, `has_close_button`, `blocks_input` still low (age_ms closed, see DR-2a above)
`origin` (feeds `unsolicited` +25), `has_close_button` (+25 when absent),
`blocks_input` (+20) are hard-coded conservative defaults in the OS
helpers (X11/macOS/Wayland report `origin:"unknown"` unconditionally;
Wayland additionally hard-codes `coverage_percent:0`). `age_ms` is no
longer part of this gap — see DR-2a, resolved this cycle by Monitor-side
inference, no helper changes needed. Real-host detection is still biased
more heavily onto title/URL matching than the classifier's design
intends, for the fields that remain. This fails safe (under-detects
rather than false-blocks). Fixing the remaining fields requires
helper-side work across all 4 platforms (X11: `_NET_WM_STATE_FOCUSED`
history for origin inference; Windows: foreground-change tracking;
similar per-platform effort for macOS/Wayland) — a larger, multi-file
undertaking better scoped as its own session, one platform at a time.

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

---

## Current State Summary (as of this audit's last commit)

- **Version**: `muten-overlay` v0.6.0.
- **Tests**: 1331 unit tests + 26 `cli_contract` integration tests + 5
  other integration suites (helper_contract, monitor_properties,
  scoring_scenarios, benign_corpus, composed_evasion, scareware_properties)
  — all green. `cargo clippy --all-targets -- -D warnings` clean.
  `cargo fmt --check` clean. Zero new dependencies added across this
  entire audit cycle. MSRV 1.75 preserved throughout.
- **What changed this cycle**: production readiness (D-1..D-9), the
  process-attribution gap (DR-1), the repeat-flood false-positive
  (DR-11), the `age_ms`/`very_new` dead-signal gap (DR-2a), the stop-flag
  response latency (DR-5), and blocklist hot-reload (DR-3) are all closed.
  The detection engine (66 signals / 10 lenses /
  confusable-normalization pipeline) and the audit-integrity
  infrastructure (hash chain + Merkle proofs) were already mature before
  this cycle began.
- **Recommended next action**: the remainder of DR-2 (helper-reported
  `origin`, `has_close_button`, `blocks_input` fidelity — `age_ms` itself
  is done, see DR-2a) is the clear next priority — it is the largest
  remaining gap between the classifier's designed detection power and
  what it actually achieves on a real host, but is scoped as its own
  multi-platform session rather than a quick fix. Next after that: DR-4
  (log rotation), ★★ and a self-contained single-session fix.
