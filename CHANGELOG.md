# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Conventional Commits](https://www.conventionalcommits.org/).

## [0.6.0] — evasion-resistant normalization + TOAD/Web3/browser-security signals (rounds 10–31)

### Removed — duplicate rules in `examples/overlay-blocklist.txt`
- Found while continuing the same file audit: 3 `process:` pairs
  squash-identical under `match_process`'s space/hyphen/underscore-
  insensitive matching (`registrysmart`/`registry smart`,
  `systemcare antivirus`/`system care antivirus`,
  `errorfix`/`error fix`), and 1 exact-duplicate `title:` line ("do not
  restart your computer," present verbatim in both the generic
  tech-support-scam block and the fake-blue-screen block). Since
  `match_title`/`match_process` only need one matching pattern to fire
  (first match wins, per `docs/SPECIFICATION.md` §5.1), the second
  occurrence in each pair was pure dead weight — indistinguishable
  spelling variants sharing the exact same normalized key, not two
  distinct real-world variants.
- Removed one line from each pair/duplicate. Zero behavior change: every
  removed line's normalized key is still covered by its surviving
  sibling. `blocklist_coverage.rs`'s `covers_fake_blue_screen` test
  (which checks "Do not restart your computer" specifically) still
  passes — it only needs *a* matching pattern to exist, and the
  surviving occurrence still does. `process_count()` (44) and
  `title_count()` (305) both remain well above the test file's `>= 10`
  / `>= 100` assertions.

### Removed — false-positive-risk `process:` entries in `examples/overlay-blocklist.txt`
- `process: iolo system mechanic` and `process: system mechanic
  professional` matched iolo Technologies' genuine, commercially-sold
  PC-tuneup product line — not a rogue-AV impersonator of it. Found
  while auditing the same file for the fictional `host:` entries
  (previous entry, this cycle): the surrounding 47 `process:` rules are
  real, well-documented historical rogue-AV/PUP brand names (WinFixer,
  XP Antivirus, Segurazo, Antivirus Pro 2017/2018, etc., all matching
  the file's cited sources), but these two specifically named a real
  legitimate product, not an impostor of one.
- Removed both, since this product's own stated design principle
  (`README.md`: "Observe-first / false-positive-averse... False
  positives break the environments muten protects") means a
  legitimately-purchased utility should never ship pre-flagged as
  scareware. Left a comment explaining the removal and how to scope a
  narrower rule if a fleet specifically needs to catch a *fake* clone
  impersonating the real product's name. Confirmed no test references
  either string. `process_count()` drops from 49 to 47 — well above
  `blocklist_coverage.rs`'s `>= 10` assertion, so no test impact.
- Investigated but did NOT touch: `phone: 1-800-555-0100` /
  `phone: +81-120-000-000` looked like the same class of issue at first
  (conventionally-fake placeholder numbers) but the section header
  explicitly frames the entire "ADVANCED RULE TYPES" block as syntax
  demonstrations for operator discovery, not curated threat intel —
  555/000-block numbers are the standard telecom-documentation
  convention for "definitely not a real number" (the phone-number
  analogue of `.example`), used here correctly and intentionally.

### Removed — fictional `host:` entries from `examples/overlay-blocklist.txt`
- The shipped example blocklist carried 5 `host:` rules
  (`win-prize-now.example`, `your-pc-is-infected.example`,
  `urgent-security-alert.example`, `microsoft-security-alert.example`,
  `windows-defender-alert.example`) that were never real: all five used
  the RFC 2606 reserved `.example` TLD, which never resolves to
  anything, and — unlike every `title:`/`glob:`/`process:`/`phone:`
  pattern elsewhere in the file — were not sourced from any of the
  file's cited threat intel. The file's own comment already called them
  "illustrative placeholders to be replaced with site-specific intel,"
  but shipped them as if they were live rules.
- Removed the 5 entries; the two already-commented-out `# host: <...>`
  syntax examples (showing the format, not claiming to be real domains)
  are kept. No test asserted on these specific hosts or on a nonzero
  `host_count()` — `blocklist_coverage.rs` only checks
  `title_count()`/`process_count()` — and no other file in the repo
  reads `examples/overlay-blocklist.txt`'s host rules (the Rust unit
  tests using `win-prize-now.example` construct their own inline
  `Ruleset::from_lines(...)`, independent of this file), so this is a
  content-only change with no code impact.

### Fixed — macOS helper hard-coded `blocks_input: false` (audit DR-2d)
- `muten-overlay-helper-macos.sh` hard-coded `blocks_input: false`
  unconditionally, silently suppressing the classifier's `blocks_input`
  (+20) signal for a genuinely modal scam dialog on macOS.
- Fixed by checking the window's accessibility `subrole` via System
  Events and treating `"AXDialog"`/`"AXSystemDialog"` as modal — the
  standard macOS Accessibility API signal for a dialog window. Confirmed
  via web search against 3 independent sources (Apple Developer Forums,
  MacScripter, a dedicated AppleScript-modal-detection writeup) before
  implementing, since this session has no macOS host to test against
  directly.
- Verified end-to-end the same way as DR-2c: stubbed `osascript` on
  `PATH`, ran the actual shipped shell script, and confirmed a modal
  test window reports `blocks_input: true` while an ordinary window
  reports `false` (new test
  `enumerate_reports_blocks_input_from_axdialog_subrole` in
  `tests/macos_helper_reference.rs`). Proved it has teeth by reverting
  to the hard-coded `false` and confirming the modal window's
  `blocks_input` silently reverted under the identical harness.
- Same known limitation as DR-2b/DR-2c: `cargo test`/`clippy`/`fmt`
  could not be run this round (sandbox egress policy blocks
  `static.crates.io`), so this test file addition is verified at the
  shell-script level only, not confirmed to compile.
- Also investigated, but deliberately did NOT change, the equivalent
  Wayland gap: only a single secondary source (a search-result summary,
  not the primary manpage or protocol spec, both of which 403'd on
  fetch) suggested a usable signal exists, which isn't solid enough
  ground to touch a shipped parser. Recorded in
  `docs/FEATURE_AUDIT_2026H2.md`'s DR-2 section for a future session
  with real `lswt`/Wayland access to verify directly.

### Fixed — macOS helper hard-coded `has_close_button: true` (audit DR-2c)
- `muten-overlay-helper-macos.sh` hard-coded `has_close_button: true`
  unconditionally, silently suppressing the classifier's `no_close_button`
  (+25) signal — the single strongest behavioral tell of a scam overlay —
  for a genuinely borderless/frameless scam window (e.g. an Electron
  `BrowserWindow` with `frame:false`) on macOS.
- Fixed by checking `exists (button 1 of w)` per window in the AppleScript
  enumeration block: the same `button 1` accessor `dismiss()` already
  relies on to click the close button, so "no `button 1`" and "`dismiss()`
  can't gracefully close this window" are now consistent by construction
  instead of two independently-drifting assumptions.
- Verified end-to-end by stubbing `osascript` on `PATH` (both the `-e`
  single-expression form and the heredoc/stdin multi-line form the script
  actually uses) and running the real shipped shell script directly (new
  `tests/macos_helper_reference.rs`,
  `enumerate_reports_has_close_button_from_button_1_existence`); proved
  it has teeth by reverting to the hard-coded `true` under the identical
  harness and confirming a borderless test window's `has_close_button`
  silently reverted to `true`.
- Same known limitation as DR-2b: `cargo test`/`clippy`/`fmt` could not
  be run this round (sandbox egress policy blocks `static.crates.io` on
  a cache-less container) — only the shell-script fix itself was
  verified end-to-end, directly, without cargo. Treat
  `macos_helper_reference.rs` as unverified-to-compile until the next
  session confirms it with a working `cargo`.

### Fixed — X11 helper hard-coded `blocks_input: false` (audit DR-2b)
- `muten-overlay-helper-linux.sh` hard-coded `blocks_input: false`
  unconditionally, silently suppressing the classifier's `blocks_input`
  (+20) signal for a genuinely modal scam dialog on X11. Also corrected a
  stale claim in `docs/FEATURE_AUDIT_2026H2.md`'s own prior DR-2 write-up:
  `has_close_button` was NOT actually hard-coded on X11/Windows (both
  already derive it from real EWMH/`WS_SYSMENU` signals, predating this
  audit cycle) — only macOS and Wayland still hard-code it.
- Fixed by deriving `blocks_input` from the standard EWMH
  `_NET_WM_STATE_MODAL` atom, reusing the same `_NET_WM_STATE` `xprop`
  fetch already made for `topmost` — one X11 round-trip now covers both
  signals instead of hard-coding one of them.
- Verified end-to-end by stubbing `xprop`/`wmctrl`/`xdotool` on `PATH`
  and running the actual shipped shell script directly (new
  `tests/linux_helper_reference.rs`,
  `enumerate_reports_blocks_input_from_net_wm_state_modal`); proved it
  has teeth by reverting to the hard-coded `false` under the identical
  harness and confirming a modal test window's `blocks_input` silently
  went back to `false`.
- **Known limitation of this round**: the sandbox's egress policy
  blocked `static.crates.io` crate downloads on an otherwise cache-less
  container, so `cargo test`/`clippy`/`fmt` could not be run against the
  new Rust test file — only the shell-script fix itself was verified
  end-to-end (directly, without cargo). Treat `linux_helper_reference.rs`
  as unverified-to-compile until the next session confirms it with a
  working `cargo`.

### Added — `docs/MODEL_PLAYBOOK.md`
- A personal reference mapping which Claude model (Haiku/Sonnet/Opus/
  Fable 5) and which skill fits which kind of work on this repo, grounded
  in what this session's DR-1 → DR-11 → DR-2a → DR-5 → DR-3 loop actually
  needed at each step (e.g. self-review of a not-yet-tested design catching
  a false-positive class before any test ran, vs. mechanical struct-literal
  edits across ~25 call sites).

### Added — blocklist hot-reload for `daemon` (audit DR-3)
- `--rules` was previously only ever read once at startup: pushing an
  updated blocklist (a newly discovered scam host, a bad process name) to
  a fleet running `daemon` required stopping and restarting every
  instance — a real availability gap, since the whole point of a
  long-running daemon is to not need a restart for routine policy
  updates.
- `Monitor` gained `set_rules(&mut self, rules: Ruleset)`, replacing the
  active blocklist from the next `sweep()` onward without touching any of
  its repeat/age/presence tracking state (a rules change has no bearing
  on which windows have already been observed).
- `cmd_daemon`'s loop now stats the `--rules` file once per sweep (a
  single cheap `metadata()` call) and, if its mtime has advanced since
  the last successful load, re-reads and re-parses it and calls
  `set_rules`. A transient read failure (file mid-write, briefly
  unreadable) is best-effort — same pattern already used for the metrics
  writer: warn once per failure streak, keep protecting on the
  last-good ruleset, and retry automatically next sweep since the
  failed attempt doesn't advance the tracked mtime.
- Added `daemon_reloads_rules_file_edited_while_running` (`cli_contract.rs`):
  runs the real binary against a window that only a `host:` rule can ever
  flag, starts with a non-matching rules file, edits it in place mid-run
  to add the matching host, and asserts an `overlay_blocked` event with
  the right `matched_rule` appears afterward. Proved it has teeth by
  reverting to the original load-once behavior and confirming the test
  failed (no audit log was ever created — the edit was never picked up)
  before restoring the fix.

### Fixed — stop-flag response latency on long `--interval-ms` (audit DR-5)
- `cmd_daemon`'s sweep loop checked the `--stop-flag` file only once per
  sweep, then slept for the *entire* configured interval in one unbroken
  `thread::sleep` call. A daemon tuned for a large fleet (a long interval
  to keep idle CPU near zero) could take up to that whole interval —
  potentially many seconds — to actually stop after a service manager's
  `ExecStop` touched the flag file, even though nothing else in the loop
  was doing any work during that time.
- Fixed by splitting the sleep into 250ms chunks, re-checking the stop
  flag between each chunk and breaking out early the moment it appears —
  the same file-check pattern the loop already used between sweeps, just
  applied more often. No new dependency, no new CLI flag: 250ms is a fixed
  granularity fine-grained enough to feel instant to an operator while
  still being cheap for a daemon that may run for weeks.
- Added `daemon_stop_flag_takes_effect_promptly_on_a_long_interval`
  (`cli_contract.rs`): runs the real compiled binary with `--interval-ms
  5000`, requests a stop after 200ms, and asserts the process exits in
  under 2s rather than waiting out the full 5s interval. Proved it has
  teeth by reverting to the single unbroken sleep first: the unfixed
  binary took 4.87s to exit under the same test, confirming the assertion
  actually distinguishes the two behaviors.

### Added — `age_ms` inference for the `very_new` signal (audit DR-2, `age_ms` slice)
- All four real OS helpers unconditionally report `age_ms: 0` ("unknown" —
  see `OverlayWindow::age_ms`'s documented contract), which silently
  disabled the `very_new` (+10) signal and the `sudden_fullscreen_takeover`
  composite (both gated on `age_ms > 0 && age_ms < 1000`) on every real
  host, even though the classifier logic for both was already correct and
  tested. Fixing this properly per-helper (4 platforms × OS-specific
  window-creation-time APIs) is a larger undertaking left as the
  remaining, still-`OPEN` part of DR-2; this round closes the
  `age_ms`-specific gap without touching any helper, by having `Monitor`
  infer age from how long *it* has been tracking a window whenever the
  helper reports `0`.
- `Monitor` gained `first_seen_ms: HashMap<WindowId, u64>` (first sweep
  timestamp a window id was observed, pruned each sweep to only
  currently-present ids) and infers `age_ms = now_ms - first_seen_ms` for
  `sweep()`'s classification pass whenever the helper's reported age is 0.
- Caught and fixed a subtler bug in my own first draft of this fix before
  it ever reached a test run: gating the *entire* `first_seen_ms` insert
  on "not the daemon's first sweep" (to protect against treating
  already-open-for-hours startup windows as newly-aged) meant a window
  present continuously since sweep 1 never got a `first_seen_ms` entry
  during sweep 1 — so on sweep 2 it looked like a brand-new id, got
  inserted fresh, and was scored `very_new` starting a few sweeps later
  anyway. The same false-positive class the fix was meant to prevent,
  just delayed by one sweep instead of eliminated.
- Corrected design: `first_seen_ms` is now recorded unconditionally on
  every sweep including the first, and a separate
  `untrusted_from_startup: HashSet<WindowId>` marks every window id
  present during the daemon's very first sweep. Age inference is only
  trusted (used) for an id *not* in that set. The set is pruned to only
  currently-present ids at the end of every sweep, so the moment a
  startup-cohort window is ever absent even once, it permanently loses
  its untrusted status — a later reappearance is a genuinely fresh
  observation (the OS could easily reuse the id for an unrelated window)
  and gets a trustworthy inferred age like any other window from then on.
- Added 3 new unit tests in `monitor.rs`
  (`startup_cohort_window_never_gets_inferred_age_while_continuously_present`,
  `window_appearing_after_first_sweep_gets_trusted_inferred_age`,
  `startup_cohort_window_becomes_trusted_again_after_disappearing_and_reappearing`)
  and 1 `cli_contract.rs` end-to-end test against the real compiled binary
  and real wall-clock time (`daemon_startup_cohort_window_never_treated_as_very_new`).
  Proved the first unit test and the e2e test both have teeth: reverted
  to the flawed `!was_first_sweep`-gated-insert design and confirmed both
  failed (the e2e test caught the real daemon firing `overlay_suspicious`
  with `very_new` on every sweep after the first), then restored the fix.

### Fixed — long-lived benign windows falsely flagged as a repeat-flood (audit DR-11)
- `Monitor::sweep` recorded a repeat-tracker "appearance" for **every**
  enumerated window on **every** sweep, conflating presence (still on
  screen) with appearance (just popped up). `signature()` is content-only
  (`title|host`), so a perfectly ordinary window left open produced the
  identical signature every sweep; combined with `REPEAT_THRESHOLD=3`,
  any such window crossed the threshold after 3 sweeps and then fired
  `scareware_detected` (repeated_flood) **continuously** for as long as
  it stayed open. The pre-existing `Origin::UserInitiated` carve-out
  never helped in practice: every real OS helper (all four platforms)
  reports `origin:"unknown"`, never `user_initiated`, so on a real host
  this bug would have flagged nearly any long-lived window. Found and
  reproduced during e2e verification of the DR-1 process-reporting work
  in the prior round (2 spurious `scareware_detected` events across 4
  sweeps of one static benign window), and deliberately left unfixed
  there pending its own scoped fix.
- Fixed by giving `Monitor` a `present_last_sweep: HashSet<Signature>`
  of the *immediately prior* sweep's signatures (replaced wholesale each
  sweep, so memory stays bounded by on-screen window count — no growth
  over a long-running daemon). A signature already in that set means
  "still here," so the tracker is only probed (`count`, non-incrementing)
  rather than recorded; a signature absent from it — first sight, or
  reappearing after having genuinely disappeared — is treated as a real
  new appearance (`record`, incrementing), preserving detection of an
  actual rogue-AV re-pop flood (alert closes, reappears moments later).
- Every pre-existing test that modeled "a flood" as *the same static
  controller swept repeatedly* (which is exactly the presence-only
  pattern the fix now correctly excludes) was rewritten to alternate
  between a controller reporting the window and one reporting nothing,
  matching real re-pop behavior instead of baking in the bug:
  `repeated_scam_triggers_scareware_event` and
  `unsolicited_repeats_still_flood` (`monitor.rs`), and the
  `unsolicited_repeats_always_flood` property test
  (`monitor_properties.rs`, corrected to generate exactly `reps` genuine
  appearances rather than `reps` sweeps of unbroken presence).
- Added 2 new direct unit tests pinning both directions
  (`long_lived_benign_window_does_not_trigger_repeated_flood`,
  `genuine_repop_flood_still_detected_across_gaps`) and 1 `cli_contract.rs`
  end-to-end test against the real compiled binary
  (`daemon_long_lived_benign_window_never_triggers_repeated_flood`).
  Manually re-verified both directions against the running daemon with
  fake helpers: a static benign window produced 0 `scareware_detected`
  across 6 sweeps (previously would have fired from sweep 3 onward); an
  alternating appear/disappear helper modeling a genuine re-pop still
  produced 3 `scareware_detected` events across 10 sweeps.

### Added — helper process reporting (audit DR-1: rogue-AV detection live in daemon mode)
- **`EnumeratedWindow.process`** (optional, `#[serde(default)]`) — the
  owning process / application name, reported by the helper *in* its
  `enumerate` payload (atomic with the window snapshot; a separate
  `processes` verb was rejected: it would double the subprocess spawns per
  sweep and introduce a TOCTOU between the window list and process list).
  `Monitor::sweep` prefers the embedded value and keeps the `process_of`
  callback as the out-of-band fallback. Until now `cmd_daemon` hard-wired
  `process_of` to `None` ("no process-list verb in the helper protocol"),
  so the `rogue_av_process` signal and all 49 shipped `process:` blocklist
  rules were dead in production daemon mode — detection-side code
  (`assess`/`match_process`) was complete; only the attribution channel
  was missing.
- All four helpers now report it best-effort (field omitted when unknown;
  old-format helper JSON keeps parsing unchanged): Windows adds a
  `GetWindowThreadProcessId` P/Invoke + `Get-Process` name lookup;
  Linux/X11 reads EWMH `_NET_WM_PID` → `/proc/PID/comm`; macOS emits the
  System Events process name it already iterates; Wayland emits the
  foreign-toplevel `app-id` (PIDs are not exposed to foreign clients —
  `match_process`'s squash semantics let `org.mozilla.firefox` match a
  rule written `firefox`). `parse_windows` also accepts a top-level
  `"process"` key so `monitor`/`enforce`/`triage` demo inputs can exercise
  the path.
- Verified end-to-end, not just at the unit level: a new `cli_contract.rs`
  test runs the real daemon against a helper reporting a blocklisted
  process on a *benign-titled* window (so only the `process:` rule can be
  responsible) and asserts `scareware_detected` + `rogue_av_process` +
  `matched_process` land in the audit log and `muten_scareware_total` goes
  non-zero. Manual runs confirmed both the new format and the old
  (process-less) format against the compiled binary. New unit tests pin
  embedded-value precedence over the callback and old-JSON back-compat.
- SPECIFICATION.md gained the `{id, process?, window}` wire table (and
  caught up on `ControllerError::Timeout` and the full 9-subcommand list);
  OVERLAY_BLOCKING.md documents the per-OS process source.
- **Known issue found during e2e verification (not yet fixed, audit
  DR-11)**: `Monitor::sweep` records a repeat-tracker "appearance" for
  every enumerated window every sweep, so a long-lived, perfectly normal
  window crosses `REPEAT_THRESHOLD=3` after 3 sweeps and emits
  `scareware_detected` (repeated_flood) continuously — presence is being
  conflated with re-popping, and the `user_initiated` carve-out never
  applies on real hosts because helpers report `origin:"unknown"`.
  Documented in `docs/FEATURE_AUDIT_2026H2.md` as the new top remaining
  deficiency alongside DR-2.

### Fixed — metrics write failure killed the protection loop
- The live-metrics fix below initially propagated a failed per-sweep
  metrics write with `?` — meaning a missing metrics directory (a fleet
  host without node_exporter installed), a full disk, or a mid-run
  permission change would kill the entire protection loop on that sweep.
  Metrics are observability, not the mission: now best-effort, warning
  once per failure streak (not every sweep at 1s intervals) and noting
  recovery. New `cli_contract.rs` test points `--metrics` into a
  nonexistent directory and asserts the daemon keeps sweeping (multiple
  audit events written) and still exits 0 on graceful stop.

### Fixed — `--metrics` only updated once, at graceful shutdown
- `daemon` computed and wrote its Prometheus textfile metrics exactly once,
  after the sweep loop exited on a stop-flag. For a daemon meant to run for
  weeks, this meant node_exporter's textfile collector saw *nothing* — no
  file at all — the entire time the daemon was healthy and running, only
  ever seeing data after the first graceful stop (which may be weeks away,
  or may never happen if the host is simply rebooted or the process is
  killed). This defeated the explicit "compatible with node_exporter
  --collector.textfile" purpose of the flag for its actual intended use
  case, even though it looked correct in every prior test (all of which
  used short-lived runs immediately followed by a stop-flag, matching the
  demo pattern rather than the real 24/7 production pattern).
- Fixed with a `CountingSink` wrapper around the audit sink that tallies
  block/suspicious/scareware counts in O(1) per event as they're emitted,
  and rewrites the metrics file after every sweep. Deliberately O(1) per
  event rather than re-scanning the audit log (as `cmd_monitor`'s
  end-of-run `count_audit_kinds` still does, which is fine for its bounded
  N-sweep demo use but would make an hourly-or-finer metrics refresh
  increasingly expensive against a real, growing, multi-week log).
- Verified with a real running process, not a static assertion: a new
  `cli_contract.rs` test spawns a daemon against a helper that returns a
  scam window every sweep, polls the metrics file *while the daemon is
  still running* (stop-flag not yet created), and asserts it already shows
  non-zero activity — then proved the test has teeth by temporarily
  reverting to the old write-once-at-shutdown behavior and confirming the
  test failed (5s timeout) before restoring the fix.

### Fixed — concurrent-instance audit-chain corruption risk
- **No single-instance guard on `daemon`** — `ChainedFileSink::open` reads
  the chain head into in-process memory with no cross-process coordination;
  two daemon instances pointed at the same `--audit-log` would each start
  from the same head and race to append, corrupting the tamper-evident
  hash chain — silently defeating the entire point of running one. A real
  advisory lock (`flock`) isn't reachable within this crate's constraints
  (needs either a newer std API than MSRV 1.75 ships, or raw libc FFI,
  and the crate is `forbid(unsafe_code)` with no new dependencies).
  Added a best-effort, std-only, safe-Rust lock: `daemon` atomically
  creates `<audit-log>.lock` (`create_new`, POSIX `O_EXCL`) before opening
  the audit log, refuses to start if it already exists, and removes it on
  a graceful stop. Documented, not hidden: a plain file isn't a kernel-
  held lock, so it does not self-clear after an unclean kill/crash — the
  error message tells the operator to confirm no other instance is
  genuinely running before deleting a stale lock, and the 3 service-
  manager templates were updated to auto-clear the lock in their
  supervisor-invoked startup step specifically (safe there, and only
  there, because systemd/launchd/Task Scheduler each independently
  guarantee the previous instance is fully dead before restarting the
  same managed unit/agent/task — an ad-hoc script bypassing the service
  manager must not adopt the same auto-clear).
- Proven with a real two-process race, not just a unit test of the lock
  function in isolation: a new `cli_contract.rs` test spawns one daemon,
  confirms a second spawn against the same `--audit-log` is refused (exit
  1), then stops the first gracefully and confirms the lock file is
  released for a legitimate restart.

### Fixed — untested `--helper-timeout-ms` CLI wiring
- The prior round's library-level timeout tests proved `SubprocessController
  ::with_timeout` works, but nothing proved the CLI flag actually reaches
  it — a refactor could silently revert `cmd_daemon` to
  `SubprocessController::new` (the library's own 5000ms default) and no
  test would notice. Added a regression test with a tight 2-second
  threshold (deliberately far below the 5000ms default, to actually
  distinguish "the flag worked" from "the flag was silently dropped") and
  verified it has real teeth by temporarily reverting the wiring and
  confirming the test fails, then restoring it.

### Fixed — hung-helper freeze and zero-event crash in the new daemon loop
- **`SubprocessController` had no timeout** — `Command::output()` blocks
  synchronously forever; a helper hang (a broken window-manager IPC call, a
  stuck modal blocking AppleScript, a frozen COM call) would freeze the
  entire `daemon` loop, including its own graceful-stop check (the
  stop-flag is only polled *between* sweeps). Found by turning the same
  Socratic questioning on the `daemon` feature just added in the prior
  round: "what happens if the subprocess never returns?" Fixed by
  rewriting `run`/`available` to spawn, drain stdout/stderr on separate
  threads (avoiding a pipe-buffer deadlock while polling), and poll
  `try_wait` against a bounded timeout (default 5s, `with_timeout`
  constructor, `--helper-timeout-ms` CLI flag) — a hung helper is killed
  and surfaced as the new `ControllerError::Timeout` variant instead of
  blocking forever. 4 new tests prove a genuinely hung helper (`sleep
  3600`) is killed within the configured timeout, not left running.
- **`cmd_monitor`/`cmd_daemon` crashed on an all-benign run** —
  `ChainedFileSink` creates its log file lazily on the first `emit()`; a
  run where every window classifies as Allow (or, for `daemon`, an empty
  desktop) never calls `emit()` at all, so the file may genuinely never
  exist. The post-run verification/metrics code unconditionally read the
  file, so this common, healthy, zero-detection case crashed with exit 1
  instead of exiting 0 with zero counts — caught by manually running the
  exact scenario end-to-end (not just unit-testing the pieces in
  isolation). Fixed in 3 places (`cmd_monitor`'s own chain-verification
  read, `cmd_daemon`'s, and the shared `count_audit_kinds` helper both use)
  by treating a missing file the same as an empty, trivially-valid chain.
  2 new `cli_contract.rs` regression tests cover both subcommands.

### Added — `daemon` subcommand (real continuous protection loop)
- **`muten-overlay daemon <helper>`** — Socratic gap analysis found that
  `enforce`/`monitor` only ever run against `NullController` over a static
  window list (dry-run/demo tooling), while `SubprocessController` (real
  helper invocation) and `Monitor::run`/`Monitor::sweep` (a fully generic,
  production-ready continuous loop with adaptive interval and a signal-free
  file-based stop mechanism) already existed in the library, fully tested,
  but nothing in the shipped binary ever wired them together. There was no
  way to actually run muten-overlay as a live protective agent on a real
  machine.
- Probes the helper once at startup and fails fast (exit 1) rather than
  looping forever against a broken helper; loops `Monitor::sweep` unbounded
  against a real wall clock and a real `--stop-flag` file
  (`--interval-ms`/`--alert-interval-ms`/`--audit-log`/`--stop-flag`/
  `--metrics`); writes an honest `muten_sweeps_total` Prometheus counter on
  graceful shutdown (hand-rolled sweep loop rather than calling
  `Monitor::run` directly, since `run` only returns the dismissed count).
- Verified end-to-end against a real fake-helper subprocess (not just unit
  tests of the library pieces in isolation): 2 new `cli_contract.rs`
  integration tests spawn the actual binary, drive it through several real
  sweeps, trigger a graceful stop via the flag-file convention, and assert
  the resulting audit log is a valid verifiable hash chain and the metrics
  file reflects real, non-zero activity.
- **`installer/overlay-helper/`** gained the actual deployment artifacts
  the product's own docs promised ("pushed via MDM") but never shipped:
  a systemd unit (`muten-overlay.service`), a macOS launchd agent
  (`com.muten.overlay.plist`), a Windows Scheduled Task
  (`muten-overlay-task.xml`), and a `README.md` documenting the
  Intune/Jamf/GPO/Ansible push pattern for each, plus the shared
  signal-free graceful-stop convention (touch a stop-flag file; the daemon
  exits 0 on its own within one sweep interval).

### Added — new detection signal (E66)
- **`notification_permission_bait`** (W=20, InterfaceInterference) — fake content-gate
  behind the browser's native notification-permission prompt: "Click Allow to continue
  watching / download / access" with no CAPTCHA framing at all (distinct from
  `clickfix_instruction`'s "not a robot" / "verify human" vocabulary, which does not
  cover this variant). Once granted, the site can push OS-level fake system alerts
  persistently, even with the browser closed — a distinct 2025-2026 growth vector
  ("Matrix Push C2", Malwarebytes Nov 2025) from ClickFix's clipboard-paste technique.
  Full 10-lens wiring: T1566 Phishing, Extract lifecycle stage, DeviceTakeover
  extraction (Mitigable), Medium magnitude, General victim profile; exempt from the
  persuasion lens as an action/gate mechanic (like `download_trap_lure`/`qr_code_lure`).

### Added — new detection signals (E63–E65)
- **`toad_case_number_lure`** (W=20, InterfaceInterference) — TOAD (Telephone-Oriented
  Attack Delivery) fingerprint: fake case/ticket/incident ID paired with "call now" /
  "call support" CTA. Proofpoint 2022/2024 data shows 554 % YoY surge in TOAD
  campaigns. Full 10-lens wiring: Authority persuasion, Pressure lifecycle stage,
  T1566 Phishing, General victim profile.
- **`wallet_connect_popup_lure`** (W=30, InterfaceInterference) — Web3 wallet-drainer
  popup: wallet-connect verb (connect MetaMask / link wallet / authorize wallet) +
  reward hook (claim airdrop / free NFT / token airdrop). IC3 2024 #1 loss category
  ($4.57 B). Full 10-lens wiring: Scarcity persuasion, Extract lifecycle, T1566,
  Cryptocurrency extraction (Irreversible), Catastrophic magnitude, CryptoInvestor
  victim profile.
- **`fake_browser_security_warning`** (W=25, InterfaceInterference) — Fake browser
  cert/SSL error + scam CTA (call support / click to fix / download security).
  Impersonates Chrome/Firefox/Edge/Safari security error pages. Full 10-lens
  wiring: Authority persuasion, TrustBuild lifecycle, T1036 Masquerading, TechVendor
  impersonation family, General victim profile.

### Fixed
- **`remote_access_lure` trigger gap** — `fake_alert_present` guard was limited to 3
  signals (blocklist_title, phone_number, clickfix_instruction). A fake BSOD + RAT
  lure would miss `remote_access_lure`. Widened to 11 signals, adding fake_bsod_lure,
  fake_scanner_cue, windows_defender_alert_lure, ip_alarm_lure, av_brand_renewal_scam,
  tech_support_invoice_scam, windows_activation_scam.
- **CONTENT_SIGNALS coverage gap** — 10 signals present in `all_signals()` were missing
  from `CONTENT_SIGNALS`, so the full-wiring coverage guard `every_content_signal_is_
  fully_wired()` silently skipped them. Added all 10 to the list (alarm_density,
  task_app_scam, software_subscription_scam, dark_web_breach_lure, cloud_quota_lure,
  windows_defender_alert_lure, tech_support_chat_lure, plus the 3 new E63–E65 signals).
- **MITRE ATT&CK mappings** — 7 signals (alarm_density, task_app_scam, software_
  subscription_scam, dark_web_breach_lure, cloud_quota_lure, tech_support_chat_lure,
  windows_defender_alert_lure) lacked MITRE technique entries, causing the now-active
  coverage guard to fail. Mapped to T1566 (Phishing) for 6 social-engineering signals
  and T1036 (Masquerading) for windows_defender_alert_lure.
- **2 broken rustdoc links** — `[fold_letter_digits_for_phone]` (rules.rs) and
  `[normalize_for_match]` (lib.rs) referenced private functions; changed to backtick-
  only code spans. `cargo doc --no-deps` now produces 0 warnings.
- **`crypto_drain_lure` false positive** — the `wallet_coerce` sub-pattern fired on
  bare "connect" + any wallet word (wallet/metamask/coinbase/web3/defi/nft) with no
  alarm or reward context. "Connect Wallet" is the universal, always-benign primary
  CTA on every legitimate Web3 dApp (Uniswap, OpenSea, MetaMask itself); confirmed via
  the `benign_corpus` adversarial-benign test harness. Removed "connect" from the
  coercion-verb list — genuine drainer patterns remain caught via `wallet_alarm`
  (connect + alarm word) and the new `wallet_connect_popup_lure` (connect + reward
  hook).
- **`cloud_quota_lure` false positive** — generic quota wording ("storage is full",
  "storage almost full", "upgrade your plan") is the verbatim text of Apple's and
  Google's own real, legitimate low-storage notifications (e.g. Apple's actual
  notification title "iCloud Storage Almost Full"), so a phishing overlay mimicking
  that UI could never be distinguished from the real thing by content alone. Redesigned
  as a two-tier AND-pair: an explicit deletion/loss consequence ("your photos will be
  deleted" — language real first-party copy avoids) fires alone; generic quota wording
  now additionally requires explicit sign-in/urgency pressure ("verify your account",
  "act now") that a passive OS notification never applies.

### Improved
- **Japanese alarm_density vocabulary** — Added 6 high-confidence Japanese fear-words
  sourced from IPA 2024 サポート詐欺 advisory and JPCERT/CC corpus: ウイルス (virus),
  マルウェア (malware), 凍結 (frozen/locked), 危険 (danger), ランサムウェア (ransomware),
  トロイ (Trojan). Previously these JP-only scam titles would fall below the 3-word
  threshold; now they correctly fire alarm_density.
- **`#[non_exhaustive]` on 6 public enums** — DarkPatternCategory, Origin, ScamStage,
  VictimProfile, ExtractionVector, AbusedAuthority. Prevents semver-breaking changes
  when future signal families add new variants (roadmap C5-5).
- **docs.rs metadata** — Added `[package.metadata.docs.rs]` with `all-features = true`
  and `rustdoc-args = ["--cfg", "docsrs"]` so docs.rs generates docs for all features.

### Documentation
- `docs/OVERLAY_BLOCKING.md` scoring table was missing 27 of 64 signals (everything
  added after `loan_fee_scam`) — added one row per signal, each individually verified
  against the actual `W_*` weight constant, detector doc comment, `category_of()`, and
  `techniques_of()` mapping. Also fixed a stale `remote_access_lure` row describing the
  old 3-signal trigger.

### Tests
- 1 328 unit tests + 23 `cli_contract` integration tests (up from 1 308
  unit-test baseline for this cycle), 0 failures, clippy-clean.

## [0.6.0] — evasion-resistant normalization (rounds 10–23)

A long, additive hardening cycle for the homoglyph / text-evasion defence.
Each round asked "what would an attacker who read our source code exploit
next?" and closed the gap, staying offline, pure, `forbid(unsafe_code)`,
dependency-free, MSRV 1.75, and false-positive-averse throughout. See
`docs/SPECIFICATION_V2.md` for the full coverage table and methodology.

### Added — confusable folding (`fold_char` / `normalize_for_match`)
- **Mathematical Alphanumeric Symbols** (U+1D400–U+1D7FF): all 16 letter
  styles (bold/italic/script/fraktur/double-struck/sans/mono), incl. the
  hole-filling Letterlike characters.
- **Greek** completeness: lowercase η/τ/ω/γ/μ, lunate sigma ϲ/Ϲ, yot ϳ,
  uppercase Ω, π/Π, ζ; **Coptic** block (U+2C80–U+2CB1, 30 letters);
  **Armenian** strong homoglyphs (օ/Օ→o, ո→n, ս→u, հ→h, յ→j); extended
  **Cyrillic** Supplement (һ, Ӏ, ԁ, ԛ, ԝ).
- **Small-capital / phonetic** letters (IPA, Phonetic Ext., Latin Ext-D),
  **Roman numeral** single-letter forms, **enclosed/circled** letters,
  **fullwidth** ASCII, **script decimal digits**, **circled/superscript
  digits**, **dash variants**, katakana middle dot.
- **Superscript/subscript/modifier** Latin letters (U+2071, U+207F,
  U+2090–U+209C, U+02B0–U+02E3).
- **NFKD-authoritative compat folds**: every codepoint Unicode declares
  compatibility-equivalent to a single ASCII letter (long-s ſ, Kelvin
  sign K, ⱼ, ꟴ, …). Ordinal indicators ª/º deliberately *not* folded
  (legitimate Spanish/Portuguese ordinals).

### Added — detection signals & pipeline
- `normalize_for_match` 11-step pipeline (bound → strip emoji → expand
  ligatures → fold halfwidth katakana → fold unicode spaces → strip
  invisibles → strip combining marks → fold confusables → collapse spaces
  → collapse spread-characters → fold leet → lowercase).
- `collapse_spread_characters`: rejoins ≥4 single-char spread words; R23
  expanded the separator set (`= # ; \ !` and dot-operators ‧ ∙ ⋅),
  keeping `:`/`+` excluded for countdown timers / Win+R shortcuts.
- `has_confusable_mixed_script`, `has_whole_script_confusable`,
  `has_compat_alpha` (incl. small-cap runs), `has_bidi_override`,
  `has_mixed_number_systems`, `has_excessive_combining_marks`.
- Dozens of scam-content detectors (clickfix, urgency countdown, forced
  retention, credential harvest, fake scanner, sextortion, gift-card,
  refund, tax-authority, pig-butchering, and many more).

### Changed
- `Script` enum is now `#[non_exhaustive]` and gained `Coptic` / `Armenian`
  variants (downstream exhaustive matches must add a wildcard arm).

### Tests
- ~1,053 unit tests + 242 scoring scenarios + extensive property tests
  (every detector: never-panic + no-false-positive invariants).

## [0.5.0] — mixed-script detection & explainability

### Added
- Mixed-script homoglyph signal, zero-width / BiDi stripping, leetspeak
  folding for blocklist matching.
- `Verdict::explain()` natural-language rationale; CLI `--json` output.
- `Sneaking` category mapping for `mixed_script`.

## [Unreleased] — v0.4.0 (product redefinition)

### Changed (BREAKING — product scope)
- **muten is redefined from "PC forced-mute" to "endpoint environment
  enforcement (audio + screen)".** The audio enforcement is unchanged
  and fully backward compatible; the product now *also* detects scam /
  full-screen overlay windows on the same managed PCs. README and
  positioning updated accordingly. See `Plan.md` for the scope
  decision and `docs/OVERLAY_BLOCKING.md` for the design.

### Added
- **`muten-overlay` crate** — pure-domain scam-overlay classifier
  (`forbid(unsafe_code)`, no OS, no network):
  - `OverlayWindow` observation type (title, url, coverage, topmost,
    close button, input capture, origin, age).
  - `classify()` — explainable additive-score heuristic with named
    weights; returns `Verdict { decision, score, signals, matched_rule }`.
  - `Decision`: `Allow` / `Suspicious` (audit, don't dismiss) / `Block`.
  - Offline `Ruleset` blocklist (host + subdomain matching, title
    substring patterns, comments, bare-host lines). Pushed via MDM,
    read offline.
  - `muten-overlay` dry-run CLI: `classify` (exit 0/5/6) and `rules`.
  - 18 unit tests + 7 property tests (~1,800 random cases): classifier
    never panics, score monotone in each suspicious signal, decision
    thresholds consistent, blocklist parser never panics, subdomain
    matching, hard-block on host hit.
- Example blocklist (`examples/overlay-blocklist.txt`) and sample scam
  observation (`examples/overlay-sample.json`).
- `docs/OVERLAY_BLOCKING.md`.

### Design notes
- **Observe-first**: default posture flags suspicious overlays for IT
  review rather than auto-dismissing, because false positives would
  break legitimate full-screen apps (video, presentations, exams,
  kiosk UIs). Only confirmed blocklist hits or unmistakable scores
  (≥100) yield `Block`.
- **No ML**: transparent, auditable scoring per CLAUDE.md I6 / Pike.
- **Privacy (I5)**: classification is fully on-device; no window
  metadata leaves the machine.

### Pending (next session)
- OS-specific window enumerator + dismisser (like the audio backends).
- Merge `muten-overlay` into the restored workspace + wire daemon to
  emit `OverlayBlocked` / `OverlaySuspicious` audit events into the
  hash chain.
- New `EventKind::OverlayBlocked` / `OverlaySuspicious` + SIEM severity
  mapping.
- README full rewrite around the "audio + screen" positioning.

## [0.3.x] / [0.3.0] / [0.2.0] / [0.1.x]

(Prior audio-enforcement history — preserved in earlier transcripts
and the restored workspace.)
