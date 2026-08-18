# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Conventional Commits](https://www.conventionalcommits.org/).

## [0.6.0] — evasion-resistant normalization + TOAD/Web3/browser-security signals (rounds 10–31)

### Fixed (accuracy) — the signal count was stale at 66; it is **89**
- Mechanically re-verified the project's headline claims instead of
  trusting them. `#![forbid(unsafe_code)]` present ✓; 26 `cli_contract`
  tests ✓; 6 direct dependencies (the "no *new* dependencies" invariant
  is intact) ✓.
- **Two figures were wrong.** `all_signals()` contains **89** unique
  signal names (no duplicates), but `FEATURE_AUDIT_2026H2.md` said "66
  signals" — and I repeated that stale number in my own DR-20 and
  THREAT_INTEL analysis this session, describing "~60 vocabulary
  signals". The real split is **9 structural** (geometry + origin) vs
  **80 non-structural**. Corrected everywhere, including the derived
  "adding the 61st vocabulary signal" phrasing → 81st.
- The correction **strengthens DR-20 rather than weakening it**: the
  imbalance between the durable structural signals and the brittle
  content ones is larger than the entry claimed, not smaller.
- Also noted: `src/` now holds 1333 `#[test]` functions against README's
  "1331" — the two DR-12 tests that have never been compiled. Left the
  README figure alone rather than asserting a count no one has run;
  WO-1 updates it from real `cargo test` output.

### Documented — the shipped blocklist has **zero `host:` rules**, which nothing said
- Swept the remaining rule types for the dead-rule class: all 44
  `process:` rules are distinct (0 redundant), and there are **0 `host:`
  rules at all** — a fact that appeared nowhere in the blocklist, the
  README, or the docs.
- This matters because `host:` is the strongest thing in the product:
  `classify()` returns `Decision::Block` immediately on a match,
  short-circuiting every other signal. So the single most powerful
  detection path ships empty, and an operator would reasonably assume
  otherwise.
- The emptiness is **correct** — an earlier revision carried fabricated
  example hosts and they were removed, because a curated known-bad list
  the authors cannot continuously verify would be stale or invented, and
  inventing one makes the most powerful rule type the least trustworthy.
  The problem was that this was silent.
- Documented it prominently in the blocklist header: why it is empty,
  that detection therefore runs entirely on the heuristic path, and how
  to populate it from a source the operator actually trusts (DNS/proxy
  telemetry, threat-intel feed, hosts seen in real incidents) — with the
  warning that it is a high-privilege list, since one wrong entry
  hard-blocks a legitimate site with no score to soften it.

### Added — `scripts/verify.sh`: one verification entrypoint, usable today
- **Questioned the requirement instead of the blocker.** "Changes are
  verified before they land" had been conflated with "GitHub Actions runs
  them" — and since only a repository owner can install
  `.github/workflows/`, verification stayed blocked indefinitely. Those
  are different things. `scripts/verify.sh` runs every check that does
  not need the registry, on any machine, right now.
- Checks: `sh -n` on all shipped helpers and scripts; the blocklist lints
  clean (DR-22); `Cargo.lock` agrees with `Cargo.toml`'s exact pins — the
  **DR-23 class of failure**, where a dependency change reaches a build
  unverified; `dependabot.yml` carries no invalid `automerge:` key
  (DR-24); and the crate declares a `rust-version` at all.
- **A skip is never a pass.** Unavailable checks are reported as SKIP,
  named, and the summary states outright that a run which skipped the
  Rust phase has *not* verified that the crate compiles or tests green.
  That is the whole point: the project's problem was silent
  non-verification, so a tool that quietly reported success would
  recreate it.
- **Teeth-tested each failure path**: a mis-cased `Title:` rule, a
  re-introduced `automerge:` key, and a `Cargo.toml`/`Cargo.lock` pin
  desync each turn the run red; the clean tree passes reproducibly
  (3/3 runs).
- **Fixed a hang the teeth test itself exposed**: the `cargo metadata`
  probe sat for minutes against the blocked registry, so the script hung
  rather than reporting a skip — precisely the "verification never
  finishes" failure it exists to prevent. It is now bounded by
  `timeout`/`gtimeout` (`MUTEN_CARGO_PROBE_TIMEOUT`, default 20s); a full
  run takes ~24s.
- `docs/ci/ci.yml` gained a `verify` job that simply calls
  `./scripts/verify.sh --offline`, so local and CI verification cannot
  drift apart — and that job is the one gate available *before* the
  workflow is installed.

### Removed — deleted 9 provably-dead blocklist rules (317→309 titles, 2→1 composites)
- Applied "question every requirement, then delete" to the shipped
  blocklist. First it questioned the tool: the linter's shadow check
  compared rules **by length**, but `match_title` returns the first match
  in **file order**, so a longer rule is only unreachable when a shorter
  one it contains appears *earlier*. Fixing that turned 9 reported
  shadows into **8 real ones plus 1 false alarm**
  (`your ip address blocked` at line 410 is reachable, because
  `ip address blocked` sits at line 411 — later). The linter now tracks
  file order and has an order-sensitivity negative test.
- Deleted the 8 genuinely unreachable `title:` rules and the dead
  `composite: unsolicited_blocklist_hit` (its `unsolicited` condition can
  never hold while helpers report `origin: unknown`).
- **Proved behaviour-preserving rather than assuming it**: each deleted
  phrase is still matched by the surviving shorter rule that was already
  winning (`critical threat detected` → `threat detected`,
  `重大なセキュリティ警告` → `セキュリティ警告`, …), so the same
  `blocklist_title` (+40) still fires with the same `matched_rule` text
  as before. The pruned file lints completely clean (0 warnings, 0 INFO).
- **Root cause, now documented in `SPECIFICATION.md` §5**: `title:` is
  substring + first-match-wins, so **any rule containing an existing
  shorter rule is dead on arrival** — specificity is simply unachievable
  through `title:`, which is why these accumulated silently. Authors
  wanting position or whole-string specificity must use `glob:` (§5.1).

### Audited (UTS #39) — normalization core is sound; found zero benign coverage for the script signals
- Audited muten's core claim — evasion-resistant Unicode normalization —
  against **UTS #39 (Unicode Security Mechanisms)**, starting from a
  specific high-severity hypothesis: naive mixed-script detection
  false-positives on Japanese, which is *inherently* multi-script
  (Hiragana + Katakana + Han). At +30 on the primary market that would be
  serious.
- **The implementation holds up.** `has_confusable_mixed_script` requires
  `latin && confusable` **within a single token** and treats
  `Script::Other` (Kana, Han, Hangul, digits, punctuation) as an explicit
  no-op, so `Windows セキュリティ警告` cannot fire it. muten deliberately
  models only *confusable-bearing* scripts rather than implementing full
  UTS #39 script resolution, and thereby sidesteps the trap. The spec
  documents `whole_script_confusable` accurately, citing UTS #39 §5.
- **But the negative test coverage is absent.** `confusable_mixed_script`
  (+30) and `whole_script_confusable` (+30) exist precisely to judge
  Cyrillic/Greek/Coptic/Armenian text, yet `BENIGN_TITLES` contains **0
  titles in any of those scripts** (verified by code-point range across
  all 68 entries — an earlier `grep` that suggested otherwise was an
  artefact of the pattern matching the em-dash `—`, corrected here).
  Neither signal has a false-positive regression guard in the scripts it
  targets.
- Concretely reachable: `has_whole_script_confusable` fires when *every*
  letter of a token folds to an ASCII look-alike. That spares ordinary
  Russian (`привет` has non-folding letters) but not a short legitimate
  all-homoglyph word — `сор` (с→c, о→o, р→p) scores +30, and with
  `fullscreen` reaches 60 → Suspicious, unnoticed by the suite.
- Recorded as a second, sharper instance of DR-21 and added as step 4 of
  **WO-12**: add Cyrillic/Greek/Armenian negatives, and decide
  deliberately whether the short-all-homoglyph case is acceptable,
  pinning the decision with a test either way.

### Researched — scoped the lock-shape false positive per platform (related-software survey)
- Followed up the screen-locker finding by asking the question that
  actually determines its severity: **can the helper even enumerate these
  windows?** The answer differs sharply by platform, which narrows the
  problem considerably.
- **X11 is the only platform where the risk is clearly live** — the
  helper enumerates via `wmctrl -lG` and dismisses via `wmctrl -c`.
  Catalogued the real software in this category (`xscreensaver`,
  `i3lock`/`i3lock-color`, `slock`, `xsecurelock`, `light-locker`,
  `gtklock`, `swaylock`, `hyprlock`, `waylock`, `alock`, `kscreenlocker`,
  `xss-lock`) for whatever allowlist the guard ends up needing.
- **A hypothesis that would shrink the risk sharply, recorded as
  unverified**: minimal lockers conventionally map *override-redirect*
  windows; `wmctrl` is EWMH/NetWM-based and so lists `_NET_CLIENT_LIST`,
  which by definition holds only *managed* windows. If that holds, these
  lockers are invisible to the helper and the FP is unreachable. I could
  not confirm the override-redirect detail from a primary source, so it
  is written up as a hypothesis with the one-line test that settles it
  (`wmctrl -l` while a locker is active on a real X session) — not as a
  fact.
- **Windows/macOS/Wayland look not at risk** for the *true* lock screen:
  Windows' `LogonUI.exe` lives on the Winlogon secure desktop and
  `EnumWindows` only covers the calling thread's desktop; macOS's lock is
  a `loginwindow`-level surface; Wayland lockers use `ext-session-lock-v1`
  rather than foreign-toplevel. **Kiosk/exam software is the exception** —
  Windows **Shell Launcher**, **Safe Exam Browser** ("Disable Explorer
  Shell" mode, though not its "Create New Desktop" mode), **Respondus
  LockDown Browser**, and **Fully Kiosk Browser** are in-session and do
  present the lock shape, so they stay a live FP concern.

### Found — a rule in the shipped blocklist can never fire; DR-20's dead-signal count corrected
- Tracing every consumer of `origin` in `classify()` showed DR-20
  understated the damage. Beyond `unsolicited` (+25) and `very_new`
  (+10), **`sudden_fullscreen_takeover` (+5) also requires
  `Origin::Unsolicited`**, so it is transitively dead — 40 points, not 35.
- More consequentially, the blocklist grammar exposes `unsolicited` and
  `user_initiated` as **`composite:` conditions**, so operator rules
  using them are inert too. This is not hypothetical: the shipped
  `examples/overlay-blocklist.txt` carries
  `composite: unsolicited_blocklist_hit 10 unsolicited has_blocklist_title`
  — **a rule that cannot fire on any real host** — and its header
  advertises the same pattern in a commented example. The gap has been
  shipping as advertised-but-inert operator capability, not merely as
  unused internal weight.
- `lint-blocklist.sh` now warns on any `composite:` rule whose conditions
  depend on `origin`. Verified it flags the shipped dead rule (line 821)
  and stays silent on a composite using only geometry conditions. The
  check is explicitly marked to be **removed once a helper reports a real
  `origin`** (WO-11), so it cannot rot into a false alarm.

### Documented (safety) — enabling `origin: Unsolicited` would make muten dismiss screen lockers
- While designing the remaining half of DR-20 (`origin`), found a second
  trap — this one **confirmed from the code**, not inferred. `classify()`
  caps the `input_trap` bonus at +5, and the comment above it says why:
  the bare lock shape *"without any content or provenance tell (origin
  unknown, no scam title/number) tops out at 95 — still `Suspicious`,
  never an automatic `Block`"*, deliberately protecting "legitimately
  locked-down full-screen apps (kiosk shells, exam lockdown browsers)".
- The arithmetic checks out exactly — fullscreen 30 + no_close 25 +
  blocks_input 20 + topmost 15 + input_trap 5 = **95** — which means
  **that false-positive guarantee is load-bearing on `origin` staying
  `Unknown`**. Supplying `Unsolicited` (+25) turns the same window into
  **120 → Block → dismissed**; `sudden_fullscreen_takeover` (+5, which
  itself requires `Unsolicited`) can take it to 125.
- The windows this hits are exactly those that legitimately appear while
  nobody is at the machine: screen lockers (xscreensaver, i3lock,
  gnome-screensaver), screensavers, corporate lock-screen policy,
  kiosk/signage shells, exam lockdown browsers. For a screen locker this
  is worse than a false positive — muten would close the lock screen on
  an unattended machine, actively degrading security.
- Recorded in DR-20 and WO-11: `origin` cannot ship as a plain helper
  field. Any implementation must first answer "what stops the lock shape
  reaching Block?" (never-dismiss process allowlist — `process` already
  exists on `EnumeratedWindow`; re-bounding the geometry stack; or
  requiring a content tell), and must pin the guard with a
  `benign_corpus`-style regression test rather than a comment.
- Also noted, honestly flagged as **unvalidated**: OS idle time is an
  appealing evidence source because — unlike `_NET_WM_USER_TIME` — it is
  maintained by the display server / OS rather than by the window, so it
  is not self-forgeable. An attempt to research per-platform idle APIs
  (X11 XScreenSaver, Wayland `ext-idle-notify-v1`, macOS `HIDIdleTime`,
  Windows `GetLastInputInfo`) and adversarially review the design
  produced **no results** — every agent hit a usage limit — so nothing
  from it is recorded as fact. The sketch also does not solve the
  locker problem: a locker appears *because* the user went idle.

### Found (regression) — DR-23: an auto-merged Dependabot bump broke the MSRV 1.75 guarantee
- The repository owner enabled Dependabot and several cargo bumps were
  merged (PRs #6–#10). **CI is still not installed** (`.github/` holds
  only `dependabot.yml`), so nothing verified them — and one broke a
  documented invariant. This is exactly the failure mode DR-16 predicted.
- `Cargo.toml` declares `rust-version = "1.75.0"`. Measured MSRVs of the
  new pins (crates.io API `rust_version`): **`clap` =4.6.6 → 1.85** (was
  4.5.20); `serde_json` =1.0.151 → 1.71; `thiserror` =2.0.20 → 1.71;
  `tempfile` =3.27.0 → 1.63; `serde` =1.0.229 → 1.56.
- Only `clap` breaks it, and maximally: `default = ["cli"]` with
  `cli = ["dep:clap"]`, so **a plain `cargo build` now needs Rust 1.85**
  while the crate advertises 1.75 — a hard build failure for anyone on
  the promised toolchain. The pins are exact and `Cargo.lock` is in sync,
  so the resolver cannot route around it. `docs/ci/ci.yml`'s `msrv` job
  would have caught this on the PR, but it is still not installed.
- **Decision taken (user expressed no preference): preserve the
  guarantee.** The recurrence guard is in place now — a Dependabot
  `ignore` for `clap >=4.6.0` was added to `.github/dependabot.yml`. The
  actual downgrade is deferred to a cargo session, because pinning `clap`
  back to `=4.5.20` also regenerates `Cargo.lock` (clap's transitive
  tree changes) and this sandbox's `cargo` is egress-blocked: run
  `cargo update -p clap --precise 4.5.20` (not a hand-edited lock) and
  confirm `cargo build`/`test` on Rust 1.75. Both options remain recorded
  in DR-23; the alternative (raise `rust-version` to 1.85) is a one-line
  policy flip if the owner prefers it.

### Fixed — DR-24: removed the invalid `automerge:` key from `dependabot.yml`
- `.github/dependabot.yml` gained an `automerge:` block (`afd85ee`), but
  Dependabot config `version: 2` has no such key — it was a legacy
  dependabot.com v1 option, and native Dependabot uses GitHub auto-merge
  or a workflow instead (GitHub's Dependabot options reference;
  `dependabot/feedback#954`). The block therefore did nothing, and
  unrecognized keys can be reported as a Dependabot **configuration
  error** that halts that ecosystem's updates.
- Removed the block (replaced with a comment explaining why it must not
  return); the file still parses as valid YAML v2. Real unattended
  merging, if wanted, should be a CI-gated workflow — and only after CI
  exists, since auto-merging bumps without CI is how DR-23 happened.

### Added — `installer/overlay-helper/lint-blocklist.sh`: catch silently-dropped blocklist rules (DR-22)
- `Ruleset::from_lines` documents itself as "skipped silently; a malformed
  entry never aborts the load". Not aborting is right — one bad line must
  not disarm a fleet — but the silence is not: the blocklist is
  operator-editable, hot-reloaded, and (per DR-20) the reliable detection
  path on real hosts, so a rule that fails to load is a detection hole
  nobody is told about. `muten-overlay rules` reports only *counts*, so a
  lost rule shows up as a number that failed to increment.
- The new linter names the offending line and exits non-zero. Each check
  mirrors a specific parser behaviour, confirmed by reading `rules.rs`:
  - **ERROR** mis-cased/mis-spaced prefix — the parser is a
    case-sensitive `strip_prefix("title:")` chain ending in
    `else { /* bare → host */ }` (rules.rs:463), so `Title:` / `title :`
    silently become *host* rules and are then discarded.
  - **ERROR** empty pattern (rules.rs:399) and **ERROR** `phone:` under
    the 7-digit floor (rules.rs:419).
  - **WARN** a literal `#` in a pattern — impossible, since comment
    stripping cuts at the first `#` with no escape.
  - **WARN** non-integer `weight:` value; **INFO** duplicate and
    substring-shadowed `title:` rules (approximate normalization, so
    labelled as hints).
- **Teeth-testing corrected the design.** The first `#` check flagged only
  content-attached `#` (`case#4821`) — and so *missed the very case that
  motivated it*: `title: your case #4821 is under review`, whose `#` is
  space-preceded and therefore indistinguishable from a trailing comment
  by spacing alone. Replaced with a signal that does discriminate: `#`
  immediately followed by a digit (comments start with a word, case and
  ticket numbers with a digit). Verified it now warns on both `#4821`
  forms while staying silent on all 52 genuine inline comments in the
  shipped blocklist, including the Japanese ones.
- The shipped `examples/overlay-blocklist.txt` lints clean (0 errors, 0
  warnings), so this is prevention plus a regression baseline, not a
  live-bug fix. The linter's comment handling is also *more* accurate
  than an earlier ad-hoc scan in this session: that scan reported 10
  substring-shadowed rules, but one was an artefact of not stripping an
  inline English comment — the real count is 9.
- Documented the hazards normatively in `SPECIFICATION.md` §5 (prefixes
  are case-sensitive; `#` is reserved with no escape, so express TOAD
  case-number lures as `glob:` wildcards; empty/short patterns are
  dropped) and in the blocklist header, with the installer README
  pointing at the linter. Filed **DR-22** + **WO-13** for the Rust half —
  collect per-line skip diagnostics and surface them via `cmd_rules` and
  on daemon reload — not written here, as cargo is egress-blocked.

### Measured — DR-21: the Japanese detection surface is 50× larger than the benign corpus guarding it
- Applied the detection literature's evaluation standard (a false-positive
  rate against a realistic corpus is a first-class result) to muten's own
  test suite, and measured rather than assumed:

  | | detection surface | benign corpus | ratio |
  |---|---|---|---|
  | **Japanese** | **502** distinct JP literals in `src/confusables.rs` + `src/lib.rs` (exact) | **10** JP titles | **50 : 1** |
  | Non-Japanese | ~1,745 EN multi-word literals *(loose heuristic)* | 58 titles | ~30 : 1 |

  `BENIGN_TITLES` is **68** hand-authored entries across 7 categories.
- muten is a Japan-market product and its Japanese vocabulary is its
  largest single body of detection logic — yet it is the least guarded,
  ~1.7× thinner than the already-thin English side. An over-broad JP term
  (a bare `警告` / `重要` / `確認` inside an AND-pair) would fire on
  legitimate Japanese software and nothing in the suite would catch it.
- Two methodological gaps against the literature's standard: the corpus
  is **imagined, not sampled** (hand-written, so it can only contain FPs
  someone thought of), and **no FP rate is ever produced** — the test is
  a binary "no content signal fires", so the repo's FP-aversion claim has
  no number behind it.
- Filed as **DR-21** + **WO-12** with a concrete plan (grow the JP corpus
  toward parity, prioritising adversarial-benign near-misses like a real
  AV's `ウイルス定義を更新しました` or a bank's genuine `重要なお知らせ`;
  fix each failure by tightening the rule, never by deleting the title;
  report `N/total` instead of a boolean). **Deliberately not done blind**:
  adding benign titles is *expected* to turn tests red, and each red is a
  genuine over-broad-rule bug — doing it without `cargo` would push tests
  whose outcome nobody can observe.

### Documented (security) — `_NET_WM_USER_TIME` looks like the answer to `origin` and is a bypass
- Researching how to close DR-20's remaining half (`origin`) surfaced the
  EWMH property **`_NET_WM_USER_TIME`**: clients set it to the timestamp
  of the user interaction that caused a window to appear (`0` meaning
  "do not focus me on map" — the mechanism behind GTK's
  `gtk_window_set_focus_on_map` and focus-stealing prevention in Sawfish,
  dwm and KDE). It maps almost word-for-word onto muten's `Origin`, so
  the tempting implementation is
  `_NET_WM_USER_TIME != 0 → Origin::UserInitiated`.
- **That implementation would be a complete bypass of the protective
  action.** In X11 the property is written by the client onto its own
  window, so a scam overlay controls it, and `UserInitiated` carries
  `W_USER_INITIATED_RELIEF = −40`. A representative overlay scoring
  fullscreen 30 + no_close 25 + blocks_input 20 + title_hit 40 = **115
  (Block → dismissed)** drops to **75 (Suspicious → audited but left on
  screen)** by forging one property. The logs would still look healthy.
- Recorded the general rule — *never let a large negative weight be
  driven by attacker-controlled input* — plus the safe asymmetric design
  (relief only from evidence observed independently of the window;
  `Unsolicited` may use weaker evidence since a false negative costs 25
  rather than the whole block; `Unknown` when in doubt) in **WO-11** and
  `THREAT_INTEL_2026.md`, so the next session closing `origin` hits the
  warning before writing code.
- Sourcing is stated honestly in both places: the `_NET_WM_USER_TIME`
  semantics come from search-result summaries corroborated across
  several independent implementations, because the freedesktop/GNOME
  spec mirrors are egress-blocked from this sandbox. The security
  conclusion does not depend on the normative wording — only on the
  property being client-writable, which is basic X11.

### Added — real `age_ms` in the Linux helper: first half of WO-11 (DR-20)
- Acting on the literature finding below: the helper is re-spawned every
  sweep and therefore had no memory, which was the *only* reason
  `age_ms` was hard-coded `0`. It now persists a first-seen timestamp per
  window id (`$MUTEN_OVERLAY_STATE`, default
  `${XDG_RUNTIME_DIR:-/tmp}/muten-overlay-seen.<uid>`) and reports the
  real elapsed time. The sweep ends with an atomic `mv`, so ids absent
  from the current enumeration are pruned and the file cannot grow
  unbounded.
- **No fabricated signal.** muten treats `age_ms == 0` as "the enumerator
  could not tell" and deliberately does *not* score it as `very_new` —
  there is an explicit guard and a test (`age_zero_is_unknown_not_very_new`)
  saying so. We honour that contract: the sweep where a window is first
  observed still emits `0`, because its true age lies in
  `[0, sweep-interval]` and emitting a sub-second value would fabricate
  `very_new` (+10) for every newly opened *benign* window — with
  `SUSPICIOUS_THRESHOLD = 50`, that could push an ordinary new fullscreen
  window (30 + 15 + 10 = 55) over the line. `very_new` now fires only
  when the daemon sweeps fast enough to genuinely observe a sub-second
  age, which is the truthful behaviour. WO-11 was corrected accordingly —
  the original "revives `very_new` (10)" claim was too optimistic.
- Verified in-sandbox on the real shipped helper with stubbed X11 tools:
  cold start → `0`; +400 ms → `469` (`very_new` fires legitimately);
  +1.6 s → `1751` (no `very_new`); a vanished window is pruned from the
  state file. Teeth: restoring the hard-coded `"age_ms":0` makes both
  sweeps report `0`, proving `very_new` was unreachable before. DR-17's
  control-char stripping and `selftest.sh` both still pass. Also fixed a
  `set -e` interaction found during testing (`awk` exits 2 when the state
  file does not yet exist, which killed the first sweep).
- **Measured the fix rather than assuming it worked — and it is only
  half a win at the shipped default.** `very_new` needs
  `0 < age_ms < 1000`, and a helper can only observe an age of about one
  sweep interval. Measured on the real Linux helper: `--interval-ms 1000`
  (the **default**) → `age_ms` 1142 → **`very_new` still does not fire**;
  500 → 589 → fires; 250 → 336 → fires. The default sweep interval is
  exactly the signal's threshold and helper runtime (~140 ms) pushes it
  over. Recovering the 10 points needs `--interval-ms` meaningfully below
  1000. Documented with the measurements in the installer README (a new
  "Tuning" section) and DR-20, including two mitigations:
  `--alert-interval-ms` (typical 200 ms) engages after any sweep with a
  detection, so a re-spawning overlay in an *active* incident does get
  `very_new`; and `age_ms` is now real audit data instead of a constant
  `0` regardless.
- **Now ported to all four helpers.** macOS and Wayland use the same
  `now_ms` / `first_seen_ms` / atomic-`mv` trio (macOS defaulting its
  state path to `$TMPDIR`, Wayland to `$XDG_RUNTIME_DIR`); the Windows
  helper uses the PowerShell equivalent — a hashtable loaded from the
  state file, `DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()`, and
  `Set-Content` + `Move-Item -Force`, wrapped in try/catch so a state
  failure can never break enumeration.
- The `now_ms` non-numeric guard is what makes this portable: macOS
  `/bin/date` has no `%N` and echoes `%3N` back verbatim, so the guard
  catches it and falls back to `seconds * 1000`. Verified against a
  simulated BSD `date` (`17861632313N` → `1786163231000`).
- Verified the identical lifecycle on the macOS and Wayland helpers with
  stubbed `osascript`/`wlrctl`: cold `0` → `457`/`469` at +400 ms → 
  `1715`/`1716` at +1.6 s. Regression-checked that DR-2b/2c/2d's
  modal/no-close signals still resolve correctly and that `selftest.sh`
  still passes on linux and wayland (macOS's `FAIL` is the correct
  "not a Darwin host" probe rejection — its `enumerate` passes).
  The `.ps1` remains **unexecuted** — no `pwsh` in the sandbox.

### Changed — literature review re-prioritized the roadmap: DR-20 filed, DR-2 promoted to WO-11
- Reviewed the tech-support-scam detection literature and found one paper
  that directly contradicts how this backlog was ordered: **Liu, Pun et
  al., "Understanding, Measuring, and Detecting Modern Technical Support
  Scams" (2023)**, introducing **TASR (Topic-Agnostic Scam Recognizer)**.
  TASR's thesis: classifying TSS by *content/topic* is brittle because
  operators pivot wording constantly, so it detects on **topic-agnostic**
  features instead. (Found via Semantic Scholar / ResearchGate; arXiv and
  publisher PDFs are egress-blocked here, so this rests on the abstract
  and indexed metadata — recorded as such, not as a full-text reading.)
- Measured muten against that thesis rather than assuming: the signal set
  is ~6 structural/topic-agnostic signals worth **125 points**
  (`fullscreen` 30, `no_close` 25, `unsolicited` 25, `blocks_input` 20,
  `topmost` 15, `very_new` 10) against **~60 vocabulary signals**, each
  needing the expected words in English or Japanese. By TASR's argument
  the structural set is the durable half — an overlay must cover the
  screen, resist closing, and arrive uninvited whatever its pretext.
- **The finding (DR-20)**: `grep` over all four shipped helpers returns
  `"origin":"unknown"` and `"age_ms":0` in 6/6 occurrences — both are
  emitted unconditionally. So `unsolicited` (25) and `very_new` (10),
  **35 points = 28% of the entire topic-agnostic budget**, can never fire
  on a real host — and they are exactly the two encoding "appeared
  uninvited, just now". What remains in the field is the brittle
  vocabulary path the literature warns about, plus three geometry
  signals. This also explains a previously-noted oddity: the docs already
  concede the blocklist is the reliable path on real hosts and the
  heuristics are weak. DR-20 is *why*.
- **Acted on it**: the DR-2 remainder was sitting in the backlog as a
  large awkward task; it is now **WO-11**, the top detection item, ahead
  of adding a 61st vocabulary signal. WO-11 splits it so the cheap half
  ships first — `age_ms` needs only a per-helper first-seen state file
  (helpers are re-spawned each sweep, which is the sole reason it is `0`)
  and is **shell-only, verifiable without cargo**, exactly like the
  DR-2b/2c/2d fixes; `origin` stays a separate design-first session, with
  an explicit warning that a wrong `user_initiated` (−40) is itself a
  detection hole.

### Fixed — `selftest.sh` now distinguishes all four dismiss outcomes; dismiss exit codes made normative (DR-19 filed)
- First-principles pass over the *act* (dismiss) step — the least-examined
  link in the observe → decide → act → record chain — found the same
  error class at two layers: **the protocol computes three distinct
  dismiss outcomes and both consumers collapse them into one bit, putting
  opposite-meaning states on the same side.**
  - The contract (every helper header, and `SubprocessController::dismiss`)
    is `exit 0` acted / `exit 2` already-gone / anything else failed,
    correctly projected to `Ok(true)` / `Ok(false)` / `Err`.
  - **`selftest.sh` (fixed now):** treated *every* non-zero code as an
    equal PASS, so a helper returning `1` for an unknown window passed
    pre-flight — yet in production that turns every benign self-closed
    window into a `ControllerError::Dismiss`. It now classifies all four
    cases separately: `0` → WARN (may report false dismissals), `2` →
    PASS ("protocol-correct already-gone"), timeout → FAIL, any other
    non-zero → WARN explaining that exit 2 is reserved for already-gone.
    Verified with a four-way fake-helper matrix (0 / 2 / 1 / hang) and
    regression-checked against the three shipped helpers, which do return
    `exit 2` and now get the precise PASS message.
  - **`Monitor::sweep` (filed as DR-19 + WO-10, not fixed here):**
    `controller.dismiss(&ew.id).unwrap_or(false)` audits `Err` (protection
    broken, scam still on screen) identically to `Ok(false)` (overlay
    closed itself, nothing wrong). A fleet-wide broken dismissal path is
    therefore invisible — it looks like a fleet where scams politely close
    themselves. Spec: keep `"dismissed"` as-is and add an additive
    `"dismiss_error"` field on failure only (SIEM-compatible), plus a
    once-per-streak warning. Rust, so not written in this cargo-less
    session.
- `docs/SPECIFICATION.md` §9 gained a normative paragraph on the dismiss
  exit codes stating that `2` and the failure codes MUST NOT be
  conflated, binding custom/third-party helpers.

### Added — control-char stripping is now a normative helper requirement (spec §9); DR-18 filed
- First-principles follow-up to DR-17: the underlying architectural
  weakness is that `SubprocessController::enumerate` parses the helper's
  whole output with a single
  `serde_json::from_str::<Vec<EnumeratedWindow>>`, so **window B's
  classification depends on window A's JSON being well-formed** even
  though they are independent observations. One malformed element ⇒ zero
  windows classified that sweep — the worst possible failure mode for a
  detector, and attacker-reachable since a hostile overlay picks its own
  title.
- DR-17 removed the one trigger we know of in *our* helpers; two further
  steps close the rest:
  - **Done now (docs, verifiable):** `docs/SPECIFICATION.md` §9 gained a
    normative **MUST** — a helper MUST NOT emit raw control characters
    (U+0000–U+001F) in JSON strings, MUST fold tab/CR/LF to spaces, and
    MUST *delete* other control chars (deleting also collapses
    `vi<ESC>rus` → `virus`, so the evasion doesn't survive into the title
    either). This binds custom/third-party helpers, which the protocol
    explicitly invites operators to write.
  - **Caught while writing that spec text**: the sentence "all four
    shipped helpers do this" was about to be false — DR-17's first pass
    had fixed only the three POSIX helpers, and
    `muten-overlay-helper-windows.ps1`'s `Json-Escape` had the identical
    bug (tab/CR/LF only). Fixed it too
    (`-replace '[\x00-\x1F\x7F]', ''`, matching POSIX `[:cntrl:]`, which
    also covers DEL). Regex semantics verified against the shell result
    via an equivalent implementation (same `virus alert` output,
    Japanese `ウイルス警告` intact); the `.ps1` itself is **not
    executed** — no `pwsh` in this sandbox, the standing caveat on all
    Windows-helper work.
  - **Filed for a cargo-capable session:** **DR-18** in
    `FEATURE_AUDIT_2026H2.md` + **WO-9** in `WORK_ORDERS.md` — add fault
    isolation to `enumerate` (sanitize-and-retry, then per-element
    `filter_map` salvage, rate-limited "dropped N elements" warning,
    with unit + `cli_contract` e2e tests and a teeth check). Not written
    here: it is Rust, and this sandbox cannot compile it.
- Also verified DR-17's fix is UTF-8-safe, which matters for a
  Japan-market product: `tr -d '[:cntrl:]'` is byte-wise and
  `[:cntrl:]` never matches UTF-8 continuation bytes, so
  `ウイルスに感染<ESC>しています` survives intact as
  `ウイルスに感染しています` — confirmed through the real shipped linux
  helper, in an unset locale.

### Fixed (security) — control char in a title blinded the whole sweep (DR-17)
- All three shell helpers' `json_escape` escaped backslash/quote and
  folded tab/CR/LF to space, but passed **other ASCII control chars
  (0x00–0x1F: ESC, form-feed, bell, NUL, …) through raw**. JSON (RFC
  8259) forbids raw control chars in strings, so a scam overlay that puts
  one in its title makes `enumerate` emit invalid JSON — and because the
  daemon parses the whole enumerate array at once with strict
  `serde_json`, that single title makes the ENTIRE sweep fail to parse.
  Every window that sweep, the scam included, goes unclassified: a
  trivial, deliberate evasion vector.
- Fix: each `json_escape` now appends `| tr -d '[:cntrl:]'` after the
  existing tab/CR/LF→space fold, deleting any stray control char.
  Deleting (rather than spacing) also defeats the evasion itself —
  `vi<ESC>rus` collapses to `virus`, still a blocklist match — and mirrors
  muten's own normalizer, which strips control chars too.
- Verified end-to-end on the real shipped linux helper with a stubbed
  `wmctrl` emitting a control-char title (output now parses; the scam
  keyword survives so the window stays classifiable), regression-clean on
  all three helpers with benign fakes, portable under `dash`, and given
  teeth by reverting one helper's `json_escape` and confirming the
  control-char title produces invalid JSON again. Pure shell change, fully
  verified in-sandbox (no `cargo` needed).

### Added — `docs/WORK_ORDERS.md`: executable instructions for Opus/Sonnet sessions
- Bridges the two existing meta-docs: `FEATURE_AUDIT_2026H2.md` records
  *what* is healthy/broken and `MODEL_PLAYBOOK.md` records *which model*
  fits which work — but neither tells a cold-started session *how to
  execute* the backlog. The new doc turns every remaining item into a
  self-contained work order (WO-1..WO-8 + backlog): purpose,
  prerequisites (a session pre-flight decides which orders are even
  executable — working cargo? owner-installed CI? real Wayland host?),
  step-by-step procedure, verification protocol, done-criteria, and the
  recommended model per the playbook.
- Codifies the invariants every order inherits (no new deps,
  forbid(unsafe_code), MSRV 1.75, FP-aversion with FP-guard twins, teeth
  discipline, real-artifact verification, "never write Rust you cannot
  compile", docs-match-reality) and the prohibitions learned empirically
  this cycle (never push `.github/workflows/` — App token rejected on
  both channels; no PR/tag/release without explicit user GO; no
  cross-wired new signals in a cargo-less session; never invent data).
- Records the user-decision history that matters for future sessions:
  WO-7 explicitly notes the EC-2/EC-3 edits were attempted and
  **rejected by the user** this cycle — future sessions must re-confirm
  before touching them.
- Self-consistency verified: every file path (13), symbol (6), and the
  one line-number reference the document makes were checked against the
  repo with `ls`/`grep` before commit — the instructions document
  contains no nonexistent references, consistent with this cycle's
  claims-must-match-reality theme.
- Follow-up: added an explicit **§1 "Current state — strengths,
  weaknesses, and which WO fixes what"** section (the "洗い出す" half of
  the request as a standalone reference) — a strengths list of assets a
  change must not degrade, and a weakness→work-order mapping table so a
  cold session can see why the WO priority order is what it is. All WO
  numbers and audit-doc `DR-*` refs in the table were grep-verified to
  resolve; sections renumbered 0–4 with no duplicates.

### Hardened — `selftest.sh` now bounds every helper call with a timeout
- A hung helper is itself a deployment hazard (the daemon survives one
  only via a tight `--helper-timeout-ms`), and the un-guarded self-test
  would have hung forever on one — the opposite of a pre-flight's job.
- Every `--probe`/`enumerate`/`dismiss` invocation now runs under
  `timeout` (Linux) or `gtimeout` (macOS/coreutils) when available
  (default 10s, `MUTEN_SELFTEST_TIMEOUT` to override), falling back to a
  bare call when neither is present — the "no hard dependency" promise is
  kept. A timeout kill (exit 124) is reported as a FAIL with a message
  pointing at `--helper-timeout-ms`.
- Verified in-sandbox: a helper that `sleep 3600`s on probe or on
  enumerate is now caught as FAIL within the timeout (2s in the test, not
  3600s), and all five original failure-mode fakes plus the three real
  helpers still classify exactly as before the change.

### Added — `installer/overlay-helper/selftest.sh` helper pre-flight validator
- Closed a real operational gap: the installer README's "Verifying a
  deployment" section only covered validating the *audit log* after the
  fact (`muten-overlay verify`), with no scripted way for an operator to
  confirm a *helper* actually satisfies the protocol on a specific
  endpoint's window manager / compositor *before* trusting the daemon
  with it. On a fleet with mixed X11/Wayland/desktop-environment hosts
  (where e.g. GNOME/KDE don't offer the wlr foreign-toplevel protocol the
  Wayland helper needs), a helper that silently enumerates nothing is a
  real deployment hazard.
- `selftest.sh <helper>` exercises all three protocol verbs and checks:
  `--probe` exits 0; `enumerate` prints a JSON array of
  `{id, window[, process]}` (a quiet desktop's `[]` is a PASS, not a
  failure); each element has a string `id` and object `window` (deep
  check, opportunistic — uses `python3` only if present); and `dismiss`
  of a non-existent id does not falsely report success (which would make
  the daemon believe it dismissed windows it never touched). Exit 0 =
  safe to deploy; exit 1 = fix first.
- Pure POSIX `sh`, no hard dependency (so it runs in the same MDM push
  step that stages the helper). Verified end-to-end in this sandbox
  against all three real shipped helpers with stubbed OS tools, and given
  teeth against five deliberately-broken helpers (probe-fails,
  non-JSON-enumerate, missing-`window`-field, blind-dismiss→WARN,
  empty-array→PASS) — each failure mode is caught with the right exit
  code. Wired into the installer README as a "Pre-flight" section.

### Investigated — Wayland `lswt` parser: confirmed a code-internal bug, deferred the rewrite
- Re-investigated the deferred DR-2 Wayland item. The primary sources
  (sourcehut `lswt.1.scd` manpage source, sr.ht project page) still 403
  on fetch, so the exact `lswt -j` JSON schema is unconfirmed and the
  parser rewrite stays correctly deferred (writing a parser against a
  guessed schema would be false verification — the same discipline that
  kept the shell-script DR-2b/2c/2d fixes honest).
- But reading `muten-overlay-helper-wayland.sh` against the consistent
  secondary reports surfaced a bug provable from the script alone:
  `pick_tool` validates lswt with `lswt -j` (JSON mode) while `enumerate`
  runs plain `lswt` and scrapes a `title:`/`app-id:` block format — the
  two functions disagree on which lswt mode they use. The plain-lswt loop
  also has no final-block flush (its own comment admits this), dropping
  the last toplevel when output lacks a trailing blank line.
- Recorded the concrete fix in `docs/FEATURE_AUDIT_2026H2.md` for the
  next Wayland-capable session: switch `enumerate` to `lswt -j` (the mode
  `pick_tool` already validates) parsed via `jq`, validate the query
  against a real `lswt -j` dump, then add a `wayland_helper_reference.rs`
  e2e test against a stub emitting that *captured real* format — not a
  guessed one. No code changed this round (no real lswt binary or Wayland
  compositor available in the sandbox to validate against).

### Fixed — installer README described daemon behavior that DR-3 had already changed
- `installer/overlay-helper/README.md` stated in two places (the Ansible
  deployment section and "Updating the blocklist in the field") that the
  `daemon` "does not currently hot-reload a running blocklist — restart
  is required." This stopped being true on 2026-07-04 (commit `549df29`,
  DR-3): `cmd_daemon` checks the `--rules` file's mtime every sweep and
  calls `Monitor::set_rules()` automatically when it changes, with a
  regression test (`daemon_reloads_rules_file_edited_while_running`)
  proving it end-to-end against the real binary. The installer README
  was last touched three days *before* DR-3 landed (commit `d54cce2`,
  2026-07-01) and was never updated afterward.
- Real-world impact: an operator following this doc's advice would
  perform an unnecessary daemon restart on every blocklist push — a
  concrete operational cost caused by a documentation defect, found
  while auditing the repo for the same "claims something that isn't
  true" pattern as the CI fix below.
- Corrected both sections to describe the actual mtime-based hot-reload
  behavior, and added an operational caveat: a copy tool that preserves
  the *source* file's original mtime (some `rsync -t` invocations,
  restoring from a backup) can leave the daemon on the previous ruleset
  even though the file's bytes changed.

### Fixed — `docs/SPECIFICATION_V2.md` was an orphaned, silently-stale spec
- The file existed but was linked from neither `README.md`'s
  documentation index nor `docs/SPECIFICATION.md` itself, and its header
  claimed to cover only "through Round 19" while its own version-history
  table (§10) had been extended through Round 30 without the rest of the
  document being refreshed — internally inconsistent about its own
  currency, and easy to mistake for an up-to-date second spec.
- Rather than deleting it (its §4 exhaustive per-script Unicode-fold
  table and §§5–7 strengths/weaknesses/improvement-areas analysis of the
  Round 19–30 confusable-folding work have no equivalent elsewhere and
  remain useful as an engineering record), added an explicit
  "SUPERSEDED — historical snapshot" banner pointing readers to
  `SPECIFICATION.md` for current behavior, added a matching back-link
  from `SPECIFICATION.md`, and linked it from `README.md`'s
  documentation index labeled **historical only** — resolving the
  orphan/staleness ambiguity without discarding the content.

### Fixed — CI claimed everywhere, existed nowhere (DR-16; workflow shipped, install blocked on owner)
- `README.md`, `deny.toml`, and `.gitleaks.toml` all described an active
  CI pipeline (format/lint/test + MSRV build + cargo-audit/cargo-deny/
  gitleaks "on every PR") — but no `.github/` directory existed anywhere
  in the repository. Same unbacked-claim class as the fictional
  blocklist hosts removed earlier this cycle, but heavier: a quality
  gate described as active that never ran.
- Wrote the real 3-job workflow (test / msrv / supply-chain, matching
  every promise those files made) and attempted to land it at
  `.github/workflows/ci.yml` via **both** available channels. Both were
  rejected by GitHub — git push: "refusing to allow a GitHub App to
  create or update workflow ... without `workflows` permission"
  (matching the constraint a prior session had already recorded in
  `.gitignore`); contents API: `403 Resource not accessible by
  integration`. The rejected local commit was cleanly reset; the remote
  branch never contained it.
- Fallback shipped instead: the workflow lives at **`docs/ci/ci.yml`**
  with install instructions in its header (one manual copy to
  `.github/workflows/ci.yml` by the repository owner, whose user token
  has the `workflow` scope App tokens lack). All three false claims
  were corrected to state the workflow is provided but not yet active;
  `.gitignore`'s note now records the 2026-07 empirical re-confirmation
  and points at the asset.
- Why this matters beyond honesty: once installed, CI runs `cargo test`
  on GitHub-hosted runners (unrestricted egress) on every push — which
  retroactively verifies all of this cycle's cargo-unverified changes
  (DR-12, `scoring_scenarios.rs` additions, both `*_helper_reference.rs`
  files) with results readable from any future session via the Actions
  API. Tracked as DR-16 in `docs/FEATURE_AUDIT_2026H2.md`, marked
  "blocked on repository owner."

### Added — FileFix / TerminalFix ClickFix-variant detection (DR-12, cargo-unverified)
- `has_clickfix_instruction` (`src/confusables.rs`) had no vocabulary for
  2026's two newest high-prevalence ClickFix variants (Recorded Future,
  The Hacker News 2026): **FileFix** (pastes into the Explorer address
  bar — no Mark-of-the-Web, bypasses SmartScreen) and
  **TerminalFix**/DownloadFix (pastes into a terminal/PowerShell).
- Added `win+e` to the existing keyboard-shortcut chain and a new
  `filefix` AND-compound block (a surface noun — address bar / file
  explorer / terminal / powershell — required together with a `paste`
  verb, mirroring the file's existing `run_cmd` precision discipline so
  a surface noun alone in ordinary IT documentation can't fire it), then
  wired it into the function's return expression. Extends the existing
  `clickfix_instruction` signal; no new signal id, no `classify()`
  change.
- Added 2 unit tests to `confusables.rs` (7 positive FileFix/TerminalFix
  phrasings; 4 FP-guard cases confirming each surface noun alone does
  not fire) and 2 end-to-end tests to `tests/scoring_scenarios.rs`
  mirroring the existing ClickFix/GlitchFix e2e tests. Checked for FP
  collision against `tests/benign_corpus.rs`'s adversarial legitimate-
  window corpus: zero hits.
- **Known limitation**: `cargo` remains unavailable in this sandbox
  (egress policy blocks `static.crates.io`). Unlike the shell-script
  DR-2b/2c/2d fixes earlier this cycle, Rust logic cannot be exercised
  without compiling it, so this change is **implementation-complete but
  unverified** — paren/brace/quote balance was checked by hand and by a
  small Python script, but `cargo build`/`test`/`clippy`/`fmt` have not
  run. Tracked in `docs/FEATURE_AUDIT_2026H2.md` DR-12 as the top
  priority for the next session with working `cargo`: build, test, prove
  the new tests have teeth by reverting the `filefix` block, then mark
  DR-12 RESOLVED.

### Added — 2026-H2 threat-intel refresh (research → docs + blocklist)
- Researched the latest public reporting and literature (WebSearch, this
  session): CypherLoc browser-locking scareware (Barracuda 2026-05, ~2.8M
  attacks in 2026), ClickFix's 2026 variant explosion (FileFix /
  TerminalFix / DownloadFix — Recorded Future, The Hacker News), the FBI
  IC3 2025 Annual Report (released 2026-04-07: $20.9B total, +26% YoY;
  AI-fraud now its own category), Microsoft Edge's on-device ML scareware
  sensor, and two new arXiv papers (PP3D 2510.18465, Anatomy of Scam
  Scenarios 2606.16052).
- `docs/THREAT_INTEL_2026.md`: added a **2026-H2 UPDATE** section capturing
  all of the above with sources, and noted that CypherLoc's re-lock loop
  (present→gone→present) is real-world confirmation the DR-11
  presence-vs-appearance fix was correct.
- `docs/FEATURE_AUDIT_2026H2.md`: filed four new OPEN items with
  implementation specs precise enough for a next session to execute
  directly — **DR-12** (ClickFix FileFix/TerminalFix vocabulary gap in
  `has_clickfix_instruction`), **DR-13** (no signal for a literal IP shown
  in an alert, the CypherLoc authenticity trick), **DR-14** (no internal
  "IT helpdesk" impersonation vocabulary), **DR-15** (AI-fraud watch item).
- `examples/overlay-blocklist.txt`: +12 `title:` rules (305→317) for the
  FileFix/TerminalFix address-bar/terminal lures and the CypherLoc
  browser-lock / IT-helpdesk framing. These are additive title
  *contributions* (+40, never an auto-block on their own), so a benign
  window that happens to contain e.g. "contact your IT helpdesk" is
  neutralized by the `user_initiated` (−40) relief when the user opened
  it — consistent with the file's existing FP-averse design. Verified no
  squash-duplicate collisions with existing rules.
- **NOT done this round**: the Rust detector changes (DR-12/13/14) are
  specified but unimplemented — `cargo` remains unavailable in this
  sandbox (egress policy blocks `static.crates.io`), so they are deferred
  to a session that can compile and run the tests. The blocklist/docs
  changes above need no compilation.

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
