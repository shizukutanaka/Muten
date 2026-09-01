# muten-overlay — Work Orders for Opus / Sonnet Sessions

> **How to read this document** (for any Claude instance picking this up
> cold): this is the execution companion to two other documents —
> [`FEATURE_AUDIT_2026H2.md`](FEATURE_AUDIT_2026H2.md) records *what* is
> healthy/broken (STATUS-tagged evidence), and
> [`MODEL_PLAYBOOK.md`](MODEL_PLAYBOOK.md) records *which model* suits
> which kind of work. This file records **how to execute** the remaining
> backlog: each work order (WO) below is a self-contained procedure with
> prerequisites, steps, a verification protocol, and done-criteria.
> Work top-down: the orders are sorted by priority. 日本語補足:
> 本書は「次のセッションが文脈ゼロで安全に作業を再開するための指示書」。
> 迷ったら FEATURE_AUDIT の該当 DR 項目を先に読むこと。

## 0. Before you start — session pre-flight

> **Check the egress proxy before concluding "no registry access".** This
> was got wrong once: cargo work was written off as impossible from
> 403s, but `curl -sS "$HTTPS_PROXY/__agentproxy/status"` shows
> **`index.crates.io` is in `noProxy`** (reachable) while only
> **`static.crates.io`** is policy-denied. So `cargo update`,
> `cargo metadata` and anything needing only registry *metadata* work
> here; only downloading `.crate` tarballs (`cargo build`, `cargo test`)
> is blocked. DR-23 was fixed on that basis. See `/root/.ccr/README.md`
> for the failure classes — and note a 403 is a policy denial to report,
> never to route around.

Run these checks first; they decide which work orders are executable in
your session:

1. `cd crates/muten-overlay && timeout 60 cargo build --lib 2>&1 | tail -5`
   — If this **downloads crates and builds**, you have a cargo-capable
   session: start with **WO-1** (highest priority, unblocks everything).
   If it fails with `static.crates.io ... 403` (the 2026-07 sandbox
   state, confirmed repeatedly), skip WO-1/3/4/6 — Rust work is
   **forbidden** in that state (see Invariants).
2. GitHub MCP `actions_list` on `shizukutanaka/Muten` — if
   `total_count > 0`, the owner has installed CI (DR-16): do **WO-2**.
3. `echo $WAYLAND_DISPLAY` + `command -v lswt` — only if you're on a real
   wlroots compositor with lswt installed can you do **WO-5**.

## 1. Current state — strengths, weaknesses, and which WO fixes what

Measured snapshot as of this document's commit. This table is a summary
of [`FEATURE_AUDIT_2026H2.md`](FEATURE_AUDIT_2026H2.md); if the two ever
disagree, the audit doc is authoritative. 日本語補足: 上段=壊しては
ならない資産、下段=弱点と、それを直す作業指示(WO)の対応表。

**Strengths — assets your change must not degrade:**

- <!--claim:signals-->89-signal / 10-lens detection engine with the evasion-resistant
  Unicode-confusable normalization pipeline (`src/confusables.rs`) —
  the product's core value.
- Tamper-evident SHA-256 audit chain with RFC 6962 Merkle anchoring
  (`src/sink.rs`) — the operator-trust story.
- False-positive-averse design that actually holds: `user_initiated`
  relief, `alert_shaped` gating on content signals, and the adversarial
  `tests/benign_corpus.rs` corpus. FP-aversion is a stated product
  principle (`README.md`), not just a habit.
- Shell layer fully verified in-sandbox on the shipped files: all three
  POSIX helpers, `installer/overlay-helper/selftest.sh` (with teeth),
  and the three MDM service templates (XML/plist/unit validated).
- Threat intel current through 2026-H2 (CypherLoc, ClickFix variant
  wave, IC3 2025) with sourced docs and blocklist coverage.
- Documentation with zero known unbacked claims — multiple false claims
  were found and purged this cycle; keep it that way.

**Weaknesses → the work order that fixes each:**

| Weakness (audit ref) | Impact | Fix |
|---|---|---|
| ~~Cargo-unverified Rust on the default branch~~ | ✅ largely resolved — 696 tests green via standalone `rustc`; only a real end-to-end `cargo test` remains | **WO-1** |
| CI claimed-then-shipped but not installed (DR-16) | no automated verification channel | **WO-2** (owner step) |
| No signal for a bare IP literal shown in an alert (DR-13, CypherLoc trick) | detection gap on a live 2.8M-victim kit | **WO-3** |
| IT-helpdesk impersonation only covered by verbatim blocklist rules (DR-14) | generalization gap (low — exact phrasings blocked) | **WO-4** |
| Wayland lswt parser: probe/enumerate mode mismatch (~~last-block drop~~ ✅ fixed 2026-08) | plain-lswt scrape may not match real output — `-j` migration needs a real host | **WO-5** |
| No fault isolation in `enumerate` parsing (DR-18): one malformed element blinds the entire sweep | worst-case failure mode; helper bugs / custom helpers see *nothing* instead of missing one window | **WO-9** |
| Failed dismiss audited identically to a self-closed window (DR-19) | a broken dismissal path across a fleet is invisible — looks like scams closing themselves | **WO-10** |
| ~~502 JP literals vs 10 JP benign titles~~ ✅ **9:1**, FP rate 0.0% measured (DR-21); **but 7 URL-driven signals (20–40 pts) still have ZERO benign URL coverage (DR-25)** | the URL surface's FP-safety rests on code comments, with nothing executable checking it | **WO-12** step 6 |
| Blocklist loader drops mis-authored rules with no diagnostic (DR-22) | a hot-reloaded, operator-edited rule that fails to load is an unannounced detection hole | **WO-13** (shell linter shipped) |
| Audit log grows unbounded; no rotation (DR-4) | multi-week deployments | **WO-6** |
| **DR-20 remainder**: `origin` still hard-coded `unknown` (~~`age_ms`~~ ✅ real on all 4 helpers since 2026-08), so `unsolicited` (25) never fires | deliberately unimplemented until the lock-shape guard lands — naive `origin` would *dismiss screen lockers* | **WO-11** (guard designed) |
| Detection vocabulary EN+JP only (DR-8) | non-EN/JP fleets under-detect | Backlog |

## 1.5 Definition of Done — what actually blocks v0.6.0

The backlog has ~20 open items and 13 work orders, which makes "finish
the product" look unbounded. It isn't. Applying *question every
requirement* — the product's one job is **detect and dismiss scam
overlays on managed fleets without false-positiving** — most of the
backlog turns out not to gate completion. Work the four blockers; do the
rest because you want the feature, not because the product is unfinished
without it.

**Status as of 2026-08-18**: B1 fixed; B2 covered (**696 tests green**
without a registry, plus the last two assertions checked directly); B3
and B4 re-classified below as *not product blockers*. Registry access was
confirmed exhaustively: no vendored sources, no crate cache, no permitted
mirror — `index.crates.io` is reachable but `static.crates.io` is a
policy 403, and per `/root/.ccr/README.md` that is to be reported, never
routed around.

**RE-CLASSIFIED 2026-08-18.** The original four-item blocking list was
written before B1 was fixed and before B2 was measured, and two of its
entries do not survive this document's own rule — *"if an item does not
make the detector wrong, the build broken, or a false positive likelier,
it is not blocking a release."* Applying that rule honestly:

| # | Item | Detector wrong? | Build broken? | FPs likelier? | Verdict |
|---|---|---|---|---|---|
| B1 | DR-23 MSRV | — | **was YES** | — | ✅ **fixed** — `clap` 4.5.20, MSRV 1.75 holds |
| B2 | cargo-unverified code | no | no | no | ✅ **all 5 touched files compile-verified and behaviour-verified** (696 tests green + assertions checked). Only an end-to-end `cargo test` remains — an environment-gated confirmation, not outstanding work |
| B3 | no CI | no | no | no | **not a product blocker** — a process guarantee for *future* changes |
| B4 | `origin` dead | no — *weaker*, not wrong | no | **no; the opposite** | **not a product blocker** — implementing it naively makes FPs *likelier* (lock shape → Block), so shipping without it is the FP-safe state |

**Every changed line of Rust this cycle is now verified.** Only four
Rust files changed since the green commit `549df29`, and each is covered:

| file | compiles | behaviour |
|---|---|---|
| `src/confusables.rs` | ✅ `rustc` | ✅ **675 tests pass**; DR-12 teeth-proven (disabling `filefix` → FAIL) |
| `tests/linux_helper_reference.rs` | ✅ `rustc` + offline stubs | ✅ **1 test passes** against the real shipped helper; DR-2b teeth-proven |
| `tests/macos_helper_reference.rs` | ✅ `rustc` + offline stubs | ✅ **2 tests pass** (DR-2c, DR-2d) against the real shipped helper |
| `tests/scoring_scenarios.rs` | ✅ `rustc` + compile-only crate stub | ✅ both new assertions checked against the *verified* `normalize_for_match` + `has_clickfix_instruction`, plus a benign control that correctly does not fire |
| `tests/benign_corpus.rs` *(edited here)* | ✅ `rustc` + compile-only crate stub | ✅ all **132** titles probed against the real detectors — **0 false positives, 0.0%** |

The 15 serde-importing modules were **not touched** — byte-identical to
their green state — so nothing unverified ships.

**The residual caveat, stated precisely**: `cargo test` has never run
end-to-end. **696 tests do run** — `confusables.rs` 675, `fingerprint.rs` 12,
`mitre.rs` 6, and the two `*_helper_reference.rs` suites (3) via
`scripts/offline-stubs/` — all teeth-proven. What remains unrun is
`tests/scoring_scenarios.rs` (2 tests), which needs the full
`muten_overlay` crate graph and hence `serde`/`sha2` from the
egress-denied `static.crates.io`. The helper suites additionally run
against *stub* `tempfile`/`serde_json`, so they verify **helper
behaviour**, not serde integration. **Do not advertise "all tests green"
until someone runs a real `cargo test`.**

**Where that leaves v0.6.0**: functionally complete and, within this
environment's limits, verified — the build works on the advertised MSRV,
the only changed source file is test-green with teeth, the four shipped
helpers and the blocklist are lint- and behaviour-clean, and detection
runs on <!--claim:title_rules-->309 title + <!--claim:glob_rules-->44 glob + <!--claim:process_rules-->44 process rules. `origin` (DR-20) and CI
(DR-16) are **documented limitations with decided remediations**, not
defects. Ship with those caveats stated, or clear them first — that is a
product decision, no longer an engineering unknown.

**NOT BLOCKING — deliberately deferred (each is a feature or a research
item, not an unfinished obligation):**

- **Vocabulary growth** — DR-13 (IP-literal signal), DR-14 (IT-helpdesk
  generalisation), DR-8 (languages beyond EN/JP), WO-8 (intel refresh).
  Per TASR this is the *brittle* detection path, and DR-21 shows each
  addition widens an untested FP surface. Adding the 81st vocabulary
  signal is the lowest-value work available. WO-8 is recurring
  maintenance and by definition never "done".
- **Feature expansion** — DR-7 (config file), DR-9 (BITB), DR-10 (signed
  builds / semver-checks / benchmarks), DR-6 (anchoring automation:
  manual works today).
- **Robustness hardening** — DR-18, DR-19, DR-22, DR-4. Real, worth
  doing, but each is a degradation-under-fault issue, not a "the product
  doesn't work" issue.
- **Cosmetic** — EC-1/EC-2/EC-3. Note the user **rejected** the EC-2 and
  EC-3 edits when they were attempted; do not redo them uninvited.
- **DR-21** sits between the two lists: it is not a broken feature, but
  it is the largest *unknown* — 502 Japanese detection terms guarded by
  10 Japanese benign titles. Treat it as required before advertising
  FP-aversion with a number attached.

**Rule of thumb**: if an item does not make the detector wrong, the build
broken, or a false positive likelier, it is not blocking a release.

## 2. Invariants — every work order inherits these

- **No new crate dependencies. `#![forbid(unsafe_code)]`. MSRV 1.75.0.
  Offline, pure detection path.** (Cargo.toml `rust-version` is the
  authority.)
- **False-positive-averse**: a legitimate window must never be flagged;
  when a detector could go either way, it stays quiet. Every new
  positive-detection test needs a negative FP-guard twin.
- **Teeth discipline**: after adding a regression test, temporarily
  revert the fix, confirm the test goes red, restore it. A test that
  never went red proves nothing.
- **Real-artifact verification**: exercise the shipped artifact (compiled
  binary via `tests/cli_contract.rs` patterns, or the actual shell
  script with stubbed OS tools on `PATH` — see
  `tests/linux_helper_reference.rs` and this repo's `selftest.sh`
  history), not just unit fixtures.
- **Never write Rust you cannot compile.** The 2026-07 sessions
  accumulated cargo-unverified code out of necessity and it is the
  repo's #1 outstanding risk; do not add to it. Shell/docs/blocklist
  work is always verifiable in-sandbox and therefore always allowed.
- **Docs must match reality.** This cycle removed multiple claims that
  described things that didn't exist (fictional blocklist hosts, a CI
  that never ran, a stale "no hot-reload" statement). Before writing
  "X exists/works", run the command that proves it.
- **Git**: commit with a detailed narrative message ending in the
  session's `Co-Authored-By` + `Claude-Session` trailers; push with
  `git push -u origin claude/deepresearch-ultrathink-improvement-yp5Y2`.
  Update `CHANGELOG.md` (top of the `[0.6.0]` section) and
  `FEATURE_AUDIT_2026H2.md` STATUS tags in the same commit as the change
  they describe.

## 3. Work orders (priority order)

### WO-1 — Clear the cargo-verification backlog 【model: Sonnet | needs: working cargo】

**Why first**: `src/confusables.rs` (DR-12 FileFix/TerminalFix),
`tests/scoring_scenarios.rs` (2 e2e tests), `tests/linux_helper_reference.rs`,
and `tests/macos_helper_reference.rs` are implementation-complete but
have **never been compiled**. Everything else queues behind this.

**Pre-flight de-risking (done 2026-08, by inspection — reading, not
compiling).** The three failure modes most likely to stall this work were
checked and all look clean, so expect it to build rather than fight it:
- **`clippy -D warnings` on unused bindings**: every `let` in
  `has_clickfix_instruction` (`compact`, `shortcut`, `run_cmd`,
  `filefix`, `captcha_frame`, `glitchfix`, `jp_clickfix`) is consumed —
  `compact` feeds `shortcut`, the rest appear in the final return
  expression. The DR-12 additions cannot trip an unused-variable denial.
- **Crate-API drift in the new test files**: `linux_helper_reference.rs`
  and `macos_helper_reference.rs` reference **no** `muten_overlay::`
  items, so no crate signature can have drifted under them.
  **Correction to an earlier version of this note**, which claimed they
  use "only std": they also depend on **`tempfile`** and
  **`serde_json`**, referenced by fully-qualified path inside function
  bodies rather than by a top-level `use` — which is exactly why a
  `^use` grep missed them. Confirmed by `rustc --test`, which fails on
  both with `unresolved module or unlinked crate`. They therefore still
  need cargo + the registry; they are not standalone-runnable.
- **Windows build breakage**: both files carry `#![cfg(unix)]` as an
  inner attribute at file scope (after the `//!` docs, before the
  `use`s), so they compile out entirely off Unix. `PermissionsExt` is
  safe.
This reduces the risk; it does not remove it — reading cannot catch
type errors inside complex expressions. Still run the full gauntlet.

1. `cd crates/muten-overlay`
**Already verified without cargo (2026-08-18).** `rustc` alone can
compile *and run* the tests of every module that has no external-crate
dependency, which this environment's blocked registry does not prevent.
Results, now automated as phase [2b/3] of `scripts/verify.sh`:
`confusables.rs` **675 passed / 0 failed** (this is the DR-12 file — the
`clickfix_fires_on_filefix_terminalfix_phrases` test passes, and
disabling the `filefix` block makes it FAIL, so it has teeth),
`fingerprint.rs` **12 passed**, `mitre.rs` **6 passed** — 693 tests
green. The remaining 15 modules import `serde`/`serde_json`/`sha2` and
still need cargo. So the DR-12 half of this work order is **done**; what
remains is the crate-wide build, the `*_helper_reference.rs` suites, and
the `scoring_scenarios.rs` additions.

**Scope of what is actually unverified (measured, not assumed).**
`git diff --name-only` from the last known-green commit (`549df29`) shows
only **four** Rust files changed this whole cycle:

| file | status |
|---|---|
| `src/confusables.rs` | ✅ **verified** — 675 tests pass via standalone `rustc`, DR-12 teeth-proven |
| `tests/linux_helper_reference.rs` | fails **only** on `unresolved crate` (E0433) for `tempfile`/`serde_json` — no syntax or type errors of its own |
| `tests/macos_helper_reference.rs` | same — only E0433 |
| `tests/scoring_scenarios.rs` | E0432/E0433 for `muten_overlay`, plus E0282s that **cascade from** that unresolved import |

**The 15 serde-importing modules were not touched** — they were green at
`549df29` and are byte-identical since. So "the crate has never been
compiled" overstates it: the only changed *source* file is verified, and
the residual risk is three **test** files. Their asserted behaviour is
independently verified at the shell level (the DR-2b/2c/2d modal and
close-button signals, DR-17 control-char handling, and `age_ms` were each
exercised end-to-end against the real shipped helper scripts with stubbed
OS tools). Absence of independent errors is evidence, not proof — a type
error could still surface once the crates resolve — but the exposure is
far smaller than "unverified crate" suggests.

2. `cargo build --all-targets` — fix any compile error minimally (most
   likely locations: the `filefix` block in `has_clickfix_instruction`,
   `src/confusables.rs` ~line 1786; the two new `*_helper_reference.rs`
   test files).
3. `cargo test` → `cargo clippy --all-targets -- -D warnings` →
   `cargo fmt --check` (run `cargo fmt` if needed). All green.
4. Teeth for DR-12: comment out the `let filefix = …` block and its
   `|| filefix` in the return, run
   `cargo test clickfix_fires_on_filefix_terminalfix_phrases` — must go
   **red** — then restore and re-run to green.
5. Update docs in the same commit:
   - `FEATURE_AUDIT_2026H2.md`: DR-12 header → `~~DR-12~~` RESOLVED (move
     into the resolved table if convenient); delete the
     "cargo-unverified" caveats from DR-2b/DR-2c/DR-2d and the Current
     State Summary; record the real test totals from step 3's output.
   - `README.md` Status line: update test counts to the measured totals.
   - `CHANGELOG.md`: one entry describing the verification result.
6. Commit + push.

**Done when**: full suite green in CI or locally, DR-12 RESOLVED, zero
"cargo-unverified" markers left in the audit doc.

### WO-2 — CI to green 【model: Sonnet (Haiku for pure babysitting) | needs: owner-installed workflow】

Precondition: the repository owner must copy `docs/ci/ci.yml` to
`.github/workflows/ci.yml` via the GitHub web UI — automated sessions
**cannot** (git push and contents API both rejected for App tokens;
empirically proven, see DR-16 in the audit doc — do not retry).

Once `actions_list` shows the workflow: watch runs on every push
(`actions_get`, `get_job_logs`), fix reds with normal minimal commits,
re-push until all three jobs (test / msrv / supply-chain) are green.
Expect first-run surprises in the `supply-chain` job (gitleaks-action or
cargo-deny config) — fix the config, not the gate, unless the gate is
factually wrong. A green `test` job supersedes WO-1 steps 2–3 (but the
teeth check in WO-1 step 4 still needs a local cargo or a deliberate
temporary branch — prefer local).

### WO-3 — DR-13: `ip_address_displayed` signal 【model: Sonnet, plan reviewed by Opus/Fable | needs: working cargo】

CypherLoc shows the victim's public IP for fake authenticity; no current
signal fires on a bare dotted-quad in an alert-shaped window
(`ip_alarm` needs alarm vocabulary). Full spec in the audit doc's DR-13.

Wiring checklist — a **new** signal id touches every lens; the crate's
invariant tests will fail if any mapping is missing. Grep for how
`notification_permission_bait` (the most recent fully-wired signal) is
registered and mirror every site, including at minimum:
`all_signals()` registration, weight constant + `weight_of` arm,
plain-language description arm, `categories`, `persuasion` (or the
shared `MECHANIC_EXEMPT` list in `src/lib.rs` tests with rationale),
`targeting`, `mitre`, and any lifecycle/extraction/loss-magnitude maps
that invariant tests enforce. Detector: hand-rolled dotted-quad scan
(no regex dep), each octet 1–3 digits ≤255; gate on `alert_shaped` in
`classify()`; weight ≈15. FP-guards: version strings like
`114.0.5735.90` (octet >255 → no fire), `user_initiated` windows.
**Do not attempt without a working cargo** — this is the exact class of
change that cannot be hand-verified.

### WO-4 — DR-14 generalized IT-helpdesk heuristic 【model: Sonnet | needs: working cargo | priority: low ★】

Mostly covered already — read the refined DR-14 entry in the audit doc
before starting (blocklist rules cover CypherLoc's exact phrasings;
`has_tech_support_chat_lure` has the nouns but is chat-gated). Only
implement if WO-1/2/3 are done and the marginal value still looks
worth it.

### WO-5 — Wayland lswt parser fix 【model: Sonnet | needs: real wlroots compositor + lswt】

Two bugs were confirmed from the script alone (see the DR-2 Wayland
note in the audit doc). **The last-toplevel drop is FIXED** (2026-08:
`{ lswt; printf '\n\n'; }` injection, four termination cases verified,
teeth-proven — see the audit note; "needs a real host" did not actually
apply to that half). **What remains here is only the mode mismatch**:
`pick_tool` validates `lswt -j` but `enumerate` parses plain `lswt`. **Procedure order matters**: first
capture real `lswt -j` output on the target compositor, THEN rewrite
`enumerate`'s lswt branch to `lswt -j` + `jq` (gated on `have jq`),
then build the fake-lswt e2e stub from the *captured* format — never a
guessed one — following `tests/linux_helper_reference.rs`'s harness
shape. Verify with `installer/overlay-helper/selftest.sh` on the real
compositor.

### WO-6 — DR-4: audit-log rotation 【model: Opus (design) → Sonnet (impl) | needs: working cargo】

The verification half already exists: `verify_chain_continued` in
`src/sink.rs` can verify a chain spanning a rotation boundary. Design
the cut mechanism (size- or age-based, daemon-side, atomic rename,
chain-continuity head carry-over), review the design against the audit
chain's tamper-evidence guarantees, then implement with cli_contract
e2e tests (real binary, real files, teeth).

### WO-9 — DR-18: fault isolation in `enumerate` parsing 【model: Sonnet | needs: working cargo】

`SubprocessController::enumerate` (`src/controller.rs`) parses the whole
helper output with one `serde_json::from_str::<Vec<EnumeratedWindow>>`;
any error blinds the entire sweep. Window B's fate should not depend on
window A's JSON. Full spec (sanitize-and-retry, then per-element
`filter_map` salvage, rate-limited "dropped N elements" warning, and the
unit + `cli_contract` e2e tests) is in the audit doc's DR-18 entry —
follow it directly. Do this soon after WO-1: it is small, well-specified,
and converts the worst failure mode (see nothing) into the mildest (miss
one window).

### WO-10 — DR-19: distinguish a failed dismiss from a self-closed window 【model: Sonnet | needs: working cargo】

`Monitor::sweep`'s `controller.dismiss(&ew.id).unwrap_or(false)` audits
`Err` (protection broken, scam still on screen) identically to
`Ok(false)` (overlay closed itself, nothing wrong). Add an additive
`"dismiss_error"` field on failure only, plus a once-per-streak warning.
Full spec and tests in the audit doc's DR-19 entry. Small, schema-safe,
and pairs naturally with WO-9 (both are "stop discarding information the
lower layer already computed").

### WO-11 — DR-20: revive the dead topic-agnostic signals (`age_ms`, then `origin`) 【model: Opus (design) → Sonnet (impl) | needs: per-platform work; `age_ms` half is shell-only】

**Read the DR-20 entry in the audit doc first** — it carries the
literature justification (TASR: topic-agnostic features are the durable
detection path; muten's are 28% dead) for why this outranks adding more
vocabulary signals. This is the highest-value detection work left.

Split it, and do the cheap half first:

1. **`age_ms` — ✅ DONE on all four helpers.**
   Implemented in `muten-overlay-helper-linux.sh` via a first-seen state
   file (`$MUTEN_OVERLAY_STATE`, default
   `${XDG_RUNTIME_DIR:-/tmp}/muten-overlay-seen.<uid>`): `first_seen_ms`
   looks the window id up, records it into a temp file, and the sweep
   ends with an atomic `mv` so ids absent from this sweep are pruned.
   The same three pieces are now in the macOS, Wayland and Windows
   helpers too (PowerShell uses a hashtable +
   `DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()` +
   `Set-Content`/`Move-Item -Force`). `now_ms`'s non-numeric guard covers
   macOS, whose `date` has no `%N` and echoes the format back verbatim —
   verified against a simulated BSD `date`. **Only the `.ps1` is
   unexecuted** (no `pwsh` in the sandbox), the standing caveat on all
   Windows-helper work.
   **Correction to the original estimate below**: this does *not* simply
   "revive `very_new` (10)". We report only the measurable quantity —
   time since the helper first observed the window — so the first
   sighting emits `0` (= "unknown", muten's existing semantic), because
   the true age is somewhere in `[0, sweep-interval]` and inventing a
   sub-second value would fabricate `very_new` (+10) on every newly
   opened *benign* window. `very_new` therefore fires only when the
   daemon sweeps fast enough to genuinely observe a sub-second age.
   Fully recovering those 10 points for slow sweeps needs real OS
   window-creation timestamps, which is separate per-platform work.

   *(original guidance, still applicable to the remaining helpers)*
   Helpers are re-spawned every sweep, so they have no memory; that is
   the only reason `age_ms` is `0`. Give each helper a small state file
   (e.g. `${XDG_RUNTIME_DIR:-/tmp}/muten-overlay-seen.<uid>`) mapping
   window id → first-seen epoch-ms, written on first sighting and read
   on later sweeps; `age_ms = now - first_seen`. Prune ids absent from
   the current enumeration so the file cannot grow without bound. This
   revives `very_new` (10) and makes `sudden_takeover` reachable.
   Verifiable end-to-end in a sandbox with stubbed OS tools exactly like
   DR-2b/2c/2d were — no cargo needed. Watch: concurrent sweeps (write
   atomically via temp-file + `mv`), and clock changes.
2. **`origin` (larger) — read the trap below before writing any code.**
   Needs cross-invocation focus/input history to distinguish "user opened
   it" from "it appeared uninvited". Design it as its own session.

   **⚠ The obvious X11 implementation is a detection bypass. Do not ship
   it.** EWMH defines `_NET_WM_USER_TIME`, which clients set to *the
   timestamp of the user interaction that caused the window to appear*
   (the value `0` conventionally meaning "do not focus me on map" — this
   is what GTK's `gtk_window_set_focus_on_map` and WM focus-stealing
   prevention in Sawfish/dwm/KDE use). That is almost word-for-word
   muten's `Origin`, so the tempting one-liner is
   `_NET_WM_USER_TIME != 0 → Origin::UserInitiated`.

   It is **client-set**: in X11 an application writes that property on
   its own window, so it is fully attacker-controlled. `UserInitiated`
   grants `W_USER_INITIATED_RELIEF = −40`. A representative scam overlay
   scores fullscreen 30 + no_close 25 + blocks_input 20 + title_hit 40 =
   **115 → Block**; with a forged `_NET_WM_USER_TIME` it becomes
   **75 → Suspicious**, which is *audited but never dismissed*. One line
   of attacker code would therefore disable the protective action
   entirely, while leaving the logs looking healthy.

   **Rule: never derive the relief from data the window itself controls.**
   The asymmetry to hold to:
   - `Origin::UserInitiated` (−40) may only come from evidence the daemon
     or helper observed *independently* of the window — e.g. muten's own
     record of a real input event immediately preceding the map, or WM
     focus history the client cannot write.
   - `Origin::Unsolicited` (+25) may use weaker evidence, because a
     false negative here merely forfeits 25 points, whereas a false
     positive on the relief forfeits the entire block. Note the
     converse FP risk is real but bounded: benign notification popups
     legitimately set `_NET_WM_USER_TIME = 0`, and at +25 (plus topmost
     15 = 40) they stay under `SUSPICIOUS_THRESHOLD = 50`.
   - When in doubt emit `Unknown`. It is the safe default and already the
     status quo.

   *Sourcing note*: the `_NET_WM_USER_TIME` semantics above come from
   search-result summaries corroborated across several independent
   implementations (GTK, Sawfish, dwm, KDE focus-stealing work); the
   freedesktop/GNOME spec mirrors were egress-blocked from the sandbox
   where this was written, so confirm the normative wording against the
   real EWMH spec before implementing. The *security* conclusion does not
   depend on that wording — it follows from the property being
   client-writable, which is basic X11.

   **⚠⚠ SECOND TRAP — enabling `Unsolicited` at all would make muten
   dismiss screen lockers. This one is confirmed from the code, not
   inferred.** `classify()` bounds the `input_trap` bonus at only +5, and
   the comment above it (`src/lib.rs`, the `let input_trap = …` block)
   states the reason outright: the bare lock shape *"without any content
   or provenance tell (origin unknown, no scam title/number) tops out at
   95 — still `Suspicious`, never an automatic `Block`. That preserves
   the observe-first guard for legitimately locked-down full-screen apps
   (kiosk shells, exam lockdown browsers) whose origin a helper can't
   always attribute."*

   That 95 checks out exactly: fullscreen 30 + no_close 25 +
   blocks_input 20 + topmost 15 + input_trap 5 = **95**. **The guard is
   therefore load-bearing on `origin` staying `Unknown`.** Supply
   `Unsolicited` (+25) and the same window becomes **120 → Block →
   dismissed** — and `sudden_fullscreen_takeover` (+5, which itself
   *requires* `Origin::Unsolicited`) can push it to 125.

   The windows this hits are exactly the ones that legitimately appear
   while nobody is touching the machine: **screen lockers**
   (xscreensaver, i3lock, gnome-screensaver), screensavers, corporate
   lock-screen policy, kiosk/digital-signage shells and exam lockdown
   browsers. For a screen locker the failure is not merely a false
   positive — muten would *close the lock screen on an unattended
   machine*, i.e. the product would actively degrade security.

   So `origin` cannot ship as a straight helper field. **Decided design —
   build this guard FIRST, before any `origin` work, as its own
   independently-shippable change:**

   > **Structure alone must never reach `Block`.** If no *content or
   > provenance-of-badness* tell fired — no `blocklist_title`, no
   > `blocklist_host`, no `blocklist_phone`, no `phone_number`, and no
   > content-vocabulary signal — clamp the final score to
   > `BLOCK_THRESHOLD - 1`, so a purely structural window can reach
   > `Suspicious` (audited) but never `Block` (dismissed).

   Why this and not the alternatives. A never-dismiss allowlist of
   locker/kiosk process names is an unbounded list that silently rots —
   every distro's locker, every kiosk vendor, every exam browser, and it
   fails open for the one you didn't enumerate. Re-bounding individual
   geometry weights spreads the fix across many constants and breaks the
   moment someone re-tunes one. The clamp is a single invariant that
   states the actual safety property directly, and it is **already the
   design's intent**: the `input_trap` comment promises the bare lock
   shape "tops out at 95 — still `Suspicious`, never an automatic
   `Block`". Today that 95 is an *arithmetic coincidence* of six
   constants; the clamp turns the same promise into something enforced.
   It also fails safe for shapes nobody has thought of yet, not just
   lockers.

   Note what it does **not** weaken: a real scam overlay carries a
   content tell (a scam title, a phone number, ClickFix instructions), so
   it is unaffected and still Blocks. The clamp only bites on windows
   whose sole evidence is their shape — which is precisely the class
   where lockers, kiosk shells and exam browsers are indistinguishable
   from scams.

   **Order of work**: (1) add a `benign_corpus`-style regression test
   pinning "lock shape + `Unsolicited` + `very_new` ⇒ not `Block`" — it
   will *fail* today if you inject `Unsolicited`, which is the proof the
   guard is needed; (2) implement the clamp; (3) confirm the scam
   scenarios in `scoring_scenarios.rs` still Block; (4) only then start
   `origin`. Teeth: remove the clamp and confirm the new test goes red.

   **Scoping the locker risk — do these windows even get enumerated?**
   (Related-software survey; sourced where noted, hypotheses flagged.)
   The lock-shape FP only bites if the helper can *see* and *close* the
   window, which differs sharply per platform:

   - **X11 — the only platform where the risk is clearly live**, because
     the helper enumerates with `wmctrl -lG` and dismisses with `wmctrl
     -c`. Real software in this category: `xscreensaver`, `i3lock` (and
     `i3lock-color`), `slock`, `swaylock` (Wayland), `xsecurelock`,
     `light-locker`, `gtklock`, `hyprlock`, `waylock`, `alock`,
     `kscreenlocker`, plus `xss-lock` as the activation glue.
     **Unverified hypothesis that would shrink the risk a lot**: minimal
     lockers (`slock`, `i3lock`, `xscreensaver`) conventionally map
     *override-redirect* windows. `wmctrl` is EWMH/NetWM-based, so it
     lists `_NET_CLIENT_LIST`, which by EWMH definition contains only
     **managed** windows — override-redirect windows are unmanaged and
     would therefore be invisible to the helper entirely. I could not
     confirm the override-redirect detail from a primary source this
     session, so **treat it as a hypothesis, not a fact**. It is also the
     single cheapest thing to test: on a real X session run
     `wmctrl -l` while a locker is active. If the locker is absent, the
     FP is unreachable through this helper and the guard can be much
     narrower; if present, the guard is mandatory before `origin` ships.
   - **Windows — likely not at risk.** The real lock screen is
     `LogonUI.exe` on the Winlogon **secure desktop**, and `EnumWindows`
     enumerates only the calling thread's desktop, so a user-session
     helper should never see it. Kiosk cases are different and *are*
     in-session: Windows **Shell Launcher** replaces `Explorer.exe` with
     a kiosk app, and Safe Exam Browser's "Disable Explorer Shell" mode
     runs on the default desktop (its "Create New Desktop" mode does
     not — that one is out of reach, like LogonUI).
   - **macOS — likely not at risk**, as the lock screen is a
     `loginwindow`-level surface rather than a System Events–enumerable
     application window.
   - **Wayland — likely not at risk**, since lockers use the dedicated
     `ext-session-lock-v1` path rather than appearing as ordinary
     foreign-toplevels.

   Exam/kiosk software worth naming in any allowlist work: **Respondus
   LockDown Browser**, **Safe Exam Browser (SEB)**, ProctorU/Honorlock
   proctoring shims, and **Fully Kiosk Browser**; plus digital-signage
   and ATM-style Shell Launcher deployments. These are in-session and
   *do* present the lock shape, so they remain a live FP concern on
   Windows even if the true lock screen is not.

   *Idea worth researching (unvalidated):* OS **idle time** is a
   promising evidence source precisely because — unlike
   `_NET_WM_USER_TIME` — it is maintained by the display server / OS
   input subsystem rather than by the window, so a window cannot forge
   its own provenance. A design sketch is "on the sweep where a window is
   first observed (the first-seen state file from step 1 makes this
   knowable), emit `Unsolicited` iff the OS reports the user idle beyond
   some threshold; otherwise `Unknown`; never `UserInitiated`." **Not
   researched to conclusion**: an attempt to validate per-platform idle
   APIs (X11 XScreenSaver, Wayland `ext-idle-notify-v1`, macOS
   `HIDIdleTime`, Windows `GetLastInputInfo`), their forgeability, and
   the FP surface was aborted when the agents hit a usage limit and
   returned nothing. Treat the sketch as unverified, and note it does
   **not** by itself solve the screen-locker problem above — a locker
   appears *because* the user went idle, so idle-time evidence would fire
   on it maximally.

Do **not** let this become "add `origin` guessing heuristics" — a false
`user_initiated` is a detection hole, and FP-aversion cuts both ways here.

### WO-12 — DR-21: close the Japanese false-positive blind spot 【model: Sonnet | needs: working cargo — non-negotiable】

502 Japanese detection literals are guarded by 10 Japanese benign titles
(50:1). Read the DR-21 entry for the full measurement.

**Verification split, so nobody misreads the evidence.** The corpus
edits here were checked two independent ways: (a) **compilation** —
`tests/benign_corpus.rs` compiles cleanly with all 64 added titles and
the rate-reporting change, checked with `rustc` against a compile-only
`muten_overlay` stub; (b) **behaviour** — every title probed against the
real detectors in `confusables.rs` (`scripts/fp-probe/`), giving
132 titles / 0 false positives / 0.0%. The stub run's own pass/fail is
**not** behavioural evidence: its `classify` returns an empty verdict, so
the benign tests pass trivially and two scam-detection tests fail as
artefacts. Only a real `cargo test` combines both.

**Expect red, and treat every red as the deliverable.** Adding benign
titles is supposed to expose over-broad rules; each failure is a real
false-positive bug to fix (usually by tightening an AND-pair, not by
deleting the title). This is exactly why it **must not** be done in a
`cargo`-less session — pushing tests whose outcome nobody can observe is
worse than not writing them.

1. Grow the JP section of `BENIGN_TITLES` in `tests/benign_corpus.rs`
   substantially — aim for a ratio comparable to the English side, so on
   the order of ~50–100 JP entries rather than 10. Draw them from real
   Japanese software: OS/desktop UI (`設定`, `システム環境設定`,
   `ごみ箱`, `タスク マネージャー`), common apps and their window-title
   conventions, JP browser/webapp titles, and **adversarial-benign**
   cases that deliberately reuse scam vocabulary legitimately — a real
   security product's `ウイルス定義を更新しました`, a bank's genuine
   `重要なお知らせ`, an OS `警告` dialog. Those near-misses are where the
   FPs actually live.
2. For each failure, tighten the offending rule so the benign title stops
   matching while the scam phrasing still does — then confirm the
   corresponding positive test still passes. Never "fix" it by removing
   the benign title.
3. ~~Replace the binary assertion with a reported **rate**~~ — ✅ **DONE**:
   `benign_corpus_fires_no_content_signal` now prints
   `benign corpus: N titles, M content-signal false positives (X.X%)` and
   includes the rate in the failure message. The bar stays at zero — the
   rate is for visibility, not tolerance. Surface it with
   `cargo test -- --nocapture`.
3b. **Pre-probed Japanese candidates (2026-08) — use these, they are
   already measured.** `scripts/fp-probe/` runs a title through all 62
   content detectors with `rustc` alone (no registry). 50 realistic
   Japanese titles were probed: **46 came back clean** and are safe to
   paste into `BENIGN_TITLES` — OS/app chrome (`設定`,
   `システム環境設定`, `ごみ箱`, `タスク マネージャー`, `無題 - メモ帳`,
   `受信トレイ - Outlook`, …) and the adversarial-benign set that reuses
   scam vocabulary legitimately (`ウイルス定義を更新しました -
   ウイルスバスター`, `スキャンが完了しました。脅威は見つかりませんでした`,
   `重要なお知らせ - 三菱UFJ銀行`, `ワンタイムパスワードを入力してください`,
   `税務署からのお知らせ - e-Tax`, `宅配便のお届け予定のお知らせ`,
   `電気料金のお知らせ`, `当選者発表 - キャンペーン事務局`, …).

   **Four fired, and all four are traps — do NOT add them to
   `BENIGN_TITLES`:**

   | title | signal |
   |---|---|
   | アカウントがロックされました - パスワードを再設定してください | `credential_harvest` |
   | 不正なログインを検知しました - ご確認ください | `credential_harvest` |
   | お客様のアカウントは一時的に制限されています | `credential_harvest` |
   | ウイルスが検出されました - 隔離しました - Windows セキュリティ | `fake_scanner` |

   Both signals are gated behind `alert_shaped` in `classify()`, so a
   real notification (small, closable, non-modal) never reaches them —
   **the signals are correct and the geometry guard is doing its job**.
   But `benign_corpus.rs` evaluates with an alert-shaped profile *on
   purpose*, to isolate content FPs, so these would fail there and the
   failure would be wrong. Put them in a separate test asserting
   *"not alert-shaped ⇒ no block"* instead. This is the concrete form of
   the warning in step 2: a red is only a bug once you have checked the
   geometry guard is not already handling it.

4. ~~**Add Cyrillic/Greek/Armenian negative cases**~~ — ✅ **DONE**: 20
   legitimate Russian/Greek/Armenian titles probed and added (corpus
   68 → 132; those scripts 0 → 20). Watch the probe trap documented in
   `scripts/fp-probe/README.md`: form detectors take the **raw** title,
   content detectors the **normalized** one — normalizing first makes
   every pure-Cyrillic word look mixed-script. Original guidance kept
   below for the remaining work:

   **~~Add Cyrillic/Greek/Armenian negative cases — currently there are
   zero.~~** `confusable_mixed_script` (+30) and `whole_script_confusable`
   (+30) exist to judge exactly those scripts, yet `BENIGN_TITLES` has no
   entry in any of them, so neither signal has an FP guard. Include
   ordinary Russian/Greek window titles (which should *not* fire, because
   they contain non-folding letters) **and** the genuinely hard case: a
   short legitimate all-homoglyph word such as `сор` or `рост`, which
   *does* fire +30 today. Decide deliberately whether that is acceptable
   (it is bounded — +30 alone is under `SUSPICIOUS_THRESHOLD`, but
   `fullscreen` + this = 60 → Suspicious) and pin the decision with a
   test either way.
6. **Give the URL signals their first benign coverage (DR-25).** Seven
   signals weighted 20–40 have **zero** benign URL coverage —
   `grep -c "url: Some" tests/benign_corpus.rs` returns 0. Add a
   `BENIGN_URLS` set and exercise it in
   **`benign_corpus_in_normal_geometry_is_allow`**, *not* in the
   alert-shaped test: `ip_host_url` and `data_uri_page` are
   `alert_shaped`-gated on purpose, so putting URLs in the alert-shaped
   corpus produces reds that are **wrong**.

   Candidates, each chosen to exercise a specific signal's FP reasoning:

   | candidate URL | exercises | why it must NOT fire |
   |---|---|---|
   | `https://www.microsoft.com/` | `brand_impersonation` | the literal brand — its comment says "the literal brand never fires" |
   | `https://mail.google.com/` | `brand_impersonation` | real brand with a subdomain |
   | `https://www.mufg.jp/` | `brand_impersonation` | non-Latin-market real brand |
   | `https://windowsupdate.com/` | `combosquat_brand` | legitimate *concatenation*; the hyphen requirement is what spares it |
   | `https://apple-support.example/` *(negative control)* | `combosquat_brand` | this one **should** fire — proves the test has teeth |
   | `http://10.0.0.5/dashboard` | `ip_host_url` | enterprise intranet raw-IP page; gated, so must not fire in normal geometry |
   | `https://storage.googleapis.com/corp-assets/report.pdf` | `cloud_storage_abuse` | legitimate blob-hosted asset; gated |
   | `https://github.com/org/repo/security/advisories` | `url_path_lure` | "security" in the path on a real domain |

   Same rule as step 2: **a red is only a bug once you have checked the
   geometry guard is not already handling it.** Note `typosquat_brand`
   fires at Levenshtein distance exactly 1 — worth adding a real short
   domain that is one edit from a brand if one can be found, since that is
   the residual risk nobody has measured.

5. Optional but valuable: note in the test header that the corpus is
   hand-authored, so it bounds *imagined* FPs only — the literature's
   collected-corpus standard remains unmet.

### WO-13 — DR-22: make silently-dropped blocklist rules visible 【model: Sonnet | needs: working cargo】

The loader skips mis-authored rules with no diagnostic, so a broken rule
is an unannounced detection hole. Full evidence and spec in the audit
doc's DR-22 entry. Collect per-line skip diagnostics in
`Ruleset::from_lines`, surface them through `cmd_rules` and on daemon
rule-reload, and consider a `\#` escape so a literal `#` (TOAD case
numbers) can be expressed at all. Keep "never abort the load" — the fix
is visibility, not strictness.

The shell half is already shipped:
`installer/overlay-helper/lint-blocklist.sh` catches the same classes
pre-deployment. Keep the two in sync — if you add an escape or change the
prefix handling, update the linter and its teeth tests to match.

### WO-7 — EC-1 / EC-2 / EC-3 cleanups 【⚠ ask the user first】

These are recorded in the audit doc's Excess section. **Important
history**: 2026-07 sessions attempted EC-2 (status banners on the four
survey docs) and EC-3 (dedup `MECHANIC_EXEMPT` in `src/lib.rs` tests)
and the user **rejected both edits**. Do not re-attempt without
explicitly confirming the user wants them; treat silence as "no".

### WO-8 — Next threat-intel refresh 【model: Opus or Fable | needs: web access only】

Repeat the 2026-H2 method (see CHANGELOG "2026-H2 threat-intel
refresh"): WebSearch the current quarter's scam-overlay landscape (check
the DR-15 AI-fraud watch item specifically), update
`THREAT_INTEL_2026.md` with a dated section, file new DR items with
implementation specs, add **additive** `title:` blocklist rules (verify
no squash-duplicates: `grep "^title:" examples/overlay-blocklist.txt |
sed 's/[ _-]//g' | sort | uniq -d`).

### Backlog (one-liners — see the audit doc for full entries)

- DR-2 remainder (`origin`/`age_ms`): **promoted out of the backlog** —
  see **WO-11** / DR-20. The literature review made it the top detection
  item, not a someday task.
- DR-6 Merkle-root external anchoring automation. DR-7 config file.
- DR-8 vocabulary beyond EN+JP. DR-9 BITB (needs protocol extension).
- DR-10 remainder: signing / `cargo-semver-checks` / benchmarks.
- v0.6.0 release tag: **requires explicit human GO** (release-approval
  discipline) and should follow, not precede, WO-1.

## 4. Prohibitions (learned the hard way this cycle)

- **Never push to `.github/workflows/`** — GitHub rejects the App token
  (both git and API paths). One retry wastes a commit-reset cycle;
  see DR-16. The workflow lives at `docs/ci/ci.yml` until the owner
  installs it.
- **Never create a PR, tag, or GitHub Release without an explicit user
  instruction in that session** (tags additionally follow the
  release-approval skill: test-pass evidence + explicit GO).
- **Never add cross-wired Rust (new signals, new lens entries) in a
  session that cannot run cargo.** Vocabulary extension of an *existing*
  signal (the DR-12 pattern) is the ceiling for blind Rust, and even
  that is a debt to be repaid by WO-1.
- **Never invent data**: no fictional "known-bad" hosts, processes, or
  phone numbers presented as real (RFC 2606 `.example` domains and
  555-block numbers are fine when explicitly labeled as placeholders).
- **Never let docs claim what you haven't proven** — run the command
  first, then write the sentence.
