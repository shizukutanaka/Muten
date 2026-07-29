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

- 66-signal / 10-lens detection engine with the evasion-resistant
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
| Cargo-unverified Rust on the default branch: DR-12 impl, 2 `scoring_scenarios.rs` tests, both `*_helper_reference.rs` files | #1 risk — could fail to compile | **WO-1** |
| CI claimed-then-shipped but not installed (DR-16) | no automated verification channel | **WO-2** (owner step) |
| No signal for a bare IP literal shown in an alert (DR-13, CypherLoc trick) | detection gap on a live 2.8M-victim kit | **WO-3** |
| IT-helpdesk impersonation only covered by verbatim blocklist rules (DR-14) | generalization gap (low — exact phrasings blocked) | **WO-4** |
| Wayland lswt parser: probe/enumerate mode mismatch + missing last-block flush (confirmed from code) | lswt hosts silently fall back / drop a window | **WO-5** |
| No fault isolation in `enumerate` parsing (DR-18): one malformed element blinds the entire sweep | worst-case failure mode; helper bugs / custom helpers see *nothing* instead of missing one window | **WO-9** |
| Failed dismiss audited identically to a self-closed window (DR-19) | a broken dismissal path across a fleet is invisible — looks like scams closing themselves | **WO-10** |
| Audit log grows unbounded; no rotation (DR-4) | multi-week deployments | **WO-6** |
| `origin` hard-coded `unknown` on all 4 platforms (DR-2 remainder) | `unsolicited` (+25) never fires on real hosts | Backlog (own session) |
| Detection vocabulary EN+JP only (DR-8) | non-EN/JP fleets under-detect | Backlog |

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

1. `cd crates/muten-overlay`
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

Two bugs are already confirmed from the script alone (see the DR-2
Wayland note in the audit doc): `pick_tool` validates `lswt -j` but
`enumerate` parses plain `lswt`; and the plain-lswt loop drops the last
toplevel (no final-block flush). **Procedure order matters**: first
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

- DR-2 remainder: `origin` inference on all 4 platforms (largest piece;
  needs cross-invocation focus-history state; own session).
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
