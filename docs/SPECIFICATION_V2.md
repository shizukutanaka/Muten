# muten-overlay v0.6 — Technical Specification (historical snapshot, Round 19–30)

> **SUPERSEDED — this is a frozen historical snapshot, not the current spec.**
> For the current normative specification (types, classifier contract,
> blocklist grammar, audit chain, CLI contract), see
> [`docs/SPECIFICATION.md`](SPECIFICATION.md) instead — that file is the
> one listed in `README.md`'s documentation index and has continued to
> receive updates through DR-1..DR-16 (2026-07), long after this file was
> generated. This document was never linked from `README.md` or
> cross-referenced by `SPECIFICATION.md`; it is kept only as a detailed
> engineering record of the Round 19–30 Unicode-confusable-folding work
> (the exhaustive per-script fold table in §4 and the Strengths/
> Weaknesses/Improvement-Areas analysis in §§5–7 have no equivalent
> elsewhere and are still useful *as history*), not as a source of truth
> for current behavior, test counts, or line counts — all of which are
> stale here and should be read from `SPECIFICATION.md`, `CHANGELOG.md`,
> and `docs/FEATURE_AUDIT_2026H2.md` instead.

> Generated: 2026-06-20. Covers the codebase through Round 19 (Coptic + superscript/subscript folding); the version-history table in §10 was later extended through Round 30 without the rest of this document being refreshed to match.

---

## 1. System Overview

`muten-overlay` is an **offline, explainable, ML-free scam-overlay and scareware classifier** for desktop window titles and URLs. It is the detection core of the Muten security suite.

**Primary goal**: classify a window (`title`, optional `url`, behavioral flags) as `Allow / Suspicious / Block` with a deterministic, auditable explanation — in microseconds, without network access, without any trained model.

**Design constants** (must not be violated by any change):
- `#![forbid(unsafe_code)]`
- Zero new crate dependencies for core detection (serde/clap are existing infra dependencies)
- MSRV 1.75.0
- Fully offline: no DNS, no HTTP, no file I/O at classify-time
- Pure functions: `classify()` is deterministic and side-effect-free
- False-positive averse: a legitimate Japanese app title must not trigger alerts

---

## 2. Architecture

```
Input: Window { title, url?, coverage_percent, topmost, has_close_button,
                blocks_input, origin, process? }
         │
         ▼
   ┌─────────────────────────────────────────────────────┐
   │              classify() — lib.rs                     │
   │  1. Behavioural signals (score +=)                   │
   │  2. Text signals on raw title (score +=)             │
   │  3. normalize_for_match(title) → normalized          │
   │  4. Blocklist match (rules.rs) → match_title()       │
   │  5. URL match (rules.rs) → match_host()              │
   │  6. Score → Decision (thresholds)                    │
   │  7. Verdict { decision, score, signals, matched_rule,│
   │               categories, explanation }              │
   └─────────────────────────────────────────────────────┘
         │
         ▼
   CLI (bin/cli.rs): text or --json output, exit codes 0/5/6/7
```

### Key source files

| File | Lines | Purpose |
|------|-------|---------|
| `src/confusables.rs` | ~10 600 | Unicode normalization pipeline + confusable folding |
| `src/lib.rs` | ~8 600 | `classify()`, all `W_*` signal constants, `Verdict` |
| `src/rules.rs` | ~1 400 | Blocklist rules, `match_title`, `match_host` |
| `src/categories.rs` | ~340 | Signal → `Category` mapping |
| `src/bin/cli.rs` | — | CLI entry point |

---

## 3. Scoring Model

| Threshold | Decision |
|-----------|----------|
| `score ≥ 100` | `Block` (exit 6) |
| `score ≥ 50` | `Suspicious` (exit 5) |
| `score < 50` | `Allow` (exit 0) |

Exit 7 = evaluation error.

Selected signal weights (from `lib.rs`):

| Signal | Weight | Notes |
|--------|--------|-------|
| `coverage_percent ≥ 90` | +30 | Full-screen coverage |
| `topmost` | +15 | Always-on-top |
| `no_close_button` | +25 | Trapped window |
| `blocks_input` | +30 | Input capture |
| `origin_unsolicited` | +20 | Not user-initiated |
| `phone_number` | +35 | Tech-support call-to-action |
| `blocklist_title` | +80 | Exact-after-norm match |
| `blocklist_host` | +70 | Host match |
| `mixed_script` | +30 | Cyrillic/Greek/Coptic+Latin token |
| `compat_chars` | +20 | Enclosed/math/small-cap letters |
| `compat_chars_present` | — | alias for `compat_chars` |
| `whole_script_confusable` | +30 | Pure-Cyrillic/Greek token folds to ASCII |

---

## 4. Normalization Pipeline

`normalize_for_match(s)` applies 11 steps in order. All steps are pure, allocation-bounded, and idempotent as a composition:

1. `bound_title_chars` — hard-cap at 2048 chars (DoS guard)
2. `strip_symbols_and_emoji` — remove emoji/dingbats that can't be keywords
3. `expand_ligatures` — ﬁ → fi, ﬀ → ff, etc. (30 ligatures)
4. `fold_halfwidth_katakana` — ｆｒｅｅ → free (fullwidth covered separately)
5. `fold_unicode_spaces` — NBSP, IDEOGRAPHIC SPACE, etc. → regular space
6. `strip_invisibles` — zero-width joiners/non-joiners, BOM, soft hyphen, BiDi marks
7. `strip_combining_marks` — accent/diacritic combining characters (category M)
8. `fold_confusables` — call `fold_char` on every character
9. `collapse_ascii_spaces` — normalise repeated spaces
10. `collapse_spread_characters` — "v·i·r·u·s" → "virus" (spread-word evasion); separators include `. , - _ / * | ~ = # ; \ !`, `· •`, the dot-operators ‧ ∙ ⋅, and NBSP — `:`/`+` excluded by design (M:SS, Win+R)
11. `fold_leet_in_words` → to_ascii_lowercase — leet substitution then lowercase

### `fold_char` coverage (as of Round 19)

| Script / Block | Unicode Range | Example evasion folded |
|----------------|--------------|----------------------|
| Cyrillic (core) | U+0400–U+045F | а→a, е→e, о→o, р→p, с→c, х→x |
| Cyrillic Extended | U+04BA–U+051D | һ→h, Ӏ→l, ԁ→d, ԛ→q, ԝ→w |
| Greek core | U+0370–U+03FF | α→a, ο→o, ρ→p, ν→v, η→n, τ→t, ω→w, π→n |
| Greek lunate sigma/yot | U+03F2–U+03F3 | ϲ→c, ϳ→j |
| **Coptic** | U+2C80–U+2CB1 | Ⲁ→a, ⲉ→e, ⲓ→i, ⲟ→o, ⲥ→s, ⲧ→t, ⲱ→w |
| Latin diacritics | U+00C0–U+024F | á→a, é→e, ü→u, ø→o, ł→l |
| Micro sign / f-hook | U+00B5, U+0192 | µ→u, ƒ→f |
| Letterlike Symbols | U+2100–U+214F | ℓ→l, ℙ→p, ℤ→z, ℘→p, Ω→w |
| Roman numerals | U+2160–U+217F | Ⅽ→c, Ⅿ→m (single-letter only) |
| IPA/Phonetic small-caps | U+0250–U+02AF, U+1D00–U+1D2F | ɴ→n, ᴛ→t, ᴜ→u, ᴡ→w |
| Latin Extended-D small-caps | U+A730–U+A731 | ꜰ→f, ꜱ→s |
| Math Alphanumeric | U+1D400–U+1D7FF | 𝒑𝒂𝒚𝒑𝒂𝒍→paypal (16 styles) |
| Enclosed/circled Latin | U+249C–U+24E9 | ⓟⓐⓨⓟⓐⓛ→paypal |
| Enclosed Alnum Supplement | U+1F110–U+1F189 | 🅟🅐🅨🅟🅐🅛→paypal |
| Fullwidth ASCII | U+FF01–U+FF5E | ｖｉｒｕｓ→virus |
| Script decimal digits | 6 scripts | Arabic-Indic, Devanagari, etc. → 0–9 |
| Circled/superscript digits | U+2460–U+2079 | ①→1, ⁴→4 |
| **Superscript Latin letters** | U+2071, U+207F | ⁱ→i, ⁿ→n |
| **Subscript Latin letters** | U+2090–U+209C | ₐ→a, ₑ→e, ₒ→o, ₜ→t |
| **Modifier Latin letters** | U+02B0–U+02E3 | ʰ→h, ʳ→r, ʷ→w, ˢ→s, ˣ→x |
| **Armenian (strong homoglyphs)** | U+0555/0585, U+0578, U+057D, U+0570, U+0575 | օ→o, ո→n, ս→u, հ→h, յ→j |
| **NFKD compat folds** | U+017F, U+1D9C/1DA0/1DBB, U+212A, U+2139, U+2145, U+2C7C/2C7D, U+A7F2–A7F4 | ſ→s, K(Kelvin)→k, ⱼ→j, ꟴ→q |
| Dash variants | U+2010–U+2015, U+2212 | –→-, —→- |
| Katakana middle dot | U+30FB | ・→· (for spread-word collapse) |

---

## 5. Strengths

### S1 — Explainability and auditability
Every verdict carries a `signals` list, a `matched_rule` (if applicable), `categories`, and a plain-language `explanation` string. Analysts can reproduce any decision by inspection; no black-box model needed.

### S2 — Evasion resistance (multi-layer)
Detection doesn't depend on a single layer. A scam must simultaneously evade:
- Behavioral signals (coverage, topmost, blocks_input, etc.)
- 30+ content-pattern functions (phone numbers, urgency cues, lure phrases)
- The blocklist (which uses a hardened 11-step normalization pipeline)
- Mixed-script detection (Cyrillic/Greek/Coptic + Latin within one token)
- Whole-script-confusable detection
- Compat-chars detection (math styles, enclosed letters, small-caps)

### S3 — False-positive discipline
- Japanese+Latin window titles are explicitly safe (CJK → `Script::Other`)
- Small-cap run threshold=4 protects DNA-style abbreviations
- Whole-script confusable checks for foldability (e.g., Russian "пора" won't fire because п doesn't fold to ASCII)
- Phone number detection runs on non-leet-folded text so `1-800-555-0100` is untouched

### S4 — Comprehensive Unicode normalization
After Round 22: fold_char covers all four confusable-bearing scripts (Cyrillic, Greek, Coptic, Armenian), all 16 Mathematical Alphanumeric styles, small-capitals, enclosed/circled letters, fullwidth, superscript/subscript/modifier letters, and every codepoint whose Unicode NFKD decomposition is a single ASCII letter (except deliberately-skipped ordinal indicators) — essentially the full practical homoglyph space for Latin-look-alike evasion.

**Verification methodology**: the NFKD-decomposition scan (Round 22) is a reusable, authoritative gap-finder — any codepoint the Unicode Consortium declares compatibility-equivalent to one ASCII letter is a safe, by-definition-correct fold. Re-running it after each Unicode version update surfaces new compatibility characters automatically.

### S5 — Offline, pure, dependency-free core
The detection core (`classify()` and all of `confusables.rs`) does no network and no disk I/O and carries no ML model weight files — it is deterministic, pure Rust. The only I/O is the CLI reading the local rules file at startup (see S8); classification itself remains air-gapped and side-effect-free.

### S6 — Test coverage
1 513 tests total (1 053 lib unit + 242 scoring scenarios + ~218 property/integration). Every new normalization function has idempotency tests; property tests assert never-panic / no-false-positive / score-monotonicity invariants for every detector.

### S8 — Operator-tunable, fully offline configuration
Both the blocklist (`host:` / `glob:` / title-substring rules) and every signal weight (`weight: <signal> <value>`) are loaded from one offline rules file (`--rules <path>`, pushed via MDM). Weights are clamped (`±MAX_ABS_WEIGHT`), case-insensitive, and fall back to compiled defaults — operators retune sensitivity and add campaign rules without a recompile, all on-device.

### S7 — MSRV 1.75 + forbid(unsafe_code)
Stable, auditable, no unsafe. Compiles on 3-year-old toolchains.

---

## 6. Weaknesses

### W1 — Armenian ✅ RESOLVED (Round 21); Georgian still open
Armenian: `fold_char` now folds the strong Latin homoglyphs օ/Օ→o, ո→n, ս→u, հ→h, յ→j, and `script_of` classifies the Armenian block (U+0530–U+058F) as `Script::Armenian` for mixed-script detection. Selection is deliberately narrow (it's a living language); whole-script detection stays FP-safe via its foldability guard.

Georgian remains uncovered. Georgian Mkhedruli has fewer reliable Latin homoglyphs than Armenian (e.g. ჿ, ო), so the priority is lower.

**Risk level**: Low (Georgian only).

### W2 — Coptic letters without explicit fold entries pass through unchanged
`fold_char` covers the 30 most-confusable Coptic letters. The remaining ~77 Coptic letters (dialect-P forms, cryptogrammic forms, Bohairic extensions) are not mapped. Most are obscure enough that they wouldn't match any Latin letter visually, but Ⲓ/ⲓ (IAUDA), Ⲥ/ⲥ (SIMA), Ⲧ/ⲧ (TAU) are covered; the gap is in rare dialect forms.

**Risk level**: Low. The attack surface for unmapped Coptic chars is very small.

### W3 — Modifier superscript letters ✅ RESOLVED (Round 20)
Characters like ʰ (U+02B0), ʲ (U+02B2), ʳ (U+02B3), ʷ (U+02B7), ʸ (U+02B8), ˡ (U+02E1), ˢ (U+02E2), ˣ (U+02E3) — category Lm, surviving `strip_combining_marks` — are now folded by `fold_char` to h/j/r/w/y/l/s/x. The non-clean shapes (ʱ h-with-hook, ˠ gamma, ˤ glottal stop) are intentionally left unfolded.

### W4 — Weight configurability ✅ ALREADY SOLVED (ruleset `weight:` lines)
The `W_*` constants are *defaults*, not the only source of truth. Any signal weight can be overridden at runtime by a `weight: <signal> <value>` line in the ruleset file: `Ruleset::weight_of(signal, default)` is consulted everywhere in `classify()`, overrides are case-insensitive and clamped to `±MAX_ABS_WEIGHT`, and fall back to the default when absent or unparseable. Operators tune sensitivity by editing the offline rules file — no recompile. (This supersedes the env-var idea originally filed as P3.)

**Risk level**: None — resolved.

### W5 — Blocklist runtime-loading ✅ ALREADY SOLVED (`--rules <file>`)
Blocklist rules are *not* code-only. The CLI loads host / title-substring / glob patterns **and** weight overrides from an offline rules file via `--rules <path>` (`Ruleset::parse` over `std::fs::read_to_string`), pushed via MDM and read at startup. A new scam campaign is handled by editing the file, not the library. Only *live hot-reload within a long-running process* is absent — moot for the per-invocation CLI, where each run re-reads the file.

**Risk level**: Low — only relevant to a future long-running daemon.

### W6 — `has_close_button` and `blocks_input` rely on caller truthfulness
The behavioral signals depend on values the collector provides. If the collector uses heuristics (accessibility API, process inspection) rather than definitive OS queries, false values can flow in. This is documented in `docs/OVERLAY_BLOCKING.md`.

**Risk level**: Architecture boundary issue; not fixable in the library.

### W7 — No fuzz testing beyond proptest
Property tests cover `normalize_for_match` and scoring monotonicity, but there is no `cargo-fuzz` / libFuzzer integration. Exotic Unicode sequences could theoretically trigger a panic in an untested code path.

**Risk level**: Low (all paths use `char::from_u32` with fallback; no unsafe indexing).

### W8 — Leet folding gap: `2→z` not implemented
The leet alphabet is `0→o, 1→i, 3→e, 4→a, 5→s, 7→t`. The digit `2` is sometimes used for 'z' ("v2rus"), but `2` was left out because it's a high-FP digit (version numbers, "2FA", "win32"). Current implementation is intentionally conservative here.

---

## 7. Improvement Areas (Prioritized)

### P1 (High) — Armenian confusables ✅ DONE (Round 21)
Folded օ/Օ→o, ո→n, ս→u, հ→h, յ→j; added `Script::Armenian`. Georgian deferred (few reliable homoglyphs).

### P2 (High) — Modifier superscript letters ✅ DONE (Round 20)
Folded ʰ→h, ʲ→j, ʳ→r, ʷ→w, ʸ→y, ˡ→l, ˢ→s, ˣ→x in `fold_char`.

### P3 — Weight externalization ✅ ALREADY DONE (ruleset `weight:` lines)
Superseded by the existing `weight: <signal> <value>` ruleset mechanism (see W4), which is cleaner than env vars: same offline file as the blocklist, audited together, clamped, case-insensitive. No further work needed; env-var variant intentionally not pursued (redundant).

### P4 (Medium) — `cargo-fuzz` integration
**What**: Add a `fuzz/` directory with fuzz targets for `normalize_for_match`, `classify`, and `fold_char`.
**Why**: Property tests are random but bounded; libFuzzer coverage-guided fuzzing finds corner cases faster.
**Effort**: Medium — fuzz harness setup, CI integration.

### P5 (Low) — Blocklist *live* hot-reload (startup-load already done)
Startup file-loading already exists (`--rules <file>`; see W5). The only remaining increment is *live* reload while a long-running process is running (e.g. watching the file for changes). This is irrelevant to the current per-invocation CLI and only becomes useful if a persistent daemon is built; deferred until then.

### P6 (Low) — `2→z` leet mapping with guard
**What**: Add `2 → 'z'` to `fold_leet_digit`, guarded by requiring the token to contain an adjacent non-digit letter (so "v2rus" → "vzrus" then to "virus" only if the broader normalization catches it via blocklist).
**Why**: Closes the only missing leet digit.
**Risk**: "2FA", "win32", version strings — must verify no FP regression across the full test suite.

---

## 8. Signal Inventory (Summary)

The following signal families are implemented (see `confusables.rs` and `lib.rs`):

**Behavioral** (8 signals): coverage, topmost, no_close_button, blocks_input, origin, process family, modality.

**Text — generic evasion** (5 signals): mixed_script, whole_script_confusable, compat_chars_present, excessive_combining_marks, bidi_override, mixed_number_systems.

**Text — scam content** (20+ functions): clickfix_instruction, urgency_countdown, forced_retention, credential_harvest_cue, fake_scanner_cue, subscription_lure, authority_lure, screen_share_lure, crypto_drain_lure, prize_lure, download_trap_lure, qr_code_lure, ip_alarm_lure, package_fee_lure, sextortion_lure, gift_card_demand, refund_scam_cue, national_id_alarm, bank_account_alarm, false_registration_billing, fake_bsod_lure, advance_fee_lure, tech_support_invoice_scam, utility_cutoff_threat, healthcare_scam, job_scam, tax_authority_scam, social_media_account_alarm.

**Blocklist** (2 signals): blocklist_title (score +80), blocklist_host (score +70).

**Phone** (1 signal): phone_number (score +35).

---

## 9. Test Coverage Summary

| Suite | Tests | What it covers |
|-------|-------|----------------|
| lib unit tests (confusables/lib/rules/categories/monitor/sink/controller) | 1 053 | Every fold_char case, normalization pipeline, signal functions, scoring, weight overrides |
| Scoring scenarios (integration) | 242 | End-to-end classify() across realistic scam/benign windows |
| Property tests + other integration suites | ~218 | Proptest never-panic / no-FP / monotonicity invariants for every detector; CLI; rules-file loading |
| **Total** | **1 513** | all green; clippy `-D warnings` clean; `cargo fmt --check` clean |

---

## 10. Version History (Recent)

| Version | Key changes |
|---------|-------------|
| v0.5.0 | Mixed-script detection, leet folding, zero-width stripping, explain(), --json CLI |
| v0.6.0 (R10–R18) | +Math Alphanumeric styles, control stripping, small-caps, Roman numerals, Greek gaps, Cyrillic supplement, Letterlike Symbols completeness |
| v0.6.0 (R19) | +Coptic block (U+2C80–U+2CFF) folding + Script::Coptic detection; superscript/subscript Latin letters |
| v0.6.0 (R20) | +Modifier (superscript) Latin letters U+02B0–U+02E3 folding |
| v0.6.0 (R21) | +Armenian strong homoglyphs (օ/ո/ս/հ/յ) + Script::Armenian |
| v0.6.0 (R22) | +NFKD-authoritative single-letter compat folds (long-s, Kelvin sign, modifier/subscript letter holes); ª/º deliberately skipped |
| v0.6.0 (R23) | +expanded spread-character separators (= # ; \ ! and dot-operators ‧ ∙ ⋅); :/+ still excluded |
| v0.6.0 (R24) | Script `#[non_exhaustive]`; CHANGELOG v0.5/v0.6 documented |
| v0.6.0 (R25) | spec corrected to credit ruleset weight/blocklist file-loading (W4/W5/P3/P5) |
| v0.6.0 (R26) | phone scanner: fold middle-dot/bullet separators (· • ‧ ∙ ⋅) → '.' so `1·800·555·0100` is detected |
| v0.6.0 (R27) | blocklist `match_phone`: fold O→0 / l→1 so a letter-substituted *known* scam number (`1-8OO-555-O1OO`) matches the curated rule |
| v0.6.0 (R28) | `match_process`: fold homoglyphs (Cyrillic/Greek/… → ASCII) so a rogue-AV binary named `РСProtector.exe` matches its rule; digits preserved (no win32→winee) |
| v0.6.0 (R29) | exhaustive invariant tests: `fold_char` proven idempotent over all 1.1M Unicode scalar values; ASCII letters/digits proven fixed points |
| v0.6.0 (R30) | composed-evasion integration suite: stacked homoglyph+leet+math+zero-width+combining+spread titles still recover, fire blocklist_title, and Block; benign control proves no phantom matches |
