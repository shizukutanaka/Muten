# Scam Overlay Threat Intel — 2026-05

Snapshot of the scam-overlay landscape used to seed
`examples/overlay-blocklist.txt`. Refresh quarterly (the host side
rotates weekly; the title/behaviour side is stable for months).

## Dominant vectors (2026)

### 1. ClickFix / FakeCAPTCHA — the #1 vector
A fake "verify you are human" / CAPTCHA / browser-error page tells the
user to press **Win+R**, paste a pre-staged clipboard command, and hit
Enter — running malware themselves, bypassing download sandboxes.
- Surged 517% in H1 2025; ~47% of intrusions Microsoft tracks (2026).
- Variants: **CrashFix** (fake "browser stopped abnormally" + malicious
  Chrome extension, Huntress Jan 2026), **GlitchFix** (ErrTraffic TDS:
  fake browser-update / "system font required" / missing-font dialogs,
  The Hacker News Jan 2026), DNS-based nslookup variant (Microsoft
  Feb 2026).
- Delivery: malvertising + SEO poisoning to pages mimicking Cloudflare
  Turnstile / Google reCAPTCHA; compromised WordPress (Elementor /
  WooCommerce / Gravity Forms) with injected JS (Sekoia IClickFix,
  `ic-tracker-js` tag); phishing to fake video-conf "verify your audio"
  pages.
- Payloads: Lumma/StealC infostealers, Latrodectus, Supper backdoor,
  MIMICRAT.

### 2. Tech-support scam (TSS) fake-virus overlays — still prolific
Full-screen "Your PC is infected / critical error / call support"
pages mimicking Windows/Microsoft/Apple/Norton/McAfee dialogs, pushing
a phone number. Victims grant remote access or pay via gift cards/crypto.
- Malvertising via Facebook ads → decoy sites → Azure Blob TSS pages
  (`*.z13.web.core.windows.net`); 100+ rotated domains/week, active
  Mon–Fri (Gen Threat Labs Feb 2026).
- AI now tailors the alert to the victim's OS/brand (e.g. "Android
  Virus Detected"), raising believability (2026 reporting).
- Behaviour tells: full-screen takeover (F11), blocks closing, fake/
  hidden close button, urgency/countdown, phone number (real OS errors
  never show one).

### 3. Scareware subscription / prize scams
"Your Norton/McAfee subscription expired", "You have won" — lower-
intensity (often have a close button), so muten flags Suspicious
rather than Block.

## How muten maps these to detection

| Threat trait | muten signal |
|---|---|
| Full-screen takeover | `fullscreen` (+30) |
| Always-on-top | `topmost` (+15) |
| Can't close / hidden X | `no_close_button` (+25) |
| Modal input capture | `blocks_input` (+20) |
| Popped up with no user action | `unsolicited` (+25) |
| Just appeared | `very_new` (+10) |
| Known scam phrase in title | `blocklist_title` (+40) |
| Confirmed scam host | `blocklist_host` → hard Block |
| User opened it themselves | `user_initiated` (−40, false-positive guard) |

Validated 2026 samples (ClickFix CAPTCHA, Azure TSS, CrashFix) score
~165 → Block. Legitimate user-opened windows containing the same scary
words score 0–50 → Allow/Suspicious, never auto-dismissed.

## What muten deliberately does NOT do
- No bare cloud-suffix host blocks (`*.web.core.windows.net`,
  `*.cloudflare.com`): they host vast legitimate content; a hard block
  would be a mass false positive. IT adds specific malicious subdomains
  observed in their own telemetry via MDM.
- No clipboard/PowerShell interception: that's an EDR/host-hardening
  job, out of muten's scope. muten removes the *lure window*; blocking
  the *command execution* belongs to the OS/EDR layer.
- No automatic blocklist fetch: offline-first (CLAUDE.md I5). IT pushes
  list updates via MDM.

## Sources
FTC consumer.ftc.gov; Trend Micro tmka-05037, tmka-12135, KongTuke
(Mar 2026); Malwarebytes (Apr–May 2026); Splunk; The Hacker News
(Jan 2026); Proofpoint TA571; Sekoia IClickFix; Huntress (CrashFix);
Gen Threat Labs / cyberpress (Feb 2026); Elastic (bincheck.io,
Feb 2026); Avast; Norton.

## Academic grounding (arXiv) and the phone-number signal

The classifier's signal set is corroborated by the security
literature, and one finding drove a new signal:

- **Miramirkhani, Starov, Nikiforakis — "Dial One for Scam: A
  Large-Scale Analysis of Technical Support Scams"** (NDSS 2017,
  arXiv:1607.06891). An 8-month study of 8,698 TSS domains. Their
  ROBOVIC detector scored pages with a keyword decision tree over a
  tuned threshold — the *same explainable additive-scoring approach*
  muten uses (validating the design over an ML black box). Crucially,
  their analysis shows TSS pages are defined by: a phone number to
  call, full-screen takeover, intrusive JS that blocks navigation
  (`onunload` hooks, repeated `alert()`), and brand/OS impersonation.
- **Microsoft Edge scareware blocker** (2024–2026): a local ML model
  that triggers on *suspicious full-screen pages* and exits full
  screen — corroborating `fullscreen` as a primary signal.
- **USPTO 8,700,913 / 9,141,797 "Detection of fake antivirus"**:
  classify GUI text to an "antivirus category" — analogous to muten's
  title/blocklist matching.

**New signal — `phone_number` (+35).** A genuine operating-system
error never shows a support phone number; a TSS page's entire purpose
is to get the victim to call one. muten now detects a phone-number
pattern (stdlib scanner, 7–15 digits with common separators, rejecting
hex/version/serial runs) and scores it **only when the window is
alert-shaped** (full-screen, modal, or missing a close button) so a
legitimate dialer or contacts window isn't penalized. This closes a
real gap: on a real host where the helper reports `origin: unknown`
(no `unsolicited` bonus), a borderless full-screen TSS page with a
phone number now reaches Block on behaviour alone — no blocklist entry
required.

## Dark-pattern strategy categorization (Gray et al. 2018)

Beyond a binary verdict, muten now tags each detection with the
high-level deceptive-design strategies it exhibits, using the
five-category taxonomy from **Gray, Kou, Battles, Hoggatt, Toombs,
"The Dark (Patterns) Side of UX Design"** (CHI 2018) — the framework
adopted across the literature (Mathur et al. 2019; Di Geronimo et al.
2020; Chen et al., UIGuard, UIST 2023, arXiv:2308.05898) and echoed by
regulators (FTC "coerced action"; California CPRA's dark-pattern
definition).

Signal → strategy mapping:

| muten signal | Gray et al. category |
|---|---|
| `blocks_input` | Forced Action (must act to proceed) |
| `no_close_button` | Obstruction (leaving made hard) |
| `repeated_flood` | Nagging (repeated intrusion) |
| `phone_number`, `blocklist_title`, `blocklist_host`, `rogue_av_process` | Interface Interference (brand/authority misdirection) |
| `fullscreen`, `topmost`, `very_new`, `unsolicited`, `user_initiated` | (descriptive only — not a strategy) |

`Verdict.categories` and the `overlay_blocked` / `overlay_suspicious`
/ `scareware_detected` audit events now include these, so a SIEM can
group overlay incidents by deceptive strategy and reports can use the
same language as CPRA/FTC enforcement. This is pure classification
over the already-computed signals — no computer vision (muten reasons
over window metadata, not pixels), offline, `forbid(unsafe_code)`.

Why categorize at all (vs. UIGuard's pixel-level CV): muten's design
constraint is window-metadata-only, so it can't do UIGuard's
element-level visual analysis. But mapping the signals it *does* have
to the standard taxonomy delivers most of the regulatory/audit value
without a vision model or its false-positive surface.

## Homoglyph evasion defense (confusable folding)

**Threat.** muten's title blocklist is the reliable detection path on
real hosts. A plain ASCII substring match is trivially evaded with
**homoglyphs** — visually identical characters from other scripts.
"your computer is infected" → "your computer is іnfected" (Cyrillic і,
U+0456) is pixel-identical to a victim but invisible to
`str::contains`. Macko et al. ("Authorship Obfuscation in Multilingual
Machine-Generated Text Detection", arXiv:2401.07867) find homoglyph
substitution among the most effective evasions of text-based
detectors across all 11 languages they tested.

**Defense.** The `confusables` module folds the high-frequency
homoglyphs that appear in scam/phishing text — Cyrillic and Greek
letters that look like Latin, full-width Latin (U+FF01–FF5E), and
common diacritics — to their ASCII skeleton before title matching,
phone-number detection, and repeat-signature computation. It's a
focused subset of Unicode UTS #39 confusables (same "focused subset"
philosophy as the blocklist), chosen to stay dependency-free, offline,
and `forbid(unsafe_code)`. Folding is idempotent and preserves
character count (property-tested).

Effect: "your computer is іnfected" (Cyrillic і) now matches the ASCII
blocklist pattern and reaches Block, instead of slipping through. This
does not claim to be a complete confusables implementation; it raises
the cost of the cheapest, most common evasion.

## Competitive analysis: Microsoft Edge Scareware Blocker

The closest same-category product is Microsoft Edge's Scareware
Blocker (GA Nov 2025, Edge 142). Comparing its detection signals to
muten validates muten's approach and surfaced blocklist gaps:

| Edge signal | muten |
|---|---|
| Full-screen mode | `fullscreen` ✓ |
| Tech-support phone number | `phone_number` ✓ |
| Keyboard/mouse hijack | `blocks_input` (helper can't reliably detect; honest default) |
| Loud alarm audio | covered by muten's *audio* enforcement layer, not overlay |
| Fake blue screens / control panels | **added to blocklist this session** |
| Law-enforcement impersonation lock-screens | **added to blocklist this session** |
| Computer-vision page-vs-sample match | out of scope (muten is metadata-only, no CV) |

Key architectural difference: Edge uses an on-device **computer-vision
ML model** comparing full-screen pages to thousands of scam samples.
muten deliberately does **not** (Pike/I6: explainable, offline,
`forbid(unsafe_code)`, no per-frame inference). The trade-off is that
muten leans on the blocklist where Edge's CV generalises — so keeping
the blocklist current with trending families is muten's equivalent of
Edge's sample corpus.

Edge's own data also reinforces muten's observe-first design: in
preview, ~30% of targeted users saw a fast-moving scam *before* the
first report reached SmartScreen — early local detection matters, and
false-alarm reporting (not auto-removal) is how Edge tunes precision.

### Blocklist additions this session (FBI IC3 2025-grounded)

Added two trending families the prior list missed: **law-enforcement /
government impersonation lock-screens** (FBI IC3 2025: complaints
~doubled to 32,500, ~$797M lost, top-5 cyber-enabled fraud) and **fake
blue-screen / system-error / control-panel** overlays (Edge security
team, 2025). Title patterns grew 53 → 70. A new
`tests/blocklist_coverage.rs` suite loads the shipped file and pins
coverage of these families (composing correctly with confusable
folding), so a future edit can't silently drop them.

## 日本語サポート詐欺 (Japanese support-scam) coverage

muten is a Japan-market product, and 偽セキュリティ警告 / サポート詐欺
is the dominant local overlay-scam variant. IPA reports the monthly
consultation count repeatedly hitting record highs; 消費者庁 issued a
formal warning about scams misusing the Microsoft logo (被害額4億円
以上). The Japanese-language blocklist section (21 title patterns) is
sourced from:

- IPA 安心相談窓口だより (2024-11 / updated 2025-04) — the canonical
  Japanese fake-warning wording ("ウイルスに感染しています", "今すぐ
  〇〇に電話してください", fake ✖ close button, alarm audio, fullscreen
  takeover, "すべてのファイルが削除されます").
- Trend Micro support advisory (2025-12), 東京スター銀行 education
  page, 消費者庁 Microsoft-logo warning (2023-09).

Implementation note: matching is confusable-fold + ASCII-lowercase.
Japanese passes through confusable folding unchanged (verified by
`confusables::preserves_non_confusable_unicode` and the
`japanese_*` blocklist-coverage tests) and `to_ascii_lowercase` only
touches ASCII, so Japanese patterns match exactly while mixed
Latin/Japanese titles ("Windows 警告: ウイルスに感染しました") still
hit. A fullscreen Japanese TSS screen now classifies as Block.

This addresses IMPROVEMENT_ROADMAP C2-1 (multilingual blocklist),
prioritised because a Japan-market product detecting zero Japanese
scams was the single largest real-world coverage gap.

## Host typosquat / homoglyph folding (C8-1)

The title blocklist was hardened against homoglyph evasion earlier;
the **host** blocklist had the same hole. A block rule for
`microsoft-support.example` was trivially dodged by
`micros0ft-support.example` (digit zero) or `paypа1...` (Cyrillic а +
digit one). `match_host` now folds confusables on both the URL host
and the rules before comparison, via `fold_host_confusables` — which
extends the script-lookalike fold with the typosquat digit map
`0→o, 1→l, 5→s, 3→e`. (The general title fold deliberately leaves
digits alone, since phone-number detection needs them; the digit map
is host-only.)

The matched *rule* string is still returned unfolded for the audit
log. Folding is for blocklist matching only, so the worst case is a
benign host folding to equal a known-bad brand rule — vanishingly
unlikely, and covered by `benign_host_not_falsely_matched`.
Verified end to end: `micr0s0ft-secure.example` → Block via the
`microsoft-secure.example` rule.
