# Overlay Blocking (v0.4.0)

muten v0.4.0 extends the product from audio-only enforcement to
**endpoint environment enforcement**: in addition to keeping managed
PCs quiet, it detects and (optionally) dismisses scam overlays — the
full-screen "your computer is infected / call support / you have won"
windows that plague library, school, kiosk, and call-center PCs.

## Design posture: observe first, block conservatively

False positives are catastrophic. Wrongly dismissing a video player,
a presentation, an exam app, or a kiosk's own UI breaks the
environments muten exists to protect. So:

- The default ruleset is empty and the classifier only **Blocks** on
  a confirmed blocklist host match or an unmistakable heuristic score
  (≥ 100).
- Everything between `SUSPICIOUS_THRESHOLD` (50) and `BLOCK_THRESHOLD`
  (100) is **Suspicious** — audited for IT review, not dismissed.
- Below 50 is **Allow**.

This mirrors the audio side's `pilot-observe` mode.

## How it scores (explainable, per CLAUDE.md I6)

`muten_overlay::classify` sums named signal weights and records which
fired in the `Verdict.signals` list, so every decision is traceable
in the audit log:

| Signal | Weight | Rationale |
|---|---:|---|
| fullscreen (≥85% coverage) | +30 | scams grab the whole screen |
| topmost | +15 | always-on-top to stay in your face |
| no_close_button | +25 | scams hide/fake the close affordance |
| blocks_input | +20 | modal capture traps the user |
| unsolicited | +25 | appeared with no user action |
| very_new (<1s) | +10 | just popped up |
| blocklist_title | +40 | title matches a known scam phrase |
| phone_number | +35 | a support number in an alert-shaped window (NDSS 2017) |
| blocklist_phone | +40 | a number on the curated `phone:` list (known scam number); high-confidence so no alert-shape needed; additive, digits-only match |
| mixed_script | +30 | title/host mixes Latin with Cyrillic/Greek (homoglyph disguise) |
| whole_script_confusable | +30 | title/host label is all-Cyrillic or all-Greek but every letter folds to a Latin look-alike (blind spot of mixed_script; UTS#39 §5) |
| compat_chars_present | +20 | title/host uses enclosed/circled Latin letters Ⓐ-Ⓩ/ⓐ-ⓩ (U+24B6-U+24E9) — evades plain-text matching; normalized automatically so blocklist matching still works |
| mixed_number_systems | +20 | one token mixes two decimal numbering systems, e.g. ASCII `5` + Arabic-Indic `٥` (ICU MIXED_NUMBERS); full-width digits count as ASCII so JP text isn't flagged |
| excessive_combining_marks | +20 | 3+ combining marks stacked on one base character ("Zalgo" obfuscation); legitimate scripts stack at most 1–2 so they never fire |
| bidi_override | +30 | title/host uses an LRO/RLO directional override (Trojan Source) |
| brand_impersonation | +40 | host label is a UTS#39 skeleton homograph of a known brand |
| combosquat_brand | +30 | host label joins a known brand + a scam-lure word as hyphen tokens (`apple-support`, `paypal-secure-login`; combosquatting, CCS 2017). Hyphen + exact-token requirement keeps `windowsupdate.com` / `support.apple.com` from firing |
| clickfix_instruction | +20 | `alert_shaped` AND normalized title contains ClickFix/fake-CAPTCHA instruction text — `win+r`, `ctrl+v`, CAPTCHA framing, run-dialog phrases, GlitchFix browser-error lures (MS Security Blog 2025: +517 % ClickFix surge). `alert_shaped` guard prevents FPs on legitimate reCAPTCHA browser pages. Leet/homoglyph evasion defeated by `normalize_for_match`. |
| urgency_countdown | +15 | `alert_shaped` AND title contains a `M:SS`/`MM:SS` pattern + urgency keyword (expir, warn, alert, infect, block, urgent, critical…). Scam overlays pair a visible countdown with fear language to coerce action; legitimate clocks/media players are user-initiated and closable (alert_shaped = false). |
| cloud_storage_abuse | +20 | `alert_shaped` AND URL host ends with a known blob-storage suffix with a non-empty tenant label (`*.blob.core.windows.net`, `*.s3.amazonaws.com`, `*.storage.googleapis.com`, etc.). Azure Blob in particular is a primary TSS delivery vector (Gen Threat Labs Feb 2026). |
| url_path_lure | +20 | `alert_shaped` AND URL path contains a known-brand token within 2 positions of a known scam-lure token (`/microsoft-alert/`, `/norton/remove/now`). Catches brand+lure combosquat patterns in paths that make scam URLs look credible in the address bar. |
| typosquat_brand | +25 | host label skeleton has Levenshtein edit-distance exactly 1 from a known brand — catches deletions (`gogle`), substitutions (`googlo`), and transpositions. Mutually exclusive with `brand_impersonation` (distance 0). |
| forced_retention_cue | +20 | `alert_shaped` AND normalized title contains a retention instruction. English: "do not close / do not turn off / do not restart / keep this window open / stay on this page". Japanese: この画面を閉じないで, 電源を切らないで, シャットダウンしないで, 再起動しないで, このページから離れないで, ウィンドウを閉じないで. The JP "この画面を閉じないでください" is the single most iconic IPA-documented サポート詐欺 retention phrase. High-specificity: legitimate software never puts a retention instruction in a window title. |
| credential_harvest_cue | +20 | `alert_shaped` AND normalized title contains account-alarm language OR credential-entry instructions. English: account suspended/locked/compromised, unusual/suspicious sign-in/login/activity, verify account, confirm password, enter credentials, update payment. Japanese: アカウントが停止/凍結/ロック/無効/制限, 不審な/不正な/異常なログイン, パスワードを確認/再入力, 本人確認, 身元確認. Phishing-overlay pattern for bank/email/social credential theft. |
| fake_scanner_cue | +20 | `alert_shaped` AND normalized title contains fake rogue-AV scan-progress language. English: scanning for threats/viruses/malware, N threats detected/found, removing malware, system repair in progress, critical system error detected. Japanese: スキャン中+脅威/ウイルス, 脅威が見つかりました, ウイルス/マルウェアを検出しました, マルウェアを削除しています, ウイルスを駆除, システムを修復しています. |
| subscription_lure | +15 | `alert_shaped` AND normalized title contains all three groups: subject (subscription/license/protection) + expiry (expired/expiring) + action (renew/activate/purchase/call). Covers the softer scareware family ("Your Norton subscription expired — renew now") that may retain a close button. |
| authority_lure | +25 | `alert_shaped` AND normalized title contains an LEA agency token + a coercion token. English agencies: fbi, cia, interpol, europol, hmrc, cybercrime, homeland security, law enforcement, australian federal police, bundeskriminalamt, gendarmerie. Japanese agencies: 警察庁, 警視庁, 国税庁, 消費者庁, サイバー警察, 公安委員会, 財務省, 総務省. Coercion (EN): warning, notice, locked, illegal, fine, arrested. Coercion (JP): 警告, 違反, 違法, ロック, ブロック, 罰金, 逮捕, 不正アクセス, 凍結. Covers Reveton/Winlock-style ransomware-bluff overlays plus IPA-documented Japanese 警察なりすまし詐欺. MITRE T1566. |
| remote_access_lure | +20 | title names a remote-access tool (AnyDesk/TeamViewer/…) AND a fake alert already fired (blocklist title, phone number, or ClickFix) — context amplification per FBI IC3 2024. Never fires on a legitimate remote-support session (no alert tell); never blocks alone. |
| screen_share_lure | +20 | `alert_shaped` AND normalized title contains screen-share social-engineering cues: share-screen + remote-enable + grant-support language. Covers the 2025 FBI IC3-reported surge in screen-sharing scams where victims are coached to share their screen before a fake support call. MITRE T1219. `alert_shaped` guard prevents FPs on legitimate screen-sharing invites. |
| crypto_drain_lure | +25 | `alert_shaped` AND normalized title contains wallet-alarm + coercion + seed-harvest language ("your wallet was drained/blocked" + "connect/verify/validate" + "enter/send seed phrase/recovery phrase/private key"). Covers the 2025-2026 surge in crypto-drain MetaMask/Ledger overlays. MITRE T1566. |
| prize_lure | +20 | `alert_shaped` AND normalized title contains a prize/lottery word (winner/prize/reward/jackpot/selected/lucky/giveaway) AND a claim-action phrase (claim/collect/redeem/click here to claim). The AND-pair requirement prevents single-keyword FPs (e.g. "winner" on a sports page). Common on library and kiosk PCs. MITRE T1566. |
| download_trap_lure | +20 | `alert_shaped` AND normalized title demands a software install: either a direct install demand ("your video player is outdated / update required / click to install") OR a fake-plugin gate (plugin noun — plugin/extension/add-on/codec + action verb — install/update/enable — or "required"). Covers fake-plugin overlays distributing malware that exploit users who can't distinguish a web overlay from a real OS dialog. MITRE T1566. |
| qr_code_lure | +20 | `alert_shaped` AND normalized title contains a QR-noun ("qr code" / "qr-code" / "scan qr") AND verify-action (verify/confirm/authenticate/access/proceed/…). Detects "quishing" overlays where a displayed QR code redirects victims to a phishing site, bypassing URL-filter controls the overlay host may trigger. A major 2025-2026 threat vector per APWG Q4 2024 and FBI IC3 2025 reports. MITRE T1566. |
| ip_alarm_lure | +20 | `alert_shaped` AND normalized title contains ip-subject ("ip address" / "your ip") AND alarm-word (hack/infect/flag/report/block/compromis/breach/…). One of the most common tech-support scam overlay templates: "Your IP address has been hacked / flagged by authorities / reported." Victims are panicked into calling a fake support number. MITRE T1566. |
| package_fee_lure | +20 | `alert_shaped` AND normalized title contains package-noun ("your package/parcel/shipment/delivery/order") AND fee-demand ("customs fee/duty/charge", "on hold", "release fee", "unable to deliver", "delivery fee"). Delivery/customs advance-fee scam overlays impersonating DHL, FedEx, USPS, or customs authorities. FTC 2024: imposter-scam delivery variants were the #2 consumer-fraud category (1.1M complaints, $2.7B+ combined losses). MITRE T1566. |
| sextortion_lure | +25 | `alert_shaped` AND normalized title contains camera-cue ("your camera/webcam", "we have recorded", "have been recording", "hacked your camera") AND extortion-word (bitcoin/btc/cryptocurrency, payment/pay, "your contacts", expose, "send this"). Browser overlay sextortion: attackers claim to have webcam footage and demand cryptocurrency to prevent sending it to the victim's contacts. FBI IC3 2024: sextortion complaints grew 42% YoY. Higher weight (25) than other content signals because the AND-pair is extremely high-specificity. MITRE T1566. |
| gift_card_demand | +30 | `alert_shaped` AND normalized title contains gift-card-noun ("gift card/gift cards", "itunes card", "google play card", "amazon/apple/ebay/steam gift card", "prepaid card", "vanilla card") AND payment-instruction (buy/purchase gift card, send codes/the codes/read the codes, scratch the card, pay with/using/in gift card, go to the store/nearest store). Tech-support and authority-impersonation scams routinely demand gift cards as "payment" to unlock a device or settle a fake fine. No legitimate software ever asks users to purchase and send gift-card codes via an alert-shaped overlay. FTC: gift cards are the #1 payment method in tech-support fraud losses. Weight +30 (near-zero FP with alert_shaped guard). MITRE T1566. |
| refund_scam_cue | +25 | `alert_shaped` AND normalized title contains refund-noun ("refund", "overpayment", "reimbursement", "rebate", "cashback", "excess charge", "overcharged", 返金, 払い戻し, 過払い, 補償金) AND refund-action ("owed to you", "you are owed", "claim your refund", "collect your refund", "pending refund", "refund is ready", "refund has been", "process/transfer/receive/get your refund", "your refund of", "refund amount", 返金手続き, 払い戻し手続き, 返金が完了, お手続きください, ご返金, 返金いたします, 返金を受け取). Scammers posing as support agents, banks, or government agencies falsely claim the victim has an uncollected refund or an overpayment to return, directing them to call a number to "collect", leading to credential theft or gift-card coercion. AND-pair prevents plain return-policy text from firing. FTC 2024 / IC3 2025. Category: Sneaking (Gray et al. 2018). MITRE T1566. |
| national_id_alarm | +30 | `alert_shaped` AND normalized title contains id-noun ("social security number", "social security", "ssn", "national insurance number", "medicare", "medicaid", マイナンバー, 個人番号, 基礎年金番号, 年金番号) AND id-alarm ("has been suspended", "used in criminal", "criminal activity", "criminal charges", "fraudulent activity", "under federal investigation", "identity theft", "has been compromised", 凍結, 不正使用, 不正利用, 犯罪に使用, 捜査中, 停止されました). FTC 2024 identifies SSA impersonation as the #1 government-impersonation scam variant; analogous scams in JP target マイナンバー and 年金番号. No legitimate service suspends a national ID via an unsolicited browser overlay. Category: InterfaceInterference. MITRE T1566. |
| bank_account_alarm | +25 | `alert_shaped` AND normalized title contains bank-noun ("bank account", "checking account", "savings account", "debit card", "credit card", "your account at", 銀行口座, キャッシュカード, 通帳, クレジットカード, デビットカード) AND bank-alarm ("unauthorized transaction", "fraudulent transaction", "suspicious transaction", "fraudulent charge", "has been frozen", "account has been frozen", "fraudulent access", "unauthorized access detected", 不正な取引, 不審な取引, 口座が停止, 口座が凍結, 不正アクセスを検知). Distinct from credential_harvest_cue (which requires a credential-entry instruction): this signal fires when only the alarm framing is present — attacker wants a call, not credential entry. AND-pair prevents generic alerts or balance pages from firing. Full JP coverage. Category: InterfaceInterference. MITRE T1566. |
| false_registration_billing | +25 | `alert_shaped` AND normalized title contains reg-claim ("you have been registered", "membership confirmed", "registration complete", "your subscription has been activated", "successfully registered", 登録が完了, 会員登録が完了, ご登録, 登録されました) AND payment-ultimatum ("pay within", "outstanding fee", "legal action", "failure to pay", "penalty fee", "collection agency", 法的措置, お支払い期限, 未払い, 延滞, 督促). Targets ワンクリック詐欺 (JP one-click fraud) and English billing-threat impostor variants documented by 消費者庁 and FTC IC3 2024. Category: InterfaceInterference. MITRE T1566. |
| fake_bsod_lure | +30 | `alert_shaped` AND normalized title contains bsod-marker ("stop code", "windows has been blocked", "your pc is blocked", "blue screen", "kernel panic", "critical process died", "kmode exception", "memory_management", ブルースクリーン, windowsがブロック, pcがブロック) AND call-barrier ("do not restart", "do not turn off", "call microsoft", "contact microsoft", "microsoft support", "apple support", 再起動しないでください, マイクロソフトサポート). Targets FakeBlue / tech-support BSOD overlays (Microsoft MSTIC 2025). Weight +30 because no legitimate OS crash ever instructs the user to call a phone number via a browser overlay — the AND-pair is near-zero-FP. Category: Obstruction. MITRE T1036. |
| advance_fee_lure | +25 | `alert_shaped` AND normalized title contains fund-claim ("inheritance", "beneficiary", "estate of", "unclaimed funds", "unclaimed inheritance", "won the lottery", "trust fund", 遺産, 受益者, 未請求の資産, 宝くじ当選) AND release-fee ("processing fee", "advance fee", "customs fee", "to release the funds", "to receive your funds", "to claim your inheritance", 手数料, 振込手数料, リリース手数料, 受け取るには手数料). Classic 419 / advance-fee fraud adapted to browser overlays; FTC BCP 2024. Category: Sneaking. MITRE T1566. |
| tech_support_invoice_scam | +25 | `alert_shaped` AND normalized title contains charge-claim ("you have been charged", "a charge of", "subscription has been renewed", "auto-charged", "billing confirmation", "renewal charge", "order confirmation", ご請求が完了, 課金されました, お引き落とし, 自動更新料金) AND cancel-CTA ("call to cancel", "if you did not authorize", "dispute this charge", "to cancel this order", "to reverse this charge", キャンセルするには電話, 不正な請求, 解約の手続き, 請求に心当たりのない). Tech-support/subscription impostor invoices; FTC 2025 impostor-scam taxonomy. Category: InterfaceInterference. MITRE T1566. |
| utility_cutoff_threat | +25 | `alert_shaped` AND normalized title contains utility-service ("electricity", "gas service", "water service", "power company", "electric company", 電気, ガス, 水道, 電力, 公共料金) AND cutoff-threat ("will be disconnected", "will be shut off", "final notice", "pay to avoid disconnection", "service will be terminated", "immediate payment required", 停止予告, 供給停止, 料金未払い, 即時お支払い, 強制停止). Utility-company impostor overlays; FTC 2024 #3 impostor-scam category. Category: InterfaceInterference. MITRE T1566. |
| healthcare_scam | +25 | `alert_shaped` AND normalized title contains health-benefit ("medicare", "medicaid", "health insurance", "medical coverage", "prescription benefit", "medical device", 健康保険, 医療保険, 介護保険, 保険証, 国民健康保険) AND benefit-urgency ("will expire", "expiring soon", "claim your free", "you have been approved", "at no cost to you", "enrollment period ends", 受給期限, 期限切れ, 無料で受け取る, 申請期限, 給付が承認). Medicare/insurance-benefit impostor overlays; IC3 2025 #1 elder-fraud category. Category: Sneaking. MITRE T1566. |
| job_scam | +25 | `alert_shaped` AND normalized title contains job-offer ("work from home", "remote work opportunity", "earn from home", "make money from home", "data entry job", "online job", 在宅ワーク, 副業, テレワーク, 在宅アルバイト, 内職) AND fee-gate ("registration fee", "equipment deposit", "starter kit", "training fee", "pay to start", "upfront fee", "refundable deposit", 登録料, 機材費, 保証金, 入会金, 初期費用). Work-from-home advance-fee scams where victims pay for a "starter kit" or "registration"; IC3 2025 top-5 non-elder-fraud category. Category: Sneaking. MITRE T1566. |
| tax_authority_scam | +30 | `alert_shaped` AND normalized title contains tax-authority ("irs notice", "internal revenue service", "unpaid taxes", "tax debt", "hmrc notice", "delinquent taxes", "tax warrant", 国税庁, 税務署, 延滞税, 税金未納) AND arrest-threat ("arrest warrant", "face arrest", "your assets will be seized", "criminal charges have been filed", 逮捕状, 差し押さえ, 刑事訴追). IRS/HMRC/国税庁 impersonators threatening arrest or asset seizure; FTC 2025 government-impostor #2. Real tax authorities never threaten arrest via browser overlays. Weight +30: AND-pair is near-zero-FP. Category: InterfaceInterference. MITRE T1566. |
| social_media_account_alarm | +25 | `alert_shaped` AND normalized title contains social-platform ("facebook account", "instagram account", "gmail account", "google account", "apple id", "icloud account", "discord account", フェイスブック, ライン, グーグルアカウント, アップルid) AND account-jeopardy ("has been hacked", "has been hijacked", "account suspended", "unauthorized login", "suspicious login detected", "verify to recover", "regain access", アカウントが停止, 不正ログイン, アカウントを回復するには). Social-platform phishing overlays coercing victims into fake "account recovery" flows to harvest credentials; APWG Q1 2025. Category: InterfaceInterference. MITRE T1566. |
| immigration_visa_scam | +25 | `alert_shaped` AND normalized title contains immigration-doc ("your visa", "your work permit", "your green card", "immigration notice", "visa status", "customs and border", ビザ, 在留資格, 在留カード, 永住許可, 入国管理) AND status-threat ("has been revoked", "deportation", "illegal overstay", "renewal fee required", "face deportation", "removal proceedings", 取り消し, 不法滞在, 強制送還, 更新料, オーバーステイ). Immigration-authority impersonators threatening deportation or visa revocation to extract fees from immigrant populations; FTC 2024; MOJI (出入国在留管理庁) advisories. Category: InterfaceInterference. MITRE T1566. |
| input_trap | +5 | full-screen + topmost + modal "screen lock" (bounded; see below) |
| sudden_fullscreen_takeover | +5 | unsolicited window seizes full screen instantly (bounded) |
| user_initiated | −40 | the user opened it → trust more |
| blocklist_host | → hard Block | confirmed scam host |

A benign user-opened full-screen video scores ~5 (Allow). A classic
fake-virus overlay scores ~125 (Block).

The `input_trap` composite fires when a window is **full-screen AND
topmost AND input-grabbing** — the shape of a browser/screen *locker*
(Keyboard-Lock / Pointer-Lock abuse, and scareware kits like CypherLoc
whose encrypted in-browser payload evades content scanners but not the
window-level lock shape). Its bonus is deliberately small: the bare lock
shape with no content or provenance tell tops out at 95 — still
`Suspicious`, never an automatic `Block` — so a legitimately locked-down
full-screen app (a kiosk shell, an exam lockdown browser) with
unknown origin is observed, not dismissed. Any real scam evidence
(unsolicited origin, a phone number, a blocklist hit) still blocks it.

The `sudden_fullscreen_takeover` composite fires when an **unsolicited**
window seizes the **full screen, on top, the instant it appears** (a
real, small, nonzero age). This is the behavioural tell Microsoft's Edge
Scareware Blocker keys on, and muten's no-CV way to flag brand-new scam
domains the blocklist hasn't caught yet — from their shape over time
rather than their content. Its bonus is likewise bounded (the bare
pattern tops out at 85, `Suspicious`); a content or provenance tell
still decides a `Block`.

### Text normalization (defeating evasion)

Before a title is matched against the blocklist it is run through
`confusables::normalize_for_match`, which composes five offline,
dependency-free passes:

1. **strip emoji and symbols** — drop characters in U+2600–U+27BF (Misc
   Symbols + Dingbats: ⚠️ ☎ ✗ ✘ etc.) and U+1F000–U+1FFFF (emoji
   blocks: 🔴 🚨 etc.). Attackers insert these mid-word to split a keyword
   past a naive substring match (`"inf⚠️ected"` → `"infected"` after strip).
   CJK/Kana (U+3000–U+9FFF+) is **not** stripped; Japanese titles are intact.
2. **strip invisibles** — drop zero-width and BiDi-control characters
   (`U+200B…200D`, `U+FEFF`, soft hyphen, `U+202A…202E`, …) that split a
   word past a naive substring match.
3. **fold confusables** — Cyrillic/Greek/full-width look-alikes → ASCII
   skeleton (e.g. Cyrillic `і` → `i`).
4. **fold leetspeak in words** — `0→o 1→i 3→e 4→a 5→s 7→t`, but only
   inside tokens that already contain a letter, so phone numbers and
   counts (pure-digit runs) are left intact.
5. **lowercase**.

The `mixed_script` signal is computed on the **raw** title and host
*before* folding (folding erases the evidence). It deliberately ignores
CJK/Kana, so a legitimate Japanese+Latin title is never flagged — the
project's false-positive-averse posture for the JP market. The
phone-number scan runs on the original (non-leet-folded) text so digits
survive.

## Blocklist format (offline)

Plain text, one rule per line, pushed via MDM and read offline:

```text
host: win-prize-now.example      # block host + any subdomain
title: your computer is infected # title substring contributes to score
process: pc protector plus       # rogue-AV process (separator-insensitive)
phone: 1-800-555-0100            # known scam number (digits-only match)
bare-host.example                # bare line == host rule
# comments after '#'
```

See `examples/overlay-blocklist.txt`. Kept small and
deployment-specific — auditable by eye, not a 100k-entry ad filter.

## CLI (dry-run)

```bash
muten-overlay rules examples/overlay-blocklist.txt
muten-overlay classify examples/overlay-sample.json --rules examples/overlay-blocklist.txt
# exit: 0 Allow, 5 Suspicious, 6 Block
echo '{...OverlayWindow JSON...}' | muten-overlay classify -
```

The `classify`/`enforce` decisions are color-coded on a terminal
(Block=red, Suspicious=yellow, Allow=green) so an operator spots a Block
at a glance. Color follows the [NO_COLOR](https://no-color.org)
convention — it is emitted only when stdout is a real TTY and `$NO_COLOR`
is unset, so piped output, redirected output, and `--json` stay plain.

## What's pure vs OS-specific

`muten-overlay` is pure domain logic (`forbid(unsafe_code)`, no OS, no
network), exactly like `muten-core`. The OS-specific pieces — a window
enumerator that produces `OverlayWindow` snapshots, and a dismisser
that acts on `Verdict::Block` — live alongside the audio backends and
are wired in by the daemon. That keeps the classifier fully testable
without a desktop, and it's covered by unit + property tests
(monotonicity, threshold consistency, never-panic on arbitrary input).

## Privacy (CLAUDE.md I5)

The classifier runs entirely on-device. No URL, title, or window
metadata leaves the machine. The blocklist is a local file. There is
no runtime network surface — consistent with muten's offline-first
guarantee.

## Enforcement loop (v0.4.0 update)

The classifier's `Block` verdict is now actionable via the
`OverlayController` trait (the overlay-side analogue of
`muten-audio`'s `AudioBackend`):

```rust
pub trait OverlayController {
    fn enumerate(&self) -> Result<Vec<EnumeratedWindow>, ControllerError>;
    fn dismiss(&self, id: &WindowId) -> Result<bool, ControllerError>;
    // + name(), available()
}
```

`enforce(controller, rules)` runs one full sweep: enumerate every
window, `classify` each, and `dismiss` only the ones scoring `Block`.
`Suspicious` and `Allow` windows are reported (for the audit log) but
never dismissed. A dismiss error on one window folds into
`dismissed = false` rather than aborting the sweep.

`NullController` is the dry-run implementation used in CI, tests, and
observe-mode rollouts: it enumerates a seeded list and "dismisses" by
recording the id, so the entire detect→decide→act loop runs and is
auditable without touching a real desktop. Real OS controllers
(Win32 / macOS / X11-Wayland) implement the same trait and are wired
in by the daemon — the loop logic does not change.

`signature(&OverlayWindow)` gives the crate-defined repeat-detection
key (normalized title + source host) so the scareware `RepeatTracker`
sees "the same pop-up" consistently across callers.

### CLI

```bash
# Dry-run the whole loop over a JSON array of {id, ...OverlayWindow}:
muten-overlay enforce windows.json --rules blocklist.txt
# exit: 0 if nothing blocked, 6 if any window blocked
```

## OS controllers (v0.4.0 update 2)

Two `OverlayController` implementations now ship:

- **`NullController`** — dry-run; enumerates a seeded list and records
  dismiss requests. Used in CI, tests, and observe-mode rollouts.
- **`SubprocessController`** — real-host controller that shells out to
  a per-OS helper, the same pattern as `muten-audio`'s pactl backend.
  muten never links a window-manager API, so the crate keeps
  `#![forbid(unsafe_code)]`; any FFI lives in the swappable helper.

### Helper protocol

The helper is invoked with one of:

| Invocation | Behaviour |
|---|---|
| `<helper> --probe` | exit 0 if usable on this host, non-zero otherwise |
| `<helper> enumerate` | print a JSON array of `{id, window}` (each an `EnumeratedWindow`) to stdout, exit 0 |
| `<helper> dismiss <id>` | exit 0 = acted, exit 2 = window already gone, any other = failure (stderr = reason) |

Override the helper path with `$MUTEN_OVERLAY_HELPER`.

A reference Linux/X11 helper using `wmctrl` + `xprop` ships at
`installer/overlay-helper/muten-overlay-helper-linux.sh`. It closes
windows gracefully (WM_DELETE_WINDOW) and never kills processes —
process/registry cleanup is the EDR's job (CLAUDE.md I9). Windows
(PowerShell) and macOS (osascript/Swift) helpers follow the same
three-verb contract.

Where a field can't be determined (X11 doesn't expose "unsolicited vs
user-initiated"), the helper defaults conservatively so the classifier
biases toward `Suspicious` (review) over `Block` (dismiss) — the safe
direction for a false-positive-averse design.

## The monitor loop (v0.4.0 update 3)

`Monitor` is the daemon-side driver that runs overlay enforcement over
time and emits audit events. One `sweep()` call:

1. `enumerate()` the windows on screen (via any `OverlayController`).
2. `classify()` each; `dismiss()` the `Block` ones.
3. Record each appearance in the `RepeatTracker` and `assess()` for
   scareware (repeat flood + rogue-AV process).
4. Emit one `AuditEvent` per notable outcome:
   `overlay_blocked`, `overlay_suspicious`, `scareware_detected`,
   `overlay_sweep_error`. `Allow` outcomes are **not** audited — a
   quiet log keeps the signal visible.

The monitor holds the repeat-tracker state across sweeps, so a rogue
AV that re-pops the same window every few seconds crosses the flood
threshold and gets a `scareware_detected` event even when each
individual window is only `Suspicious`.

### Audit sink

`Monitor` depends only on a tiny `AuditSink` trait, not on a concrete
IO type — the same "depend on a trait" rule as the rest of muten. In
the full workspace the daemon wires a sink that writes to
`muten-events` JSONL and chains each line through the
`muten-audit-chain` SHA-256 hash chain, so overlay/scareware events
become tamper-evident alongside the audio enforcement events. Tests
use the in-memory `MemorySink`.

A controller error during a sweep emits `overlay_sweep_error` and the
loop continues — a transient window-manager hiccup never crashes the
daemon (same posture as the audio backend's `BackendError`).

## Tamper-evident audit log (v0.4.0 update 4)

The overlay monitor can now write a self-contained, tamper-evident
audit log via `ChainedFileSink` — a minimal SHA-256 hash chain whose
on-disk format matches `muten-audit-chain` exactly, so when the full
workspace is reassembled the two are interchangeable (a log written by
one verifies in the other).

Each event line carries `{seq, prev_hash, timestamp_ms, kind,
window_id, detail, hash}` where `hash = SHA-256(prev_hash ‖ 0x00 ‖
be(timestamp_ms) ‖ 0x00 ‖ kind ‖ 0x00 ‖ window_id ‖ 0x00 ‖ detail ‖
0x00 ‖ be(seq))` (see `SPECIFICATION.md` §8 for the normative layout).
`timestamp_ms` is part of the hash, so events cannot be backdated.
Editing or deleting any line except the last breaks the chain at a
detectable line number — the defense for threat-model **S3** (audit-log
tampering). `ChainedFileSink::open` *refuses to append onto
an already-tampered log*, and resumes cleanly from a valid one.

`Monitor::run(controller, sink, &RunConfig{interval_ms, max_sweeps},
clock, process_of, should_stop)` drives periodic sweeps. The clock and
stop-flag are injected, so the loop is fully testable without real
sleeps or signal handlers (the file-based stop flag keeps the crate
`forbid(unsafe_code)`).

### CLI

```bash
# Run 3 sweeps, write + verify a chained audit log:
muten-overlay monitor windows.json --rules blocklist.txt --sweeps 3 \
    --audit-log /var/lib/muten/overlay-audit.log
# Re-running on a tampered log refuses to append (exit 1).
```

## Helper signal fidelity (v0.4.0 update 5)

A contract-test suite (`tests/helper_contract.rs`) pins the exact JSON
each OS helper emits and asserts it deserializes and classifies
sensibly. Writing it surfaced a real limitation and a fix:

**Limitation.** The helpers can't cheaply determine every field. On a
real host, `origin` is `unknown` (no `unsolicited` +25) and `age_ms`
is `0` (no `very_new`, after the earlier fix). So a borderless
full-screen scam scores only `fullscreen + topmost = 45` on the
*heuristic alone* → Allow. **The blocklist (host/title) is therefore
the reliable detection path on real hosts**, not the soft heuristic; a
title hit lifts the same window to Suspicious/Block. This is now
documented and locked by `known_limitation_*` tests.

**Fix.** `has_close_button` was hard-coded `true` by the helpers,
silently suppressing the `no_close_button` (+25) signal — the single
strongest behavioural tell of a scam overlay. The Linux and Windows
helpers now *detect* it:

- Windows: `WS_SYSMENU` window-style bit (no system menu ⇒ no close).
- Linux/X11: EWMH `_NET_WM_ALLOWED_ACTIONS` lacking
  `_NET_WM_ACTION_CLOSE`.

Both default to `true` only when the property is genuinely absent, to
avoid over-flagging legitimate windows. With a real `has_close_button:
false` from a borderless scam, the heuristic gains the +25 it needs to
reach Suspicious without any blocklist entry.

## Wayland support (v0.4.0 update 6)

A fourth reference helper,
`installer/overlay-helper/muten-overlay-helper-wayland.sh`, covers the
2026 Linux default (Wayland on Ubuntu/Fedora/GNOME/KDE). It uses the
wlroots `wlr-foreign-toplevel-management` protocol via `lswt` or
`wlrctl`.

**Honest scope.** Wayland deliberately restricts window enumeration:

- **wlroots compositors** (Sway, Hyprland, river, Wayfire, labwc):
  the helper lists toplevel **title + app-id**, so muten's title
  blocklist works. `wlrctl` can also request a graceful close
  (dismiss).
- **GNOME (Mutter) / KDE (KWin)**: do *not* implement
  wlr-foreign-toplevel as of 2026 (KDE bug 502647 open). The helper
  PROBES FALSE there, so muten falls back to observe/NullController
  rather than pretending to see windows — same conservative posture as
  every other "can't determine it" case.

Wayland exposes no geometry/stacking to foreign clients, so the helper
reports `coverage_percent: 0`, `topmost: false`, `age_ms: 0`. The
behavioural heuristic therefore has little to work with on Wayland and
the **title blocklist is the detection path** — which is muten's
reliable real-host path regardless. `tests/helper_contract.rs` pins
the Wayland output shape and confirms a known scam title is still
caught with geometry zeroed out.

The `SubprocessController` picks the helper via `$MUTEN_OVERLAY_HELPER`
or platform default; deployments on Wayland point it at the Wayland
helper. X11 sessions (including XWayland-hosted) continue to use the
wmctrl helper.
