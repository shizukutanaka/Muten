# muten-overlay 改善カタログ 2026-H2 — 10カテゴリ × 10改善点

> 製品を **10カテゴリ**に分類し、各カテゴリごとに **arxiv.org + GitHub** から
> 関連情報を集めて **10件ずつ**改善点を洗い出す総覧。`IMPROVEMENT_ROADMAP.md`
> (2026-05)と `RESEARCH_IMPROVEMENTS_2026H1.md`(2026-06)の統合・更新版。
>
> 対象: muten-overlay **v0.5.0**(162 tests) / 調査日: 2026-06
> 凡例: 状態 = ✅実装済 / 🔻計画(roadmap既出) / 🆕新規 ; 優先度 ★〜★★★
> 各項目: **[根拠]**(arXiv ID / GitHub repo)/ **[muten]**(現状と適用)。
>
> 不変の制約(全項目遵守): オフライン / window メタデータ上の純粋関数 /
> per-frame CV なし / `#![forbid(unsafe_code)]` / 説明可能な加算スコア /
> 誤検出回避(observe-first) / 検出・監査のみ(プロセスkill・レジストリ改変なし)。

## カテゴリ一覧

1. スケアウェア / 偽AV検出 (anti-scareware)
2. テクニカルサポート詐欺 (TSS) 検出
3. Rust システムライブラリ / crate 設計
4. CLI / 開発者ツール
5. ヒューリスティック分類エンジン (説明可能 AI)
6. 可観測性 / 改ざん耐性監査
7. OS 統合 / クロスプラットフォーム window 管理
8. テキスト / Unicode 処理
9. アンチ詐欺 / ダークパターン / 規制対応
10. エンタープライズ配布 / 供給チェーンセキュリティ

調査手法注記: サンドボックスから arxiv.org/github.com への直接 WebFetch は
HTTP 403 となる場合があり、特定事項は WebSearch 抽出 + 安定した一次標準で
相互確認した。arXiv ID / GitHub repo は実在を可能な範囲で個別確認している。

<!-- 以降、各カテゴリを batch で追記 -->

---

## カテゴリ 1: スケアウェア / 偽AV検出 (anti-scareware)

同種OSS: CybercentreCanada/CCCS-Yara, Yara-Rules/rules, jarelllama/Scam-Blocklist,
iam-py-test/my_filters_001。同種製品: Edge Scareware Blocker, Malwarebytes Browser Guard。

1. ✅ ★★★ **repeat-flood + rogue-AV プロセス信号**
   [根拠] CybercentreCanada/CCCS-Yara — FakeAV/scareware を「偽AVを装い金銭を要求」と分類。
   [muten] `assess()` が repeat + process を実装済。CCCS-Yara の FakeAV ファミリ名で
   `process:` 族を拡充できる(✅基盤 / 拡充は🆕)。

2. 🆕 ★★★ **コミュニティ scam blocklist の蒸留取り込み(MDM 配信)**
   [根拠] jarelllama/Scam-Blocklist — dnstwist/URLCrazy/DGA + Google Search で新規詐欺ドメインを
   日次自動収集。
   [muten] offline-first を維持しつつ、こうした大規模リストを muten の「焦点を絞った小型 host
   blocklist」に蒸留する変換器を提供し MDM 配布。検出パスにライブ取得は持ち込まない。

3. 🆕 ★★★ **`sudden_fullscreen_takeover` 信号(突発全画面)**
   [根拠] Edge Scareware Blocker (2025) の中核 behavioral tell(CV と独立)/ PP3D arXiv:2510.18465。
   [muten] `origin=unsolicited ∧ coverage→~100% ∧ age_ms 小 ∧ topmost` を加算信号化。blocklist 遅延を ML なしで補う。

4. 🆕 ★★★ **`input_trap` 信号(Keyboard/Pointer-Lock 悪用)**
   [根拠] arXiv:2509.13186(JS-capability で fullscreen+lock が支配的詐欺クラスタ)/ Chrome 131 permission gate。
   [muten] `blocks_input ∧ coverage 高 ∧ topmost` を高重み複合信号 `input_trap` に昇格、`explain()` 対応。

5. 🆕 ★★ **ClickFix / fake-CAPTCHA タイトル族**
   [根拠] MS Security Blog 2025-08(+517% / 侵入47%)— "verify you are human" / "press Win+R"。
   [muten] title blocklist 族 + `clickfix_instruction` 信号(JP 含む)。純 blocklist + 加算。

6. 🆕 ★★ **antimalware hosts フィードのオフライン蒸留**
   [根拠] iam-py-test/my_filters_001(antimalware_hosts.txt — scam/phishing/PUP/stalkerware)。
   [muten] #2 と同様、host 族の供給源として変換器に取り込む(オフライン)。

7. 🔻 ★★ **検出後アクションの多様化(全画面解除＋無音化＋警告)**
   [根拠] Edge Scareware Blocker は検出時に exit-fullscreen + silence-audio + warn。
   [muten] 現状 dismiss 一択。muten の音声強制 crate と連携し overlay 検出時に無音化(roadmap C1-2/3)。

8. 🆕 ★ **カウントダウン/タイマー文言キュー**
   [根拠] Securelist browser-lockers — 罰金 locker は countdown で緊急性を演出。
   [muten] title に countdown 文言(`\d+:\d{2}` + urgency 語)で弱信号。confusable fold 後照合。

9. 🔻 ★ **MITRE ATT&CK タグ付け(T1566 Phishing / T1656 Impersonation)**
   [根拠] Sigma/ATT&CK 検知-as-code の標準実務。
   [muten] 監査イベントに technique タグ(roadmap C1-8、C6 の Sigma 連携と合流)。

10. 🔻 ★ **検出時の sweep 間隔動的短縮**
    [根拠] Edge preview「30% が報告前に被害」→ 早期検出が要。
    [muten] scam 検出時に高頻度化(roadmap C1-7)。`RunConfig.interval_ms` の動的化。

Sources(C1): https://github.com/CybercentreCanada/CCCS-Yara ,
https://github.com/jarelllama/Scam-Blocklist , https://github.com/Yara-Rules/rules ,
https://github.com/iam-py-test/my_filters_001 , arXiv:2510.18465, arXiv:2509.13186,
https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-...,
https://blogs.windows.com/msedgedev/2025/01/27/stand-up-to-scareware-with-scareware-blocker/

---

## カテゴリ 2: テクニカルサポート詐欺 (TSS) 検出

同種OSS: jarelllama/Scam-Blocklist, scamsniffer/scam-database, mradamdavies/number-skid,
GitHub topics: phone-scam / malicious-domains。研究: ROBOVIC, "Dial One for Scam"。

1. ✅ ★★★ **電話番号-in-alert 信号 + 日英 blocklist**
   [根拠] Miramirkhani et al. "Dial One for Scam" (arXiv:1607.06891) — 番号は最強 tell。
   [muten] 実装済。以下で拡充。

2. 🆕 ★★ **既知不正番号のオフライン辞書**
   [根拠] mradamdavies/number-skid(Amazon/Microsoft なりすまし番号)+ GitHub phone-scam topic。
   [muten] 既知 scam 番号の小型オフライン辞書を `phone:` ルールとして追加し、一致で高重み。
   一般 phone-number 信号(形状ベース)を補完。

3. 🆕 ★★ **暗号資産リカバリ(再被害)詐欺ファミリ**
   [根拠] scamsniffer/scam-database(Web3 phishing ホスト)/ FBI IC3 2024(暗号資産で最大損失)。
   [muten] host/title 族 `recover (crypto|funds)`, `crypto recovery` 等 + scamsniffer 由来 host を蒸留。

4. 🆕 ★★ **タイポスクワット host 検出(dnstwist 系アルゴリズム)**
   [根拠] jarelllama/Scam-Blocklist は dnstwist/URLCrazy で typosquat/doppelganger/IDN homograph を生成。
   [muten] 現 host confusable fold に加え、omission/insertion/transposition/doppelganger の
   オフライン生成・照合(既知ブランドの近傍生成 → blocklist 化)。

5. 🆕 ★★ **リモートアクセスツール lure(process 族・文脈増幅)**
   [根拠] FTC/IC3 2024 — AnyDesk/TeamViewer/UltraViewer/LogMeIn/RustDesk/ScreenConnect へ誘導。
   [muten] `process:` 族 `remote_access_tool` を文脈増幅(単独 Block でなく偽アラート共起で加点)。

6. 🆕 ★ **電話番号の国際形式精度向上(0120 / +44 等)**
   [根拠] roadmap C2-2 / 各国フォーマット。
   [muten] `contains_phone_number` を国別フォーマット認識に拡張(7–15桁汎用 → 国別重み)。

7. 🆕 ★★ **離脱阻止 JS(onbeforeunload/alert flood)を helper シグナル化**
   [根拠] Miramirkhani 2017 — TSS は離脱阻止 JS を多用。
   [muten] helper が JS event/連続 alert を観測し `exit_blocking` メタデータとして供給 → 加算信号。

8. 🆕 ★ **TSS 頻出語の自動学習(オフライン)**
   [根拠] ROBOVIC (arXiv:1607.06891) — techsupport/alert/pc 等の頻出語。
   [muten] 監査ログ/既知 host から頻出 n-gram を抽出し候補 title パターンを IT に提案(静的運用維持)。

9. 🆕 ★ **IDN homograph host 検出(skeleton)**
   [根拠] Scam-Blocklist の IDN homograph 検出 / ShamFinder arXiv:1909.07539。
   [muten] mixed-script 信号に加え UTS#39 `skeleton(host)` 衝突照合(C8 と合流)。

10. 🔻 ★ **FTC/IC3 統計の四半期反映**
    [根拠] FBI IC3 2024 Report。
    [muten] blocklist 族を四半期で更新する運用(roadmap C2-10)。

Sources(C2): https://github.com/jarelllama/Scam-Blocklist ,
https://github.com/scamsniffer/scam-database , https://github.com/mradamdavies/number-skid ,
https://github.com/topics/phone-scam , arXiv:1607.06891, arXiv:1909.07539, arXiv:2509.13186,
https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf
