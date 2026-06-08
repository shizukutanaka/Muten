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

3. ✅ ★★★ **`sudden_fullscreen_takeover` 信号(突発全画面)** — 実装済(v0.5.0, +5)
   [根拠] Edge Scareware Blocker (2025) の中核 behavioral tell(CV と独立)/ PP3D arXiv:2510.18465。
   [muten] `origin=unsolicited ∧ coverage→~100% ∧ topmost ∧ 0<age_ms<1000` を bounded 加算信号として実装、
   `explain()`「seized the full screen the instant it appeared」対応。blocklist 遅延を ML なしで補う。
   bounded(+5): 内容 tell が無ければ 85 = Suspicious 止まり。

4. ✅ ★★★ **`input_trap` 信号(Keyboard/Pointer-Lock 悪用)** — 実装済(v0.5.0, +5)
   [根拠] arXiv:2509.13186(JS-capability で fullscreen+lock が支配的詐欺クラスタ)/ Chrome 131 permission gate。
   [muten] `blocks_input ∧ coverage 高 ∧ topmost` を複合信号 `input_trap`(ForcedAction)として実装、
   `explain()`「locks the screen by trapping keyboard/mouse」対応。重みは bounded(+5): 内容/出自の
   tell が無い純粋 lock shape は 95 = Suspicious 止まりで、kiosk/試験ロックダウンの誤Block を回避。

5. ✅ ★★ **ClickFix / fake-CAPTCHA タイトル族** — 実装済(v0.5.0)
   [根拠] MS Security Blog 2025-08(+517% / 侵入47%)— "verify you are human" / "press Win+R"。
   [muten] 18 件の title blocklist 族(例: "verify you are human", "press win+r") + 構造信号
   `clickfix_instruction`(weight 20, ForcedAction): alert_shaped ∧ normalized title が
   キーボード命令/CAPTCHA フレーミングを含む。leet/homoglyph 回避は normalize_for_match で吸収。
   alert_shaped ガードで正規 reCAPTCHA タブ(フルスクリーンでも modal でもない)を FP 除外。
   新公開関数 `confusables::has_clickfix_instruction()`。(C1-5 ✓DONE)

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

---

## カテゴリ 3: Rust システムライブラリ / crate 設計

同種OSS(高品質 Rust crate ツール): obi1kenobi/cargo-semver-checks, rust-fuzz/cargo-fuzz,
EmbarkStudios/cargo-deny, bheisler/criterion.rs, taiki-e/cargo-hack, Enselic/cargo-public-api,
crate-ci/typos, foresterre/cargo-msrv, dtolnay/* (crate 設計の規範)。

1. ✅ ★★ **cargo-deny / cargo-audit / MSRV CI / clippy -D warnings / gitleaks**
   [根拠] EmbarkStudios/cargo-deny, rustsec/rustsec(cargo-audit)。
   [muten] CI 実装済(供給鎖ゲート)。以下は未実装の品質ゲート。

2. ✅ ★★★ **`#![deny(missing_docs)]` で公開 API doc 強制** — 実装済(v0.5.0)
   [根拠] dtolnay 系 crate の規範 / docs.rs 文化。
   [muten] 全公開 API(struct field / enum variant / trait / const)に doc を追加し
   `#![deny(missing_docs)]` を lib.rs に付与。`cargo doc --no-deps` が警告ゼロ。(C3-2 ✓DONE)

3. 🔻 ★★ **cargo-semver-checks で API 破壊を CI 検出**
   [根拠] obi1kenobi/cargo-semver-checks — rustc 機構で semver 違反を検出、CI Action 同梱。
   [muten] fleet 自動化が消費する公開 API/blocklist スキーマの破壊を PR + pre-publish で阻止。

4. 🔻 ★★★ **feature flags(cli/monitor/sink/controller を optional 化)**
   [根拠] taiki-e/cargo-hack — feature 組合せの網羅ビルド/テスト。
   [muten] 現状「全部入り」。ライブラリ利用者が最小依存に。cargo-hack で feature-combo を CI 検証。

5. 🔻 ★★★ **no_std 純検出コア分離**
   [根拠] no_std crate 設計の標準(core/alloc 分割)。
   [muten] classify/rules/confusables は std 不要化可。`muten-core`(no_std/forbid/deny-docs)を分離。

6. 🔻 ★★ **cargo-fuzz で parser をファズ + OSS-Fuzz**
   [根拠] rust-fuzz/cargo-fuzz — 「parser は高価値ファズ対象」、forbid(unsafe) なら sanitizer 無効で高速。
   [muten] `fuzz/` に blocklist/メタデータ/署名 bundle parser target。no-panic・有界資源を assert。

7. 🆕 ★★ **cargo-mutants で test スイートの実効性検証**
   [根拠] sourcefrog/cargo-mutants — コードに mutation を注入しテストが捕捉するか測定。
   [muten] property test 162 件の「見逃し」を定量化。スコアリング/parser のテスト網羅を補強。

8. 🆕 ★ **cargo-public-api で公開 API スナップショット**
   [根拠] Enselic/cargo-public-api — 公開 API 差分を CI で可視化。
   [muten] semver-checks と併用し、意図しない API 露出/削除をレビューで検出。

9. 🔻 ★ **docs.rs メタデータ + criterion ベンチ**
   [根拠] bheisler/criterion.rs(統計的ベンチ・回帰検出)。
   [muten] `[package.metadata.docs.rs]` で all-features doc 生成。classify/fold のスループット回帰検出。

10. 🆕 ★ **`#[non_exhaustive]` + typos CI**
    [根拠] crate-ci/typos(誤字 CI)/ 標準の非破壊 enum 設計。
    [muten] Decision/DarkPatternCategory/ScarewareDecision に `#[non_exhaustive]`、doc/コメントに typos。

Sources(C3): https://github.com/obi1kenobi/cargo-semver-checks ,
https://github.com/rust-fuzz/cargo-fuzz , https://github.com/EmbarkStudios/cargo-deny ,
https://github.com/bheisler/criterion.rs , https://github.com/taiki-e/cargo-hack ,
https://github.com/sourcefrog/cargo-mutants , https://github.com/Enselic/cargo-public-api ,
https://github.com/crate-ci/typos , https://github.com/foresterre/cargo-msrv

---

## カテゴリ 4: CLI / 開発者ツール

同種OSS: clap-rs/clap (clap_complete, clap_mangen), console-rs/indicatif, BurntSushi/ripgrep,
sharkdp/fd, sharkdp/bat, rust-cli/anstyle (anstream), owo-colors/owo-colors。標準: NO_COLOR, clig.dev。

1. ✅ ★★ **classify/scareware `--json` + stdin(`-`)+ 終了コード + `why:` 行**
   [根拠] NDJSON/JSON 機械可読慣行。
   [muten] 実装済。以下は未実装の UX/連携。

2. 🔻 ★★ **monitor/enforce の `--json` / NDJSON ストリーミング出力**
   [根拠] ripgrep `--json`(NDJSON, 1イベント1行)。
   [muten] SIEM へ sweep 結果を逐次 NDJSON で。enforce のバッチ JSON も。

3. 🔻 ★★★ **stdin ストリーミング classify(helper 出力を pipe で連続処理)**
   [根拠] ripgrep/fd の stream-first 設計。
   [muten] 現状 enforce は JSON 配列一括。1行1 window の NDJSON を連続 classify。

4. 🔻 ★★ **シェル補完生成(bash/zsh/fish/pwsh)**
   [根拠] clap-rs/clap_complete(+ clap_complete_nushell)。
   [muten] `completions` サブコマンド or build script で生成・配布。

5. 🔻 ★ **man page 生成**
   [根拠] clap-rs/clap_mangen。
   [muten] roff man page を生成し配布物に同梱。

6. ✅ ★★ **カラー出力(Block=赤/Suspicious=黄)+ NO_COLOR 準拠** — 実装済(v0.5.0)
   [根拠] no-color.org 標準 / rust-cli/anstyle(anstream)/ owo-colors。
   [muten] `std::io::IsTerminal` で TTY 検出 + `NO_COLOR` 尊重(依存追加なし、手書き ANSI)。
   classify/enforce の decision を着色(Block=赤/Suspicious=黄/Allow=緑)。pipe/`--json` は素のまま。
   `should_colorize`/`paint` を単体テスト。226 tests。(Roadmap C4-6 ✓DONE)

7. 🔻 ★★ **`--quiet`/`--verbose`/`-v` ログレベル + 構造化ログ**
   [根拠] clig.dev ガイドライン / tracing-rs。
   [muten] 監査は別経路、診断ログのレベル制御を追加。

8. 🔻 ★★ **終了コードの `--help` 明記 + exitcode 規約**
   [根拠] clig.dev「終了コードを文書化せよ」。
   [muten] 0/5/6/7 の意味を help と man に明記。

9. 🔻 ★ **`--version` に build info(commit hash / date)**
   [根拠] vergen 系のビルド時メタ埋め込み慣行。
   [muten] SemVer に加え commit/date(再現ビルドの SOURCE_DATE_EPOCH と整合)。

10. 🔻 ★ **設定ファイル(~/.config/muten/overlay.toml)+ 進捗表示**
    [根拠] console-rs/indicatif(進捗)/ XDG base dir 慣行。
    [muten] 既定 rules パス等を設定化。大量 window 処理時に進捗(>200ms)。

Sources(C4): https://github.com/clap-rs/clap (clap_complete, clap_mangen) ,
https://github.com/console-rs/indicatif , https://github.com/BurntSushi/ripgrep ,
https://github.com/rust-cli/anstyle , https://github.com/owo-colors/owo-colors ,
https://no-color.org , https://clig.dev

---

## カテゴリ 5: ヒューリスティック分類エンジン (説明可能 AI)

同種OSS: VirusTotal/yara-x (Rust 製 YARA), SigmaHQ/sigma, open-policy-agent/opa (rego),
zmap/zgrab 系の signal 設計。研究: UIGuard (arXiv:2308.05898), ROBOVIC (arXiv:1607.06891)。

1. 🔻 ★★★ **閾値(BLOCK=100 / SUSPICIOUS=50)の根拠文書化 + 実データ A/B**
   [根拠] ROBOVIC は閾値を実データで tuning。
   [muten] 現状は設計値。監査ログ(後述 C6)から signal 別発火率を集計し閾値を検証。

2. 🔻 ★★★ **複合ルール(AND 条件)を一級市民に**
   [根拠] YARA/Sigma は boolean 式(AND/OR/NOT)で表現力を担保。
   [muten] 現状は線形加算のみ。`coverage 高 ∧ topmost ∧ blocks_input ∧ !close`(= H1 survey の
   `coercive_overlay`)等の AND ルールを加算より高重みで。説明可能性は維持。

3. 🔻 ★★ **重み設定の外部化(現場チューニング)**
   [根拠] Sigma/OPA は検知ロジックを config/policy として外部化。
   [muten] `W_FULLSCREEN` 等を MDM 配布の署名付き config 化(C10 の signed config と合流)。

4. 🆕 ★★ **YARA-X 風ルール言語の検討(Rust 製・safe)**
   [根拠] VirusTotal/yara-x — YARA の Rust 全面書き直し、メモリ安全・高速。
   [muten] blocklist を prefix:形式から表現力ある DSL へ。ただし I3(過剰実装回避)と要バランス、
   まずは #2 の AND ルールで十分か評価。

5. 🔻 ★★ **signal の信頼度重み(helper 取得確度で減衰)**
   [根拠] 不確実な観測を低重み化する標準的アプローチ。
   [muten] `origin=unknown` / `age_ms=0`(取得不能)は低信頼 → 加点を減衰。bool 加点を確度付きに。

6. 🔻 ★★ **explainability 出力強化(自然文)**
   [根拠] UIGuard (arXiv:2308.05898) は「なぜ」を提示。
   [muten] `Verdict::explain()` 実装済(✅)。複合ルール発火時の文面を拡張(#2 と合流)。

7. 🆕 ★ **per-signal の誤検出率を監査ログから集計**
   [根拠] 検知-as-code の評価実務(precision/recall を継続測定)。
   [muten] 監査ログ + IT の誤検出フィードバックから signal 別精度を集計し重み見直しに供給(静的運用維持)。

8. 🔻 ★ **正規表現/glob title マッチ(substring の先)**
   [根拠] YARA はワイルドカード/正規表現を許可。
   [muten] 現状 substring。`call .* now` 等の限定的 glob を安全に(ReDoS 回避の有界マッチ)。

9. 🔻 ★ **時間減衰 / ベースライン外れ値(任意・ML黒箱回避)**
   [根拠] 異常検知の標準だが muten は I6(説明可能)堅持。
   [muten] 環境の正常 window 分布を「説明可能な統計」(出現頻度の閾値)として外れ値弱信号化。黒箱は使わない。

10. 🆕 ★★ **複合ルールの property test(単調性・境界の保証)**
    [根拠] proptest による不変条件検証(既存 162 tests の延長)。
    [muten] AND ルール導入時に「各 suspicious 信号でスコア単調」「閾値整合」を property test で固定。

Sources(C5): https://github.com/VirusTotal/yara-x , https://github.com/SigmaHQ/sigma ,
https://github.com/open-policy-agent/opa , arXiv:2308.05898, arXiv:1607.06891

---

## カテゴリ 6: 可観測性 / 改ざん耐性監査

同種OSS: google/trillian, sigstore/rekor, transparency-dev/merkle, C2SP/C2SP,
SigmaHQ/sigma, open-telemetry/opentelemetry-rust。研究: Crosby-Wallach (USENIX 2009),
RFC 9162, Schneier-Kelsey (TISSEC 1999), arXiv:2308.05557, arXiv:2605.00065。

1. ✅ ★★★ **timestamp 付き linear SHA-256 監査チェーン**
   [根拠] tamper-evident logging の基礎。
   [muten] `sink.rs` 実装済(改行/削除/backdate 検出)。以下で検証性・root 保護を強化。

2. 🔻 ★★★ **Merkle history tree で O(n)→O(log n) inclusion/consistency proof**
   [根拠] Crosby-Wallach (USENIX 2009) / RFC 9162 / transparency-dev/merkle, google/trillian。
   [muten] 各行 hash を CT 葉 `H(0x00‖entry)` として再利用、right-edge のみ保持で追記 O(log n)。
   `inclusion_proof(seq)` / `consistency_proof(old,new)` 追加。forbid(unsafe)/no_std 両立。

3. 🔻 ★★★ **外部 root アンカーを C2SP checkpoint(signed note)で offline+MDM**
   [根拠] C2SP/C2SP tlog-checkpoint(sigstore/Sunlight 本番)/ sigstore/rekor の STH。
   [muten] sweep 末尾に `origin\ntree_size\nbase64(root)` + Ed25519 署名を別 security domain に保存、
   MDM が consistency proof 検証で truncation/改竄を中央検出(roadmap C6-2 解消)。

4. 🆕 ★★★ **canonical serialization(JCS/CBOR)で hash 入力を確定**
   [根拠] RFC 8785 (JCS) / RFC 8949 §4.2 (CBOR canonical) — CT が葉入力をバイト厳密化する理由。
   [muten] 現 `link_hash` は `serde_json::to_vec(detail)` 依存 → JSON キー順序差で偽 chain break の懸念
   (workspace audit-chain との interchangeable 制約を破壊)。準バグ、先行価値高。round-trip property test 追加。

5. 🔻 ★★ **forward-secure MAC によるキー進化**
   [根拠] Schneier-Kelsey (TISSEC 1999) / arXiv:2308.05557, 2605.00065。
   [muten] `k_{i+1}=SHA256(k_i)`、各行 `mac`、`k_i` ゼロ化。seed は OS 鍵ストア封入。鍵漏洩後の遡及改竄耐性。

6. 🆕 ★★ **4イベント種別の OTel + Sigma 二重マッピング(offline export)**
   [根拠] open-telemetry/opentelemetry-rust / SigmaHQ/sigma / OTel semantic conventions。
   [muten] `kind`→`event.name`, `seq`→ULID, file/OTLP-file exporter で offline。Sigma ルール同梱(ATT&CK タグ)。

7. 🔻 ★★ **Prometheus メトリクス(検証性を SLI 化)**
   [根拠] rekor/CT は STH 発行間隔・witness 鮮度を運用指標化。
   [muten] `muten_audit_events_total{kind}`, `_chain_verify_seconds`, `_last_checkpoint_age_seconds`,
   `_chain_broken{file}`(即アラート), `_tree_size`。pull 専用 textfile collector で offline。

8. 🆕 ★★ **追記耐久性 + truncation/クラッシュ区別**
   [根拠] Schneier-Kelsey の既知弱点=末尾削除 / Balloon (ePrint 2015/007)。
   [muten] 1行=単一 O_APPEND write + checkpoint 前のみ fsync。`verify_chain` に「末尾半端行=truncation
   (回復可能)」variant を追加し正常クラッシュと改竄を区別。

9. 🔻 ★ **ログローテーション + チェーン継続**
   [根拠] RFC 9162 consistency proof / Sunlight tiled-log。
   [muten] ローテ境界を封印 checkpoint で締め、新 genesis を旧 root に連結。`verify_chain` をマルチファイル対応。

10. 🔻 ★ **署名付き checkpoint で非否認性(sigstore 流)**
    [根拠] sigstore/rekor(periodic 署名)/ in-toto。
    [muten] 個別イベント署名は過大 → checkpoint を device key(#5 共用)で Ed25519 署名。

Sources(C6): https://github.com/google/trillian , https://github.com/sigstore/rekor ,
https://github.com/transparency-dev/merkle , https://github.com/C2SP/C2SP ,
https://github.com/open-telemetry/opentelemetry-rust , https://github.com/SigmaHQ/sigma ,
arXiv:2308.05557, arXiv:2605.00065, RFC 9162, RFC 8785

---

## カテゴリ 7: OS 統合 / クロスプラットフォーム window 管理

同種OSS: AccessKit/accesskit (AT-SPI/UIAutomation, Rust), leexgone/uiautomation-rs,
autopilot-rs/autopilot-rs, rust-windowing/winit, smithay (Wayland), jordansissel/xdotool,
microsoft/PowerToys, Hammerspoon/hammerspoon。

1. ✅ ★★★ **Wayland helper(ext-foreign-toplevel-list)+ X11/macOS/Windows helper**
   [根拠] wlroots/ext-foreign-toplevel-list プロトコル。
   [muten] 実装済。以下で helper のシグナル忠実度を上げる。

2. 🔻 ★★ **macOS close-button / modal を Accessibility API で実取得**
   [根拠] AccessKit/accesskit — Unix=AT-SPI, macOS/Windows=各 a11y API で role/state を公開。
   [muten] `has_close_button` は現状 true 固定。a11y の AXCloseButton/AXModal で honest 化。

3. 🔻 ★★ **Windows: UIAutomation で高精度 window 属性**
   [根拠] leexgone/uiautomation-rs / microsoft windows-rs UIAutomation。
   [muten] Win32 P/Invoke より UIA の ControlType/IsModal/IsTopmost が高精度。helper を UIA 化。

3-b. 🔻 ★★ **AT-SPI で Linux の role/modal/close を取得**
   [根拠] AccessKit Unix adapter(AT-SPI D-Bus via zbus)。
   [muten] Wayland では toplevel 列挙に加え AT-SPI で modal/close affordance を補完。

4. 🔻 ★★ **origin(unsolicited/user-initiated)の実検出(foreground 変化追跡)**
   [根拠] 過去 session で `unsolicited`+25 が実機で死(常に unknown)。
   [muten] helper が直近の user input → window 出現の時間相関を取り `origin` を honest 化。

5. 🔻 ★★ **blocks_input(モーダル/入力グラブ)の honest 化**
   [根拠] UIA `IsModal` / X11 grab / Wayland のフォーカス制約。
   [muten] 取得可能な OS では false 固定をやめ実値供給。`input_trap`(C1-4)の前提。

6. 🔻 ★ **age_ms 実取得(window 作成時刻)**
   [根拠] `_NET_WM_*` / UIA / a11y のタイムスタンプ。
   [muten] very_new / instant_takeover(C1-3)の前提。0 固定をやめる。

7. 🔻 ★★ **helper の署名検証(起動前の完全性確認)**
   [根拠] 供給チェーン(C10-1 と合流)。
   [muten] `SubprocessController` が helper を exec する前に ed25519/cosign blob 検証。

8. 🔻 ★ **helper のタイムアウト(enumerate/dismiss のハング対策)**
   [根拠] 堅牢な subprocess 制御の基本。
   [muten] 現状無制限。`Command` に deadline、超過で sweep_error 監査。

9. 🔻 ★ **multi-monitor 対応(coverage 計算)**
   [根拠] 複数ディスプレイ環境での被覆率は単一画面前提だと誤る。
   [muten] coverage を「アクティブ画面」基準に厳密化、helper が monitor geometry を供給。

10. 🔻 ★ **helper 権限最小化の文書(各 OS の必要権限)**
    [根拠] macOS Accessibility / Windows UIA の権限要件。
    [muten] MDM 配布手順に必要権限(macOS Accessibility 許可等)を明記(I9)。

Sources(C7): https://github.com/AccessKit/accesskit , https://github.com/leexgone/uiautomation-rs ,
https://github.com/autopilot-rs/autopilot-rs , https://github.com/rust-windowing/winit ,
https://github.com/jordansissel/xdotool , https://github.com/microsoft/PowerToys

---

## カテゴリ 8: テキスト / Unicode 処理

同種OSS: unicode-org/icu4x (Rust ICU), unicode-rs/unicode-security, mpkorstanje/tr39-confusables,
unicode-rs/unicode-normalization。標準: UTS#39, UTS#46, RFC 8785。

1. ✅ ★★ **confusable folding(title/host)+ mixed-script + zero-width/BiDi strip + leetspeak + 全角**
   [根拠] UTS#39 confusables(focused subset)。
   [muten] v0.5.0 実装済。以下で UTS#39 アルゴリズムへ昇格。

2. ✅ ★★★ **UTS#39 `skeleton()` 衝突照合(既知ブランド表)** — 実装済(v0.5.0)
   [根拠] UTS#39 §4 / mpkorstanje/tr39-confusables / unicode-rs/unicode-security。
   [muten] `confusables::skeleton()` + 内蔵 `KNOWN_BRANDS`(20)で `brand_impersonation`
   信号(+40, InterfaceInterference)。host ラベルの skeleton がブランドに一致しリテラルでない時に発火。
   `раура1.com`(→paypal)発火、本物 `paypal.com` は不発火(FP ガード)。zero-config の homograph 検出。

3. ✅ ★★★ **Whole-Script Confusable 信号(mixed-script の盲点)** — 実装済(v0.5.0, +30)
   [根拠] UTS#39 §5 / unicode-rs/unicode-security の `whole_script_confusable`。
   [muten] `confusables::has_whole_script_confusable()` + `whole_script_confusable` 信号(+30,
   Sneaking)。全 Cyrillic `ѕсоре`(→"scope")等を捕捉。URL は label 単位でチェック(TLD の
   Latin 文字による誤判定を防ぐ)。FP ガード: ASCII fold を持たない文字(п, θ…)を含む
   legitimate なテキストは発火しない。191 tests。(Roadmap C8-3 ✓DONE)

4. 🔻 ★★★ **Restriction-Level 連続スコア化**
   [根拠] UTS#39 §5.2 / ICU SpoofChecker RESTRICTION_LEVEL。
   [muten] script 集合からレベル算出、緩いほど段階加点。加算モデルに自然適合。

5. 🔻 ★★★ **BiDi 制御の「存在=信号」化(Trojan Source、isolate 含む)**
   [根拠] Trojan Source (arXiv:2111.00169, USENIX Sec'23)。
   [muten] strip 前に検出し `bidi_control_present` 信号化。正規 UI には出ない高信頼。

6. ✅ ★★ **Mixed-Number-System 検出** — 実装済(v0.5.0, +20)
   [根拠] ICU SpoofChecker MIXED_NUMBERS。
   [muten] `digit_system()` で数字を numbering system 別分類し、`has_mixed_number_systems()` で
   1トークン内 2種混在を `mixed_number_systems` 信号化(+20, Sneaking)。ASCII と全角は同一
   system 扱いで JP の全角数字を誤検出しない(FP ガード)。216 tests。(Roadmap C8-6 ✓DONE)

7. ✅ ★★ **Combining-Mark / Default-Ignorable 乱用検出** — 実装済(v0.5.0, +20)
   [根拠] UTS#39 INVISIBLE / unicode general-category。
   [muten] `is_combining_mark()` + `has_excessive_combining_marks()` で 1 基底文字に
   3 個以上の結合マークが積まれた "Zalgo" を `excessive_combining_marks` 信号化(+20, Sneaking)。
   閾値 3 が FP ガード(ベトナム語/アラビア語/Indic は 1-2 個まで)。223 tests。(Roadmap C8-7 ✓DONE)
   [補足] default-ignorable は既存 `strip_invisibles` が網羅。
   [muten] 結合マーク2連・基底なし結合マーク・Default_Ignorable で信号。純関数。

8. ✅ ★★ **NFKC 正規化と confusable-fold の不一致を弱信号化** — 実装済(v0.5.0, +20)
   [根拠] unicode-rs/unicode-normalization(NFKC)/ confusables.txt と NFKC は31文字相違。
   [muten] 囲み文字(Enclosed Latin Letters U+24B6-U+24E9: Ⓐ-Ⓩ/ⓐ-ⓩ)を `fold_char()` に
   追加し、`normalize_for_match` 経由のブロックリスト照合が自動的に恩恵を受ける。
   `confusables::has_compat_alpha()` で raw 文字列の存在を `compat_chars_present` 信号化
   (weight +20, Sneaking)。201 tests。(Roadmap C8-8 ✓DONE)

9. 🆕 ★★ **icu4x への移行検討(完全 UTS#39、ただし依存増・no_std 影響を評価)**
   [根拠] unicode-org/icu4x — no_std 対応の本格 Unicode、データ駆動。
   [muten] 現状は手書き subset。完全性 vs 依存増/バイナリ肥大/forbid(unsafe) を I3 で衡量。
   まずは #2–#7 を dependency-free 実装、必要時のみ icu4x。

10. 🔻 ★ **confusable fold の property test 拡充(mixed-script 不変条件)**
    [根拠] proptest(既存)。
    [muten] skeleton 冪等性 / whole-script 判定 / restriction-level 単調性を property test 固定。

Sources(C8): https://github.com/unicode-org/icu4x , https://github.com/unicode-rs/unicode-security ,
https://github.com/mpkorstanje/tr39-confusables , https://github.com/unicode-rs/unicode-normalization ,
https://unicode.org/reports/tr39/ , arXiv:2111.00169

---

## カテゴリ 9: アンチ詐欺 / ダークパターン / 規制対応

同種OSS: DarkDialogs/OpenScience(cookie ダイアログ 10 種検出), dibollinger/CookieBlock-Consent-Crawler,
simtape/dark_pattern_research。研究: UIGuard (arXiv:2308.05898), UMBRA (arXiv:2603.21515),
real-time deceptive patterns (arXiv:2411.07441), Mathur et al. 2019。規制: FTC / CPRA / EU DSA。

1. ✅ ★★ **dark-pattern 5分類タグ(Gray et al. 2018)+ mixed_script→Sneaking**
   [根拠] Gray et al. CHI 2018。
   [muten] v0.5.0 で 5/5 カテゴリ到達。以下で severity と規制整合を強化。

2. 🔻 ★★ **カテゴリ別 severity スコア(害の重み)**
   [根拠] Mathur et al. 2019 / UMBRA は違法性の重い順に位置づけ。
   [muten] Forced Action/Sneaking=高、Nagging=低の severity 重みを加算へ反映。

3. 🆕 ★★ **規制条項タグ付け(FTC / CPRA / EU DSA)**
   [根拠] FTC 2024 dark-pattern report / CPRA「ダークパターン経由の同意は無効」/ EU DSA Art.25。
   [muten] 各検出に `FTC-disguised-ads` / `CPRA-consent` / `DSA-Art25` タグを `explain()`/監査へ付加。

4. 🆕 ★★ **進化型ダークパターン(DP11–DP19)の語彙取り込み**
   [根拠] UMBRA (arXiv:2603.21515) — pay-to-opt-out / 取消障壁 / fake opt-out を 99% で検出。
   [muten] overlay 文脈に該当する語彙(fake opt-out / 取消障壁の文言)を title 信号化。

5. 🆕 ★ **同意/cookie ダークパターン検出器の知見転用**
   [根拠] DarkDialogs/OpenScience(10 種自動検出)/ CookieBlock-Consent-Crawler(OpenWPM)。
   [muten] overlay の一種としての consent ダークパターン(accept 強調/reject 秘匿)を将来スコープに。

6. 🆕 ★ **リアルタイム deceptive pattern 検出の特徴量転用**
   [根拠] arXiv:2411.07441 — 測定可能な HCI 特徴でリアルタイム検出。
   [muten] CV を使わず、muten メタデータで近似できる特徴(被覆・モーダル・close 秘匿)を抽出。

7. 🔻 ★★ **誤検出の異議申立てフロー(正規 window の除外記録)**
   [根拠] Edge の false-alarm 報告ループ。
   [muten] 正規 window を Block した際の記録 + MDM 配布の allowlist 除外(監査に残す)。

8. 🆕 ★ **GDPR: 監査ログの PII 最小化/マスキング**
   [根拠] CLAUDE.md I5 / GDPR データ最小化。
   [muten] window title に PII が混入し得る → 監査記録時に既知 PII パターンをマスク(オフライン)。

9. 🆕 ★ **CPRA/FTC レポート様式出力**
   [根拠] CPRA dark-pattern 定義 / 規制提出様式。
   [muten] 監査ログを規制提出形式(カテゴリ + 条項タグ + 証拠)にエクスポート。

10. 🆕 ★ **法執行なりすましの法域別 tuning**
    [根拠] FBI IC3 2024 / 各国ブランド(警察庁・FBI 等)。
    [muten] locker/法執行なりすまし語彙を法域別に(JP/EN/…)。confusable fold 後照合。

Sources(C9): https://github.com/DarkDialogs/OpenScience ,
https://github.com/dibollinger/CookieBlock-Consent-Crawler ,
https://github.com/simtape/dark_pattern_research ,
arXiv:2308.05898, arXiv:2603.21515, arXiv:2411.07441, arXiv:2406.01608

---

## カテゴリ 10: エンタープライズ配布 / 供給チェーンセキュリティ

同種OSS: sigstore/cosign, jedisct1/minisign, theupdateframework/specification,
CycloneDX/cyclonedx-rust-cargo, slsa-framework/slsa-github-generator, osquery/osquery, wazuh/wazuh。
研究: Ladisa et al. SoK (Oakland 2023), arXiv:2409.05014。規制: EU CRA, EO 14028。

1. 🆕 ★★★ **per-OS helper スクリプトを署名し exec 前に検証**
   [根拠] sigstore/cosign(`sign-blob --bundle`、オフライン検証)/ Ladisa et al. SoK。
   [muten] helper(bash/PS)は exec される未署名コード=最弱リンク。daemon が spawn 前に
   オフライン検証(埋込 pubkey、Rekor 不要)、不一致で exec 拒否。

2. 🆕 ★★★ **MDM 配布 blocklist の署名 + オフライン検証 + anti-rollback**
   [根拠] theupdateframework(オフライン鍵・閾値・freshness/rollback 保護)。
   [muten] blocklist を署名 blob 化、pinned pubkey + 単調増加 `version` + `valid_until` を parse 前検証。
   高保証に 2-of-N 閾値。config が検出判断を駆動する以上 integrity 必須。

3. 🆕 ★★ **runtime 検証器は minisign/ed25519 で forbid(unsafe)・zero-network 維持**
   [根拠] jedisct1/minisign(cosign の着想元、ed25519、network 不要)。
   [muten] publish=cosign(Rekor 公開記録)、runtime=埋込 pure-Rust ed25519。依存の unsafe は cargo-deny gate。

4. 🔻 ★★ **SBOM(CycloneDX)+ SLSA provenance を CI 成果物に**
   [根拠] CycloneDX/cyclonedx-rust-cargo / slsa-framework/slsa-github-generator(L2–L3)。
   [muten] `cargo cyclonedx --format json`(出荷 feature)+ signed provenance を Release 添付。CRA 対応。

5. 🔻 ★★ **再現ビルド(determinism ゲート)**
   [根拠] reproducible-builds.org/rust / RFC 3127 trim-paths。
   [muten] `[profile.release] trim-paths="all"` + `SOURCE_DATE_EPOCH` + toolchain 固定、CI で2回ビルド diff。

6. 🔻 ★★★ **MDM 配布テンプレート(Intune/Jamf/GPO/Ansible)**
   [根拠] osquery/osquery, wazuh/wazuh の配布手順。
   [muten] helper + rules + 鍵 を各 MDM で配布するテンプレートを同梱(roadmap C10-4)。

7. 🆕 ★ **no_std 純検出コアで trusted/攻撃面を最小化**
   [根拠] secure-design(arXiv:2406.10109 系)。
   [muten] `muten-core` を no_std 化し IO/exec/署名境界を明示(C3-5 と合流)。

8. ✅ ★★ **cargo-audit + cargo-deny + gitleaks CI ゲート**
   [根拠] rustsec/rustsec, EmbarkStudios/cargo-deny。
   [muten] 実装済。SBOM/SLSA/署名で拡張。

9. 🔻 ★ **検証可能リリース文書(CRA 整合 SECURITY.md)**
   [根拠] EU CRA(SBOM 作成/維持/10年保持 + 脆弱性対応、2027-12 期限)/ osquery の GPG 鍵公開。
   [muten] `SECURITY.md` + 「リリース検証」doc(公開鍵・検証手順・SBOM 配置・脆弱性 SLA・CRA チェックリスト)。

10. 🔻 ★ **テレメトリの opt-in(匿名集計、PII 最小化)**
    [根拠] Edge anonymous signals / CLAUDE.md I5。
    [muten] 検出統計の匿名集計を opt-in、PII 最小化を厳守(オフライン既定)。

Sources(C10): https://github.com/sigstore/cosign , https://github.com/jedisct1/minisign ,
https://github.com/theupdateframework/specification , https://github.com/CycloneDX/cyclonedx-rust-cargo ,
https://github.com/slsa-framework/slsa-github-generator , https://github.com/osquery/osquery ,
https://github.com/wazuh/wazuh , arXiv:2409.05014

---

## 横断的 次sprint候補(★★★ 集約)

製品目標(公開可能・保守性・安全性・法的安定性)への寄与順:

1. **検出メタデータ複合信号**(C1-3/4, C5-2)— `sudden_fullscreen_takeover` / `input_trap` /
   `coercive_overlay`。既存メタデータの結合のみ、CV不要・blocklist 遅延に強い最高 ROI。
2. **UTS#39 昇格**(C8-2/3/4/5)— skeleton 衝突 / whole-script / restriction-level / BiDi-present。
3. **ClickFix 等 新詐欺ファミリ blocklist**(C1-5, C2-3/5)— 2025 最大トレンド + GitHub 由来の蒸留。
4. **監査の検証性と root 保護**(C6-2/3/4)— Merkle + C2SP checkpoint + canonical serialization(準バグ)。
5. **未署名攻撃面の封鎖**(C10-1/2, C7-7)— helper / blocklist の署名 + オフライン検証 + anti-rollback。
6. **crate 品質ゲート**(C3-3/4/6)— semver-checks / feature flags + cargo-hack / fuzz。

## スコープ外(I3: 過剰実装回避)

- **CV / ML 黒箱**(PP3D/Edge の画像モデル, LLM 推論)— I6 説明可能・offline・推論なしを堅持。
  behavioral tell はメタデータで再現(C1-3/4)。
- **network / 証明書 / WHOIS / リアルタイム reputation** — offline-first。abuse TLD/host は
  オフライン蒸留リストで近似(C1-2, C2-4)。
- **プロセス kill / レジストリ改変** — 検出・監査のみ(除去は EDR)。
- **ブロックチェーン / consensus 監査** — Merkle + signed checkpoint で split-view/truncation を十分カバー。
- **完全 UTS#39 テーブル即時導入** — icu4x は依存増/肥大ゆえ #2–#7 を dependency-free 実装後に衡量(C8-9)。

## 出典総覧

各カテゴリ末尾の Sources を参照。arXiv: 2510.18465, 2509.13186, 2401.09824, 1607.06891,
1909.07539, 2111.00169, 2308.05898, 2603.21515, 2411.07441, 2406.01608, 2306.05816,
2308.05557, 2605.00065, 2409.05014。GitHub: jarelllama/Scam-Blocklist, CybercentreCanada/CCCS-Yara,
scamsniffer/scam-database, VirusTotal/yara-x, SigmaHQ/sigma, google/trillian, sigstore/rekor,
transparency-dev/merkle, C2SP/C2SP, AccessKit/accesskit, unicode-org/icu4x,
unicode-rs/unicode-security, DarkDialogs/OpenScience, sigstore/cosign, jedisct1/minisign,
CycloneDX/cyclonedx-rust-cargo, slsa-framework/slsa-github-generator, obi1kenobi/cargo-semver-checks,
rust-fuzz/cargo-fuzz, EmbarkStudios/cargo-deny ほか。標準: UTS#39, RFC 9162, RFC 8785, C2SP, NO_COLOR,
SLSA v1.0, EU CRA。

---

## 追補 (Delta) 2026-06 #2 — net-new ソース

前パスの 10×10 後に見つかった**正味新規**の出典のみ。該当カテゴリに追記する形で記録。

D1. 🆕 ★★★ **CypherLoc 型 browser-lock scareware(scanner/sandbox 回避)** → C1
   [根拠] Barracuda Threat Spotlight 2026-05 — CypherLoc は 2026 年に 280万件、
   「encrypted, condition-based execution inside the browser」でスキャナ/サンドボックスを回避し
   偽テクサポへ誘導。
   [muten] 重要含意: コンテンツ走査を回避されても **window レベルの tell(browser-lock /
   全画面 / no-close / 偽サポート番号)は残る** → muten のメタデータ先行アプローチの優位を裏付け。
   `input_trap`(C1-4)/`sudden_fullscreen_takeover`(C1-3)を最優先に。CypherLoc 由来 host/title 族も追加。

D2. 🆕 ★★ **LLM スキャム検出は敵対的入力で破綻 → muten の no-ML を正当化** → C5
   [根拠] arXiv:2412.00621(Adversarial Scam Detection: LLM Vulnerabilities)/ arXiv:2511.01746
   (Scam Shield)— 敵対的に改変した scam メッセージが LLM 検出器を回避。
   [muten] 透明な加算スコア(I6)は敵対的プロンプト/難読化で「説明不能に崩れる」ことがない設計優位。
   設計判断 ADR の根拠として記録(ML 黒箱を採らない理由を強化)。回避耐性は C8 の正規化で対応。

D3. 🆕 ★★ **長期保持監査の post-quantum 耐性(crypto-agile 署名)** → C6 / C10
   [根拠] arXiv:2512.00110(PQ-Resilient Audit Evidence for Long-Lived Regulated Systems)/
   arXiv:2312.16322(PQ Sanitizable Signature for Audit Logs)/ NIST FIPS 204 ML-DSA
   (署名 2.4kB / 公開鍵 1.3kB)/ C2SP checkpoint は ML-DSA-44 を既に許容。
   [muten] muten の SHA-256 hash chain は **既に PQ 安全**(ハッシュベース)。一方 checkpoint/
   MAC 署名(Ed25519, C6-3/10, C10-1/2)は PQ 非対応 → CRA の 10 年保持を見据え、
   署名方式を **crypto-agile**(Ed25519 ↔ ML-DSA を algorithm-id で切替)に設計。検出パスは不変・offline。

D4. 🆕 ★ **不確実性下のしきい値運用(adversarial 環境での FP/FN バランス)** → C5
   [根拠] arXiv:2412.00621 系は「敵対的 drift で精度が劣化」と指摘。
   [muten] 静的しきい値の定期的な実データ検証(C5-1)を回避トレンド(CypherLoc 等)に合わせて
   四半期レビューする運用を明記。observe-first を維持し FP 増を防ぐ。

Sources(Delta): https://blog.barracuda.com/2026/05/20/threat-spotlight-cypherloc-scareware ,
arXiv:2412.00621, arXiv:2511.01746, arXiv:2512.00110, arXiv:2312.16322, NIST FIPS 204 (ML-DSA)。

> 収束メモ: 検出ファミリ(CypherLoc)と監査の PQ 耐性は正味新規だったが、構造的な
> 改善カテゴリ(10×10)はほぼ網羅済み。以降の調査は「新規脅威ファミリの blocklist 反映」と
> 「新標準(PQC 等)への追従」という**増分更新**が中心になる見込み。
