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

---

## カテゴリ 3: Rust システムライブラリ / crate 設計

同種OSS(高品質 Rust crate ツール): obi1kenobi/cargo-semver-checks, rust-fuzz/cargo-fuzz,
EmbarkStudios/cargo-deny, bheisler/criterion.rs, taiki-e/cargo-hack, Enselic/cargo-public-api,
crate-ci/typos, foresterre/cargo-msrv, dtolnay/* (crate 設計の規範)。

1. ✅ ★★ **cargo-deny / cargo-audit / MSRV CI / clippy -D warnings / gitleaks**
   [根拠] EmbarkStudios/cargo-deny, rustsec/rustsec(cargo-audit)。
   [muten] CI 実装済(供給鎖ゲート)。以下は未実装の品質ゲート。

2. 🔻 ★★★ **`#![deny(missing_docs)]` で公開 API doc 強制**
   [根拠] dtolnay 系 crate の規範 / docs.rs 文化。
   [muten] 多くに doc あるが強制なし。pure-core に付与し公開 API を網羅。

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

6. 🔻 ★★ **カラー出力(Block=赤/Suspicious=黄)+ NO_COLOR 準拠**
   [根拠] no-color.org 標準 / rust-cli/anstyle(anstream)/ owo-colors。
   [muten] TTY 検出 + `NO_COLOR`/`--no-color` 尊重。accent `#00C4CC`。

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
