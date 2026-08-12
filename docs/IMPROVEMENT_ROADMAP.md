# muten-overlay — 10カテゴリ別 改善ロードマップ

> 製品を10カテゴリに分類し、各10件の改善点を arxiv / GitHub / 同種ソフトの
> 調査に基づき洗い出した。各項目は **[根拠]** と **[muten現状]** を併記。
> 優先度: ★★★=次sprint候補 / ★★=中期 / ★=将来。
> 注: 一部はスコープ外を明示(過剰実装回避 I3)。

調査日: 2026-05 / 対象: muten-overlay v0.4.0 (127 tests, 8 modules, 3,166 LOC)

---

## カテゴリ1: スケアウェア / 偽AV検出ソフト (anti-scareware)

同種: Microsoft Edge Scareware Blocker, Malwarebytes, Defender SmartScreen

1. ✓DONE ★★★ **Wayland 対応**: Linux helper は wmctrl(X11専用)。Ubuntu/Fedora/GNOME/KDE は2021年からWaylandデフォルト。`ext-foreign-toplevel-list` で toplevel 列挙、process等は portal 経由。[根拠: X.Org 2024 maintenance-only, CVE-2025-62229/30/31] [現状: X11のみ]
2. ★★ **音声シグナル連携**: Edge は "loud alarm sounds" を scareware シグナルに使用。muten は音声強制crateを持つ → overlay検出時に音声enforcementと連携可能。[現状: overlay/audio分離、未連携]
3. ★★ **検出後アクションの多様化**: Edge は「full-screen解除＋無音化＋警告＋Close/Continue選択」。muten は dismiss一択。[現状: Block→dismiss]
4. ★★★ **fake blue screen / control panel** title 拡充(今sprintで追加済 ✓)
5. ★★★ **法執行なりすまし** lock-screen(今sprintで追加済 ✓)
6. ★ **コミュニティ報告ループ**: Edge は false-alarm報告でモデル改善。muten は監査ログから誤検出を学習する仕組みなし。[現状: 静的ルール]
7. ★★ **30%が報告前に被害** (Edge preview) → 早期検出のため sweep間隔の動的短縮(scam検出時に高頻度化)。[現状: 固定interval]
8. ★ **MITRE ATT&CK マッピング**: 検出を T1566(Phishing)/T1656(Impersonation) にタグ付け。[現状: dark-pattern categoryのみ]
9. ★★ **ブラウザ拡張連携**: scam の多くはブラウザ内。window-levelだけでなくブラウザ拡張からのシグナル受信API。[現状: window-levelのみ]
10. ★ **検出統計のダッシュボード**: 監査ログを集計する閲覧UI。[現状: JSONLのみ]

## カテゴリ2: テクサポ詐欺 (TSS) 検出

同種: ROBOVIC (NDSS 2017), Edge, ScamAdviser

1. ✓DONE(日本語) ★★★ **多言語 blocklist**: 現状英語title中心。phishingは22言語に分散。muten は日本市場向けなのに日本語 scam title 皆無。[根拠: arXiv:2306.05816] [現状: 英語のみ]
2. ★★ **電話番号の国際形式**: 現detector は7-15桁。国別フォーマット(日本0120, 英国+44)の精度向上。[現状: 汎用scan]
3. ★ **TSS ドメイン頻出語の自動学習**: techsupport/alert/pc等。[根拠: arXiv:1607.06891 ROBOVIC] [現状: 静的]
4. ★★ **onunload/alert フラッディング検出**: TSS は離脱阻止JS。helper が JS event を観測。[根拠: Miramirkhani 2017] [現状: window-levelで取得困難]
5. ★ **音声読み上げ検出**: TSS は "your computer has virus" を音声再生。audio crate連携。[現状: 未]
6. ★★ **偽ダウンロードボタン検出**: 複数の紛らわしいボタン。[根拠: dark pattern Interface Interference] [現状: window metadataで不可]
7. ★ **リダイレクトチェーン分析**: malvertising経由。[現状: スコープ外(URLのみ)]
8. ★★ **タイポスクワッティング host検出**: micros0ft.com 等。confusable folding を host にも適用。[根拠: NDSS 2015 typosquatting] [現状: title のみ folding]
9. ★ **証明書/WHOIS シグナル**: 新規ドメインは高リスク。[現状: スコープ外(offline)]
10. ★★ **FTC/IC3 統計の定期反映**: blocklist を四半期更新。[根拠: FBI IC3 2025] [現状: 手動]

## カテゴリ3: Rust システムライブラリ / crate設計

同種: clippy, ripgrep, tokei (高品質Rust crate)

1. ✓DONE ★★★ **`#![deny(missing_docs)]`**: 公開API全docコメント強制。lib.rs に実装済み、0警告確認済み(2026-07)。
2. ★★ **`cargo-semver-checks`**: API破壊を CI で検出。[根拠: 公開crateのSemVer遵守] [現状: なし]
3. ★★ **feature flags**: `cli`/`monitor`/`sink` を optional feature 化、ライブラリ利用者が最小依存に。[現状: 全部入り]
4. ★★★ **`no_std` 検討**: classify/rules/confusables は std不要にできる。組込み利用可能性。[現状: std前提]
5. ✓DONE ★ **`#[non_exhaustive]`**: DarkPatternCategory/Origin/ScamStage/VictimProfile/ExtractionVector/AbusedAuthority に付与済み(2026-07)。
6. ✓DONE ★★ **fuzzing (cargo-fuzz)**: fuzz/fuzz_targets/ に4ターゲット実装済み(fuzz_classify, fuzz_ruleset_parse, fuzz_verify_chain, fuzz_window_json)。
7. ✓DONE ★★ **`cargo-deny`**: 依存ライセンス/脆弱性/重複を CI gate。[現状: なし]
8. ✓DONE ★ **MSRV CI matrix**: 1.75.0 を CI で実際にテスト。[現状: 宣言のみ]
9. ✓DONE ★★ **docs.rs メタデータ**: `[package.metadata.docs.rs]` に all-features=true 設定済み(2026-07)。
10. ★ **ベンチマーク (criterion)**: classify/fold のスループット計測、回帰検出。[現状: なし]

## カテゴリ4: CLI / 開発者ツール

同種: ripgrep, fd, bat, gh

1. ★★ **シェル補完生成**: clap_complete で bash/zsh/fish/pwsh。[根拠: モダンCLI標準] [現状: なし]
2. ✓DONE(部分, v0.5.0) ★★ **`--json` 出力**: classify/scareware に `--json`(verdict + explanation を機械可読JSONで)。SIEM連携。monitor/enforce は次段。[現状: text]
3. ✓DONE ★★★ **stdin ストリーミング**: `classify --stream` で NDJSON を1行ずつ連続classify実装済み(cmd_classify_stream)。
4. ★ **man page 生成**: clap_mangen。[現状: なし]
5. ★★ **`--quiet`/`--verbose`/`-v`**: ログレベル制御。[現状: なし]
6. ★ **カラー出力**: Block=赤/Suspicious=黄(#00C4CC accent)、`--no-color`対応。[現状: プレーン]
7. ★★ **exit code 文書化**: 0/5/6/7 の意味を `--help` に明記。[現状: コード内のみ]
8. ★ **`--version` の build info**: commit hash/build date。[現状: SemVerのみ]
9. ★★ **設定ファイル**: `~/.config/muten/overlay.toml` でデフォルトrules path等。[現状: 毎回--rules]
10. ★ **progress表示**: 大量window処理時。[根拠: UX 200ms超は進捗] [現状: なし]

## カテゴリ5: ヒューリスティック分類エンジン (説明可能AI)

同種: ROBOVIC, UIGuard, YARA

1. ★★ **重み設定の外部化**: W_FULLSCREEN等をconfig化、現場でチューニング。[現状: ハードコードconst]
2. ★★★ **閾値の根拠文書化＋A/Bデータ**: BLOCK=100の妥当性を実データで検証。[根拠: ROBOVICは閾値tuned] [現状: 設計値]
3. ★ **signal の信頼度重み**: helper が確実に取れたか(origin=unknownは低信頼)で減衰。[現状: bool加点]
4. ★★ **複合ルール (AND条件)**: 「fullscreen AND phone AND no_close」を単独より高スコア。[現状: 線形加算のみ]
5. ★ **時間減衰**: 古いsignalの重み低下。[現状: なし]
6. ★★(部分) **YARA風ルール言語**: `composite:` で AND条件DSL実装済み(rules.rs)。フル正規表現/OR条件等は未対応。[現状: composite: prefix形式]
7. ★ **per-signal の誤検出率記録**: 監査ログから signal別精度を集計。[現状: なし]
8. ✓DONE(v0.5.0) ★★ **explainability出力強化**: `Verdict::explain()` が「なぜBlockか」を決定論的な自然文で返す(UIGuard的)。CLI `why:` 行 + `--json` の `explanation`。[根拠: arXiv:2308.05898] [現状: signal名リスト]
9. ★(部分) **正規表現/glob title マッチ**: `glob:` で全文ワイルドカードは実装済み(rules.rs)。title: 自体への正規表現は未対応。[現状: title:はsubstring、glob:は別ruleで全文match]
10. ★★ **ベースライン学習(任意)**: 環境の正常window分布を学習し外れ値検出。ただしML黒箱回避(I6)とのバランス要。[現状: 静的]

## カテゴリ6: 可観測性 / 改ざん耐性監査

同種: Certificate Transparency, sigstore rekor, AWS QLDB

1. ✓DONE ★★★ **Merkle tree anchoring**: merkle.rs に merkle_root/inclusion_proof/consistency_proof/verify_inclusion/verify_consistency 実装済み。README記載の「RFC 6962 Merkle root + inclusion proofs」。
2. ★★★ **root の外部アンカー**: chain head を別security domain(HSM/別ストレージ)に。同じ場所だと攻撃者が両方改竄。[根拠: weak root anchoring antipattern] [現状: 同一ファイル]
3. ★★ **forward-security (Schneier-Kelsey)**: 鍵を進化させ過去ログを将来の鍵漏洩から保護。[根拠: Schneier-Kelsey 1999] [現状: なし]
4. ★★ **OpenTelemetry export**: 監査イベントをOTel spanで。[根拠: CLAUDE.md §9.3] [現状: JSONLのみ]
5. ★ **periodic root commitment**: 定期的にroot hashを外部(syslog/不変ストレージ)へ。[現状: なし]
6. ★★ **構造化ログ必須field**: timestamp/level/service/trace_id。[根拠: CLAUDE.md §9.1] [現状: kind/window_id/detailのみ、timestamp無し]
7. ✓DONE ★★★ **timestamp 追加**: AuditEvent に timestamp_ms 追加、hash chain に組込み(改ざん検出対象)。
8. ★ **ログローテーション+チェーン継続**: 大容量時のファイル分割と chain跨ぎ検証。[現状: 単一ファイル]
9. ★★ **Prometheus metrics**: blocked/suspicious/sweep_error カウンタ。[根拠: CLAUDE.md §9.2 SLO] [現状: なし]
10. ★ **署名付きログ (sigstore)**: ed25519署名で非否認性。[根拠: sigstore rekor] [現状: hashのみ]

## カテゴリ7: OS統合 / クロスプラットフォーム window管理

同種: wmctrl, xdotool, PowerToys, Hammerspoon

1. ✓DONE ★★★ **Wayland helper**: ext-foreign-toplevel-list + portal。[根拠: 2026 default] [現状: X11のみ]
2. ★★ **macOS close-button実検出**: 現状true固定。Accessibility APIで取得。[現状: ハードコード]
3. ★★ **origin (unsolicited/user-initiated) 実検出**: foreground変化追跡。`unsolicited`+25が実機で死。[根拠: 過去sessionで判明] [現状: unknown固定]
4. ★★ **blocks_input 検出の honest化**: モーダル/入力グラブを取れるOSでは取る。[現状: false固定]
5. ★ **age_ms 実取得**: window作成時刻。very_newが実機で死。[現状: 0固定]
6. ★★ **helper の署名検証**: SubprocessControllerが起動するhelperの完全性確認。[根拠: 供給チェーン] [現状: パスのみ]
7. ★ **helper のタイムアウト**: enumerate/dismiss が固まった時。[現状: 無制限]
8. ★★ **Windows: UIAutomation**: Win32より高精度なwindow属性。[現状: Win32 P/Invoke]
9. ★ **multi-monitor 対応**: coverage計算が単一画面前提の箇所。[現状: 部分的]
10. ★★ **helper の権限最小化文書**: 各OSで必要な権限(macOS Accessibility等)をMDM配布手順に。[根拠: I9] [現状: コメントのみ]

## カテゴリ8: テキスト / Unicode処理

同種: Unicode UTS#39, Google Safe Browsing, idn-homograph検出

1. ✓DONE ★★ **host への confusable folding**: 現状titleのみ。micros0ft.com等のtyposquat。[根拠: NDSS 2015] [現状: title限定]
2. ★★★ **完全UTS#39 confusables**: 現状頻出subset。unicode-security crate検討(但し依存増)。[根拠: arXiv:2401.07867 homoglyph] [現状: 手書きsubset]
3. ★ **NFKC正規化**: 合成文字/互換文字の正規化。[現状: confusableのみ]
4. ✓DONE(v0.5.0) ★★ **mixed-script検出**: 1単語にラテン+キリル/ギリシャ混在 = `mixed_script`(+30, Sneaking)シグナル。raw title/host で fold 前に判定、CJK/かなは無視(日本語+ラテンの誤検出回避)。[根拠: UTS#39 mixed-script] [現状: fold後に消える]
5. ✓DONE(v0.5.0) ★ **zero-width文字除去**: `strip_invisibles` で ZWSP/BiDi制御を normalize_for_match と host matching の前段で除去。[現状: 未対応]
6. ✓DONE(v0.5.0) ★★ **leetspeak正規化**: `fold_leet_in_words` で v1rus→virus, 1nfected→infected。文字を含むトークンのみ(純数字=電話番号は不変)。[根拠: 一般的回避] [現状: 数字隣接で誤検出回避のみ]
7. ★ **絵文字/記号の正規化**: ⚠️等を含むtitle。[現状: 未]
8. ★★ **日本語全角/半角統一**: 全角は対応済だが、日本語blocklist追加時にカナ正規化要。[現状: 全角ラテンのみ]
9. ★ **RTL override検出**: Unicode BiDi override での偽装。[現状: 未]
10. ★★ **confusable fold の property test拡充**: mixed-script不変条件等。[現状: idempotent/length のみ]

## カテゴリ9: アンチ詐欺 / ダークパターン / 規制対応

同種: UIGuard, dark-pattern-detection, CPRA/GDPR compliance tools

1. ✓DONE(v0.5.0) ★★ **Sneaking カテゴリの signal**: `mixed_script`(homoglyph偽装=情報の偽装)を Sneaking にマッピング。5/5カテゴリに到達。[根拠: Gray et al. 2018] [現状: 4/5カテゴリのみ]
2. ★ **CPRA/FTC レポート様式出力**: 監査ログを規制提出形式に。[根拠: CPRA dark pattern定義] [現状: dark-pattern tagのみ]
3. ★★ **EU DSA / Cyber Resilience Act 整合**: EU市場向けコンプラ。[現状: 未検討]
4. ★ **dark pattern 重大度スコア**: カテゴリ別の害の重み。[根拠: Mathur et al. 2019] [現状: 有無のみ]
5. ★★ **GDPR: PII最小化の監査ログ検証**: window titleにPII混入時のマスキング。[根拠: CLAUDE.md I5] [現状: titleそのまま記録]
6. ★ **同意ダークパターン検出**: cookie banner等(overlayの一種)。[根拠: arXiv:2401.04119] [現状: scam特化]
7. ✓DONE ★★ **法執行なりすましの法域別tuning**: `authority_lure` が日本(警察庁/警視庁/国税庁/消費者庁/サイバー警察)+ 日本語強制語(警告/違反/ロック/罰金/逮捕/不正アクセス/凍結)、英語圏(Europol/HMRC/NCA/AFP/BKA/Gendarmerie)を認識。[根拠: FBI IC3 2025, IPA サポート詐欺/警察なりすまし詐欺] [旧: 英語FBI等]
8. ★ **証拠保全モード**: インシデント時にwindow情報を法的証拠として保全。[現状: 監査ログのみ]
9. ★★ **誤検出の異議申立てフロー**: 正規windowをBlockした際の記録と除外。[根拠: Edge false-alarm報告] [現状: なし]
10. ★ **アクセシビリティ配慮**: 検出UIがWCAG AA。[根拠: CLAUDE.md §7] [現状: CLIのみ]

## カテゴリ10: エンタープライズ配布 / 供給チェーンセキュリティ

同種: osquery, Wazuh, Sigstore, SLSA

1. ★★★ **署名ビルド**: Authenticode/Developer ID/GPG+Sigstore。[根拠: CLAUDE.md §8] [現状: なし]
2. ★★ **SLSA provenance**: ビルド来歴の検証可能性。[根拠: 供給チェーン] [現状: なし]
3. ★★ **SBOM生成**: cargo-cyclonedx で部品表。[根拠: CRA/EO 14028] [現状: なし]
4. ★★★ **MDM配布テンプレート**: Intune/Jamf/GPO/Ansible で helper+rules配布。[根拠: muten本体に既存パターン(muten v0.3.0)] [現状: overlayは未]
5. ★★ **blocklist の集中配信**: MDM経由でrules更新、署名付き。[現状: ローカルファイル]
6. ★ **helper のコード署名検証 (再掲7-6連携)**: 起動前に署名確認。[現状: なし]
7. ★★ **reproducible build**: 同一入力→同一バイナリ。[根拠: CLAUDE.md release skill] [現状: 未検証]
8. ✓DONE ★ **gitleaks CI**: secret混入防止。[根拠: CLAUDE.md I4] [現状: 手動確認のみ]
9. ✓DONE ★★ **Dependabot/cargo-audit CI**: 依存脆弱性の自動検出。[根拠: CLAUDE.md §5.2] [現状: なし]
10. ★ **テレメトリのopt-in**: 検出統計の匿名集計(PII最小化 I5厳守)。[根拠: Edge anonymous signals] [現状: なし]

---

## 横断的に優先度が高い改善 (★★★ 集約)

製品目標(GitHub公開可能・保守性・安全性・法的安定性)への寄与順:

1. ~~Wayland helper (C1-1, C7-1)~~ ✓実装済 — wlroots系で title検出復活、GNOME/KDEは正直にフォールバック
2. ~~AuditEvent に timestamp (C6-7)~~ ✓実装済 — hash chainに組込み
3. **Merkle anchoring + 外部root** (C6-1, C6-2) — 改ざん耐性の検証性とroot保護
4. ~~多言語(日本語)blocklist (C2-1)~~ ✓実装済 — 21 JP title、IPA/トレンドマイクロ/消費者庁出典
5. **署名ビルド + SBOM + CI脆弱性スキャン** (C10-1,3,9) — 公開・配布の前提
6. ~~CLI `--json` 出力 (C4-2)~~ ✓実装済(classify/scareware) — SIEM連携の実用性
7. ~~host への confusable folding (C8-1)~~ ✓実装済 — typosquat digit fold + homoglyph
8. ~~回避耐性: mixed-script / zero-width / leetspeak (C8-4/5/6, C9-1)~~ ✓実装済(v0.5.0) — homoglyph偽装の主要回避をオフラインで封じる、Sneaking到達
9. ~~説明可能性: `Verdict::explain()` (C5-8)~~ ✓実装済(v0.5.0) — 自然文の判定理由

## スコープ外と判断したもの (I3: 過剰実装回避)

- **computer vision / ML黒箱** — Edgeは使うが muten は I6(説明可能)・offline・forbid unsafe・推論なしを堅持。blocklist最新化で代替
- **ネットワーク/証明書/WHOIS シグナル** — offline-first 原則。別レイヤの責務
- **プロセスkill/レジストリ改変** — I9(検出・監査のみ)。除去はEDRの責務
- **ブロックチェーン監査** — Merkleで十分、consensus latencyは過剰

## 出典
arXiv: 1607.06891 (TSS/ROBOVIC), 2308.05898 (UIGuard), 2401.07867 (homoglyph),
2306.05816 (multilingual phishing), 2605.00065 (Merkle tamper-evident),
2308.05557 (forward-integrity logging), 2401.04119 (dark patterns).
業界: Microsoft Edge Scareware Blocker (2025), FBI IC3 2025, FTC, Gray et al. CHI 2018,
Crosby-Wallach NDSS 2009, Schneier-Kelsey 1999, Wayland protocols, SLSA, Sigstore.

---

## 実装ログ追記 (CI / 供給チェーン — C10-8/9 + C3-7/8)

GitHub Actions CI を新設(`.github/workflows/ci.yml`)。製品目標「公開可能」
の前提である自動 gate を整備:

- **test job (stable)**: rustfmt --check / clippy -D warnings / test
  --all-targets / doc --no-deps。ローカル inner loop と完全一致。
- **msrv job (1.75.0)**: 宣言した rust-version を実際に build+test し、
  「宣言だけ」を排除(C3-8)。
- **supply-chain job**: cargo-audit(RUSTSEC脆弱性)+ cargo-deny
  (ライセンス allow-list / banned crates / source 制限、`deny.toml`)
  + gitleaks(secret 混入、`.gitleaks.toml`)。CLAUDE.md §5.2 / I4。
- **helpers job**: 4 OS helper の `sh -n` + shellcheck + PSScriptAnalyzer。

`deny.toml`: MIT/Apache-2.0/BSD/ISC/Unicode/Zlib のみ許可、wildcard
依存禁止、crates.io 限定。`.gitleaks.toml`: 偽サポート電話番号
(scam sample)と SHA-256 digest を allowlist。

全 config は TOML/YAML 構文検証済。CI が動く stable では tools が
build される(コンテナの 1.75 では cargo-deny の edition2024 要件で
ローカル実行不可だが、CI は stable で問題なし)。残: 署名ビルド
(Authenticode/Developer ID/GPG+Sigstore, C10-1)、SBOM(C10-3)。
