# muten-overlay 改善点調査 2026-H1 — 同種ソフト + arXiv ベース

> 既存 `IMPROVEMENT_ROADMAP.md`(2026-05 調査)の続編。v0.4.0→**v0.5.0** で実装済の
> 項目(Wayland / 監査チェーン timestamp / 日本語ブロックリスト / host confusable
> folding / phone-number 信号 / **mixed-script 信号** / **zero-width・BiDi strip** /
> **leetspeak fold** / **Verdict::explain()** / **classify・scareware `--json`** /
> dark-pattern 5分類 / CI supply-chain gate)は除外し、**同種ソフト + 直近(2023–2026)の
> arxiv.org 文献**から新規/具体化できる改善点のみを洗い出した。
>
> 調査日: 2026-06 / 対象: muten-overlay v0.5.0 (162 tests)
> 各項目: **[根拠]**(出典)/ **[muten適用]**(制約内の具体化)/ 優先度 ★〜★★★ /
> **NEW**(ロードマップ未記載) or **GROUNDING**(既存plan に根拠・アルゴリズムを肉付け)。
>
> **不変の制約**(全項目が遵守): オフライン / window メタデータ上の純粋関数 /
> per-frame CV なし / `#![forbid(unsafe_code)]` / 説明可能な加算スコア /
> 誤検出回避(observe-first) / 検出・監査のみ(プロセスkill・レジストリ改変なし)。

調査手法注記: サンドボックスから arxiv.org/unicode.org への直接 WebFetch は HTTP 403 で
全滅したため、各論文の特定事項は WebSearch 抽出スニペット + 安定した一次標準
(UTS#39, RFC 9162, C2SP, Schneier-Kelsey)で相互確認した。新規 arXiv ID
(2510.18465, 2509.13186, 2605.00065, 2603.21515 等)は検索で実在を個別確認済み。

---

## カテゴリ A: TSS / スケアウェア / 詐欺オーバーレイ検出

同種: Microsoft Edge Scareware Blocker (2025), Malwarebytes Browser Guard, PP3D。
中核知見: **最も費用対効果が高い改善は、muten が既に収集しているメタデータ
(`blocks_input` / `has_close_button` / `coverage_percent` / `topmost` / `origin` /
`age_ms`)を新たな「複合ルール」で結合すること** — 新入力ゼロ・CV不要・blocklist遅延に強い。

1. **★★★ NEW — `input_trap` 信号(Keyboard-Lock / Pointer-Lock 悪用)**
   [根拠] Chrome for Developers / textslashplain (2023–25): browser-locker は Keyboard
   Lock API(Esc 長押しでしか全画面解除不可)+ Pointer Lock(カーソル秘匿)で操作を奪う。
   Chrome 131 は両 API を permission gate 化。arXiv:2509.13186 は「fullscreen + lock API」
   が JS-capability クラスタリングの支配的詐欺クラスタと報告。
   [muten適用] `blocks_input ∧ coverage 高 ∧ topmost` を generic `blocks_input` より
   高重みの名前付き複合信号 `input_trap` に昇格。`explain()` が「ページがキーボード/
   マウスを拘束」と説明可能。helper が pointer/keyboard grab を取得できる OS では honest 化。

2. **★★★ NEW — `sudden_fullscreen_takeover` / `instant_takeover`(突発全画面 × 低 age)**
   [根拠] Edge Scareware Blocker (2025) の中核 behavioral tell は「突発的な全画面奪取」
   (CV モデルとは独立)。PP3D (arXiv:2510.18465) も「scam overlay はページ読込から ms 単位で
   出現し topmost を維持」。blocklist は新規ドメインに数時間〜数日遅れる。
   [muten適用] 既存 `age_ms` を活用: `origin=unsolicited ∧ coverage→~100% ∧ age_ms 小 ∧
   topmost` を加算信号化。**blocklist 遅延を ML なしで補う zero-day 対策**。
   (※ helper の `age_ms` / `origin` 実取得が前提 — ロードマップ C7-3/5 と合流。)

3. **★★★ NEW — `coercive_overlay` 複合カテゴリ(強制操作の論理積)**
   [根拠] UIGuard/AppRay の Forced Action/Obstruction、cookie 研究の reject 秘匿:
   deceptive-UI は単一属性でなく**組合せ**で成立する、が一貫知見。
   [muten適用] `coverage 高 ∧ topmost ∧ blocks_input ∧ !has_close_button ∧ age_ms 小` を
   新カテゴリ `CoerciveOverlay` として強い加算。fake update / scareware に直撃、純粋合成信号。

4. **★★★ NEW — ClickFix / fake-CAPTCHA タイトル族**
   [根拠] Microsoft Security Blog (2025-08) / Splunk: ClickFix は H1-2025 で +517%、
   侵入の 47%。"Verify you are human" / "I am not a robot" / 偽 Cloudflare・reCAPTCHA、
   "press Win+R then Ctrl+V" を指示。文字列が安定し観測容易。
   [muten適用] title blocklist 族 + `clickfix_instruction` 信号を追加(`press win\+r`,
   `verify you are human`, `i am not a robot`, JP 等)。純 blocklist + 加算。

5. **★★ NEW — 暗号資産リカバリ(再被害)詐欺 族**
   [根拠] FBI IC3 2024(60代以上が暗号資産で $2.8B 損失)+ CFTC/WA-DFI 2025 勧告:
   "recover your stolen crypto in 24–48h" / "CryptoForensics" 等の recovery-fraud 族。
   [muten適用] title/host 族追加: `recover (your )?(crypto|funds|bitcoin)`,
   `crypto recovery`, `fund recovery`, `chargeback specialist`。2024 最大損失トレンド反映。

6. **★★ NEW — リモートアクセスツール lure(process-name 族・文脈増幅)**
   [根拠] FTC/IC3 2024: TSS が AnyDesk/TeamViewer/UltraViewer/LogMeIn/RustDesk/
   ScreenConnect へ誘導。
   [muten適用] `process:` 族 `remote_access_tool` を追加。単独 Block でなく(正規利用あり)、
   **unsolicited な偽アラート窓と共起したときにスコア増幅**する combined-rule(監査寄り)。

7. **★★ NEW — 疑わしい TLD / なりすまし host サブ信号**
   [根拠] MS ClickFix blog: scam overlay は `.shop .live .icu .online` や dashed lookalike
   (`access-ssa-gov.es`)に集中。arXiv:2509.13186: 951k ページ→11k クラスタ、ドメイン高速ローテ。
   [muten適用] 既存 confusable fold に加え、(a) abuse 多発 TLD の小型オフライン加重リスト、
   (b) `microsoft`/`gov`/`paypal` 等を**非登録可能ラベル**として含む host パターンを加算信号化。

8. **★ NEW — locker / 罰金 偽アラート 多言語語彙拡充**
   [根拠] Securelist browser-lockers + MS/Malwarebytes: "Access to this PC has been
   blocked" / "Windows Defender Security Center" / 警察罰金 + カウントダウン 等の安定族。
   [muten適用] title blocklist に locker/fine 族 + JP 等価表現を追加(既存 phone-number 信号を補完)。

9. **★ NEW — 通知許可 / 当選 sweepstakes カテゴリタグ**
   [根拠] PP3D (arXiv:2510.18465) は "notification stealing" / "fake lottery" を独立操作カテゴリ化。
   [muten適用] `you('ve| have) won` / `claim your prize` / `enable notifications to continue`
   を title/host 族化し既存 dark-pattern 分類でタグ付け。

---

## カテゴリ B: Unicode / homoglyph 回避 + ダークパターン

中核知見: 現状の folding は「正規化して見る」段階。**UTS#39 の skeleton/restriction-level/
whole-script** という確立アルゴリズムへ昇格すると、現 mixed-script 信号の盲点を埋められる。
ICU SpoofChecker (MIXED_NUMBERS/INVISIBLE/WHOLE_SCRIPT/RESTRICTION_LEVEL) を
dependency-free サブセットとして再実装可能。

1. **★★★ NEW — UTS#39 `skeleton()` 衝突照合(既知ブランド表)**
   [根拠] UTS#39 §4 + ShamFinder (arXiv:1909.07539): skeleton は各文字を confusable 代表字へ
   写像した中間形で、見た目が同じ2文字列は同一 skeleton。
   [muten適用] `skeleton(host)` を計算しオフライン同梱の小型「正規ブランド表」の skeleton と
   完全一致照合 → `skeleton_collides_known_brand`(高重み)。`skeleton("раура1.com")==
   skeleton("paypal.com")`。現 folding の自然な発展。

2. **★★★ NEW — Whole-Script Confusable 信号(mixed-script の盲点)**
   [根拠] UTS#39 §5: `"ѕсоре"`(全 Cyrillic)は mixed-script 検査を**素通り**する典型スプーフ。
   [muten適用] 「ASCII を1文字も含まず、全文字が Latin confusable 集合へ写像可能」なら
   `whole_script_confusable` 発火。mixed-script とは独立の純関数で全置換ドメインを捕捉。

3. **★★★ NEW — Restriction-Level 連続スコア化**
   [根拠] UTS#39 §5.2: ASCII-Only→Single-Script→Highly→Moderately→Minimally→Unrestricted。
   Latin+Cyrillic/Greek/Cherokee 混在は特に危険。
   [muten適用] script 集合から restriction level を算出する純関数 → レベルが緩いほど段階的に
   加算。単一 boolean でなく**連続的で説明可能なスコア**として加算モデルに自然適合。

4. **★★★ NEW — BiDi 制御の「存在=信号」化(Trojan Source、isolate を含む)**
   [根拠] Trojan Source (arXiv:2111.00169, USENIX Sec'23): 危険文字は override/embedding/
   **isolate (U+2066-9)**。論文核心は「多くの防御が isolate を素通りさせた」点。
   [muten適用] 既に strip 済だが、**strip 前に存在検出して `bidi_control_present` 信号化**
   (特に isolate 系)。正規 UI タイトルにはまず出ない高信頼信号。説明文に明記。

5. **★★ NEW — Mixed-Number-System 検出**
   [根拠] ICU `MIXED_NUMBERS`: ASCII `0-9` + Arabic-Indic `٠-٩` + 全角 + Bengali 等の混在は
   正規テキストでほぼ起きない難読化指標(leetspeak とは別軸)。
   [muten適用] 数字を Unicode ブロック別に分類、2種以上混在で `mixed_number_systems` 発火。
   FP 極小で安全。

6. **★★ NEW — Combining-Mark / Default-Ignorable 乱用検出**
   [根拠] UTS#39 INVISIBLE: 同一基底への結合マーク重複、基底なし結合マーク列、
   Default_Ignorable 群(U+115F, U+2065, U+FFA0…)は視覚難読化・カウント水増しの兆候。
   [muten適用] (a) 結合マーク2連 (b) 基底非存在の結合マーク (c) Default_Ignorable 存在 で
   `combining_mark_abuse` 信号。general-category 小サブセットで純粋実装。

7. **★★ NEW — NFKC と confusable-fold の「不一致」を弱信号化**
   [根拠] confusables.txt と NFKC は別物(互換分解 vs 視覚衝突)で 31 文字食い違う。
   ChatPhishDetector (arXiv:2306.05816) も正規化後にブランド照合。
   [muten適用] host/title に NFKC を純関数追加し**「NFKC 後に形が変わったこと自体」**を
   弱信号 `compatibility_chars_present`(`ⓟⓐⓨⓟⓐⓛ`, 合字, 上付き等を捕捉)。

8. **★★ NEW — ダークパターン「重大度スコア」+ 規制タグ付け**
   [根拠] UIGuard 後継 (arXiv:2308.05898) は18類型を多段化。UMBRA (arXiv:2603.21515) は
   DP11–DP19 の進化型(pay-to-opt-out / 取消障壁 / fake opt-out)を 99% 精度で検出。
   規制(FTC 2024 / CPRA / EU DSA / 提案中 Digital Fairness Act)は違法性の重い順に位置づけ。
   [muten適用] 既存5分類に (a) カテゴリ別 **severity 重み**(Forced Action/Sneaking=高)を
   加算へ反映、(b) 規制条項タグ(`FTC-disguised-ads`/`CPRA-consent`/`DSA-Art25`)を説明へ付加。

9. **★ NEW — 多言語ソーシャルエンジニアリング語彙(緊急/権威)辞書信号**
   [根拠] ChatPhishDetector (arXiv:2306.05816): 22 言語でブランド偽装 + SE 技法(緊急/恐怖/
   権威)を高精度検出。「英語のみ辞書は 10–40% すり抜け」。
   [muten適用] 緊急/脅迫/権威キーフレーズの小型オフライン多言語辞書(confusable fold 後照合)
   → `urgency_lure_phrase` 信号。FP 回避のため低〜中重み・監査寄り。

---

## カテゴリ C: 改ざん耐性監査 / 可観測性

対象コード: `src/sink.rs`(linear SHA-256 chain、`verify_chain` は O(n))。
ロードマップ C6 の planned 項目に根拠・アルゴリズムを肉付けし、未記載の新規も追加。
最優先 3 点(①Merkle ②外部 checkpoint ③canonical serialization)が「O(log n) 検証・
root 保護・workspace 相互運用」というコア制約に直結。

1. **★★★ GROUNDING — history tree で O(n)→O(log n) inclusion/consistency proof**
   [根拠] Crosby-Wallach (USENIX Sec 2009) の history tree。RFC 9162(CT 2.0)が標準化:
   葉 `H(0x00‖entry)`/内部 `H(0x01‖L‖R)`(ドメイン分離で二次プリイメージ防御)。inclusion
   proof は `⌈log2 n⌉` ハッシュ → 80M でも ~27×32B ≈ 864B。
   [muten適用] 既存 JSONL 不変で各行 hash を CT 葉ハッシュとして再利用。"right edge"
   (各レベル未確定右端、`⌈log2 n⌉` 個)のみ保持で追記 O(log n)。`inclusion_proof(seq)` /
   `consistency_proof(old,new)` を追加。`forbid(unsafe_code)`・no_std 両立。linear chain
   (全削除検出)と Merkle(効率的証明 + 過去 root 一貫性)は相補的。

2. **★★★ GROUNDING — 外部 root アンカーを C2SP checkpoint(signed note)形式で offline+MDM へ**
   [根拠] C2SP `tlog-checkpoint`(sigstore/Sunlight 本番実証): checkpoint = 3行 signed note
   (origin / tree_size / base64(root))+ Ed25519 署名。自己完結・オフライン検証可、split-view 防止。
   [muten適用] sweep バッチ末尾/N イベント毎に checkpoint を生成し **(a)** 監査ファイルとは
   別 security domain(別パーミッション)に保存(C6-2 "weak root anchoring" 解消)、**(b)** MDM
   の read-only テレメトリで逆同期 → 中央で truncation/履歴改竄を consistency proof 検出。
   書き出しは hot path 外。

3. **★★★ NEW — canonical serialization の厳密化(検証決定性・相互運用のバグ予防)**
   [根拠] CT/RFC 9162 が葉入力をバイト厳密に定義するのは再シリアライズ非依存のため。
   [muten適用] 現 `link_hash` は `serde_json::to_vec(detail)` で hash 計算 →
   **JSON キー順序/数値表現/Unicode エスケープが書込と検証で食い違うと偽陽性 chain break**
   の懸念(「workspace audit-chain と interchangeable」制約を壊す)。detail の hash 入力を
   **JCS(RFC 8785)** か **CBOR canonical(RFC 8949 §4.2)** で確定。空 detail の扱い
   (書込=実値 / verify=`json!({})`)も一致させ、proptest に「write→read→verify ラウンドトリップ
   不変」を追加。**(robustness 寄りの準バグ — 優先度高)**

4. **★★ NEW — 追記耐久性 + truncation/クラッシュ区別**
   [根拠] Schneier-Kelsey の既知弱点 = 末尾削除(truncation)。Balloon (ePrint 2015/007) は
   永続性を正当性条件に含む。
   [muten適用] 現 `emit` は fsync せず、部分書込(改行前クラッシュ→半端 JSON)が次回 verify で
   chain break 扱い=正常クラッシュと改竄が区別不能。(a) 1行=単一 `O_APPEND` write + checkpoint
   直前のみ `fsync`(group commit)、(b) `verify_chain` に「最終行が途中で切れた」= truncation
   (回復可能)variant を追加し再 open 時に半端行を切詰めて再開。

5. **★★ GROUNDING — forward-secure MAC によるキー進化**
   [根拠] Schneier-Kelsey (ACM TISSEC 1999): `A_i=H(A_{i-1})` で MAC 鍵進化、使用後即破棄 →
   時刻 t の侵害でも t 以前を改竄/偽造不可。arXiv:2308.05557 / 2605.00065 が resource 制約下で
   key-evolution + Merkle 併用を推奨。
   [muten適用] SHA-256 のみで実装可: seed を OS 鍵ストア(Keychain/DPAPI/keyutils)に封入、
   各 sweep で `k_{i+1}=SHA256(k_i)`、各行に `mac` 付与、`k_i` ゼロ化。純ハッシュ chain に無い
   「鍵漏洩後の遡及改竄耐性」を追加。

6. **★★ NEW — 4イベント種別の OTel + Sigma 二重マッピング(offline export)**
   [根拠] OTel semantic conventions: 監査イベントは LogRecord + `event.name`、重複排除に
   `log.record.uid`(ULID 推奨)。Sigma はベンダー非依存検知ルール。
   [muten適用] (a) 各 `kind`→`event.name=security.overlay.blocked` 等、`seq`→ULID、
   `timestamp_ms`→ns 化、file/OTLP-file exporter で offline export(hot path 外)。
   (b) 4 種別の Sigma ルールを同梱し MITRE ATT&CK T1566/T1656 タグ(C1-8 と合流)。detection-as-code。

7. **★★ NEW — 可観測性 SLO メトリクス(検証性そのものを監視)**
   [根拠] rekor/CT は STH 発行間隔・witness 鮮度を運用指標化。
   [muten適用] Prometheus(C6-9 具体化): `muten_audit_events_total{kind}`、
   `muten_audit_chain_verify_seconds`、`muten_audit_last_checkpoint_age_seconds`、
   `muten_audit_chain_broken{file}`(0/1 即アラート)、`muten_audit_tree_size`。pull 専用
   textfile collector で offline。SLO: 「検証 週次 100% 成功」「checkpoint 鮮度違反=ページャ」。

8. **★ GROUNDING — ローテーション時の chain/tree continuity** / **★ GROUNDING — 署名 checkpoint の
   非否認性**: RFC 9162 consistency proof でローテ境界(旧 root→新 genesis)を O(log n) 検証
   (C6-8 解消)。個別イベント署名は過大ゆえ **checkpoint を Ed25519 署名**するのが最小コストの
   非否認性(rekor と同設計、鍵は項目5の device key 共用、C6-10 具体化)。

---

## カテゴリ D: 配布 / 供給チェーン / Rust crate 品質

中核知見: **署名付きバイナリは計画済だが、per-OS helper スクリプトと MDM 配布
blocklist — どちらもビルド後に可変で、かつ直接セキュリティ挙動を駆動する — が未署名の
攻撃面**。ここを offline で閉じるのが最大の穴埋め。

1. **★★★ NEW — helper スクリプトを cosign blob 署名し exec 前に検証**
   [根拠] Sigstore cosign は任意ファイルの blob 署名対応(`sign-blob --bundle`)で
   **完全オフライン検証可**。Ladisa et al. SoK(107 攻撃→33 安全策)は配布物の署名+検証を
   最高価値の安全策に列挙。helper(bash/PowerShell)は exec される未署名コード=最弱リンク。
   [muten適用] リリース時に各 helper を署名し `.sigstore.json` bundle を同梱。daemon が
   spawn 前にオフライン検証(埋込 pubkey、Rekor 不要)。不一致なら exec 拒否。

2. **★★★ NEW — MDM 配布 blocklist の署名 + オフライン検証 + anti-rollback**
   [根拠] TUF: 「全 role がオフライン鍵に依存すべき」「署名メタデータが改竄/replay/不正配布
   から保護」、n-of-m 閾値。config が検出判断を駆動する以上、それ自身が integrity 保護必須。
   [muten適用] blocklist を署名 blob 化(minisign/cosign)。daemon が pinned pubkey で署名 +
   単調増加 `version` + `valid_until`(anti-rollback/replay — TUF の教訓)を parse 前に検証。
   高保証には 2-of-N 閾値。全 offline。

3. **★★ NEW — runtime 検証器は minisign/ed25519 で forbid(unsafe)・zero-network を維持**
   [根拠] 「cosign は minisign/signify に着想」。Fulcio/Rekor/OCI スタックは重依存 + network 形状で
   muten 制約に反する。
   [muten適用] cosign は build/release 時(SLSA + Rekor 公開記録)、runtime の helper/blocklist
   検証は埋込 pure-Rust ed25519(`ed25519-dalek`、依存の unsafe は cargo-deny で gate)。
   dual: publish=cosign / runtime=ed25519。

4. **★★ GROUNDING — SBOM(CycloneDX)+ SLSA provenance を CI リリース成果物に**
   [根拠] `cargo-cyclonedx` は公式プラグイン(feature 反映・dev-dep 除外・license 記録、
   CycloneDX 1.6=Ecma 標準)で CRA の機械可読 SBOM 要件に合致。SLSA v1.0: L2=hosted+署名、
   L3=分離。GitHub hosted runner + signed provenance で安価に L2–L3。
   [muten適用] CI に `cargo cyclonedx --format json`(出荷 feature 組合せ)+ SLSA generator を追加し
   Release に添付。CRA 対応の具体策。

5. **★★ GROUNDING — リリースビルドの再現性ゲート**
   [根拠] reproducible-builds.org/rust: `trim-paths`(RFC 3127 profile option)+
   `SOURCE_DATE_EPOCH`。署名済バイナリが監査済ソース由来であることをfleetが独立確認可。
   [muten適用] `[profile.release] trim-paths="all"`、tag コミット日時を `SOURCE_DATE_EPOCH` に、
   `rust-toolchain.toml` 固定。CI で2回ビルド→ハッシュ diff、不一致で fail、期待 SHA-256 を公開。

6. **★★ NEW — cargo-semver-checks で API 安定性をゲート**
   [根拠] top-1000 crate の「31 リリースに1回 / 6 crate に1回超」が semver 違反を出荷。
   cargo-semver-checks は rustc 機構を使用、CI Action あり。fleet 自動化が消費する config/CLI の
   破壊は運用インシデント。
   [muten適用] CI(PR + pre-publish)に `cargo semver-checks`。公開検出 API と blocklist スキーマ型に特に有効。

7. **★★ NEW — parser を cargo-fuzz でファズ + OSS-Fuzz 連携**
   [根拠] 「parser は高価値ファズ対象(untrusted データに正しく振る舞う必要)」。forbid(unsafe)
   なら sanitizer 無効化で高速化でき、目標は panic/DoS/論理頑健性。blocklist は MDM(半信頼)、
   メタデータは OS 由来。
   [muten適用] `fuzz/` に blocklist deserialization / 署名 bundle parser / metadata→検出入力の
   target を追加。no-panic・有界資源を assert。OSS-Fuzz 投入。`fuzz/` 隔離で MSRV/nightly 非干渉。

8. **★ NEW — no_std + deny(missing_docs) の純検出コア分離**
   [根拠] 「window メタデータ上の純粋関数」は no_std へ移植可能な形。検出中核を no_std 化すると
   trusted/攻撃面が最小化し IO/exec/署名境界が明示化(arXiv:2406.10109 secure-design)。
   [muten適用] `muten-core`(`no_std`/`forbid(unsafe)`/`deny(missing_docs)`/純検出)と `muten`
   (std: CLI/IO/helper exec/署名)に分割。`thumbv7em-none-eabi` 等で no_std CI ターゲット追加し
   std 混入を防止。低優先(refactor コスト)だが高アーキ価値。

9. **★ GROUNDING — 検証可能リリース/信頼モデル文書(CRA 整合 SECURITY.md)**
   [根拠] EU CRA は SBOM 作成/維持/10年保持 + 脆弱性対応プロセスを法的義務化(2027-12 期限、
   2026-09 から報告)。osquery は検証用 GPG 鍵を文書配布。
   [muten適用] `SECURITY.md` + 「リリース検証」doc: cosign/minisign 公開鍵と binary/helper/
   blocklist のオフライン検証手順、SBOM/provenance 配置、脆弱性開示 + SLA、CRA 技術文書チェックリスト。

---

## 横断的 次sprint候補(★★★ 集約)

製品目標(公開可能・保守性・安全性・法的安定性)への寄与順:

1. **検出: メタデータ複合信号** — `input_trap` / `sudden_fullscreen_takeover` /
   `coercive_overlay`(A-1/2/3)。新入力ゼロ・CV不要・blocklist 遅延に強い**最高 ROI**。
2. **検出: UTS#39 昇格** — `skeleton()` 衝突照合 / whole-script / restriction-level /
   BiDi-present 信号(B-1/2/3/4)。既存 folding の自然な発展で盲点を閉じる。
3. **検出: ClickFix タイトル族**(A-4)— 2025 最大の急増トレンド、純 blocklist 追加。
4. **監査: ①Merkle history tree ②C2SP checkpoint 外部アンカー ③canonical serialization**
   (C-1/2/3)— ③は相互運用を壊す準バグで先行価値が高い。
5. **供給鎖: helper / blocklist の署名 + オフライン検証 + anti-rollback**(D-1/2)—
   未署名の可変攻撃面を閉じる。

## スコープ外(I3: 過剰実装回避)

- **CV / ML 黒箱**(PP3D のモデル自体、Edge の画像モデル)— I6 説明可能 / offline / 推論なしを堅持。
  ただし behavioral tell(突発全画面・input trap)は**メタデータで**再現する(A-1/2)。
- **network / 証明書 / WHOIS / SmartScreen 報告**(リアルタイム TLD reputation 等)— offline-first。
  abuse TLD は小型オフライン加重リストで近似(A-7)。
- **プロセス kill / レジストリ改変** — 検出・監査のみ(除去は EDR)。
- **ブロックチェーン / consensus 監査** — Merkle + signed checkpoint で split-view/truncation を十分カバー。

## 出典(主要)

TSS/scareware: arXiv 2510.18465 (PP3D), 2509.13186 (JS-capability phishing),
2401.09824 (crypto TSS); Microsoft Edge Scareware Blocker (2025-01/10);
MS ClickFix blog (2025-08); Securelist browser-lockers; FBI IC3 2024 Report;
Chrome keyboard/pointer-lock permission (Chrome 131); textslashplain fullscreen abuse.
Unicode/dark-pattern: UTS#39 (skeleton / restriction levels / confusable types);
ICU SpoofChecker; arXiv 2111.00169 (Trojan Source), 1909.07539 (ShamFinder),
2308.05898 (UIGuard), 2306.05816 (ChatPhishDetector), 2603.21515 (UMBRA cookie DP11-19),
2406.01608 (e-commerce dark patterns); FTC/CPRA/EU DSA.
監査/可観測性: Crosby-Wallach (USENIX Sec 2009); RFC 9162 (CT 2.0); C2SP tlog-checkpoint/
tlog-proof/tlog-tiles; Schneier-Kelsey (ACM TISSEC 1999); arXiv 2308.05557, 2605.00065;
Balloon (ePrint 2015/007); sigstore rekor; in-toto/SLSA; OTel semantic conventions; Sigma.
供給鎖/Rust: SLSA v1.0; Sigstore cosign blob signing; TUF; cargo-cyclonedx (CycloneDX 1.6);
reproducible-builds.org/rust + RFC 3127; cargo-semver-checks; cargo-fuzz/OSS-Fuzz;
Ladisa et al. SoK (Oakland 2023); arXiv 2409.05014 (SLSA deployment); EU CRA; osquery/Wazuh.
