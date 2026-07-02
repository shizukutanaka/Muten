# muten-overlay 機能過不足監査 (2026-07)

> ソクラテス式問答法による監査の集約。各項目は推測ではなく、コード・テスト・
> 実バイナリの実行で**検証済み**。「過剰」= 実害または保守負荷のある余剰、
> 「適正」= 監査の結果、健全と確認されたもの、「不足」= 製品の掲げる目的
> (managed fleet での scam overlay の検出と排除) に対して欠けているもの。
> 修正済み項目は本ブランチ (claude/deepresearch-ultrathink-improvement-yp5Y2)
> のコミットで対応済み。

---

## 1. 過剰 — 検出し、修正済み

| # | 項目 | 実害 | 対応 |
|---|---|---|---|
| E-1 | `crypto_drain_lure` の `wallet_coerce` が裸の "connect" + wallet 語で発火 | "Connect Wallet" は全正規 Web3 dApp (Uniswap/OpenSea/MetaMask 本体) の標準 CTA — 確実な誤検出 | "connect" を coercion 動詞から除外。実ドレイナは wallet_alarm / wallet_connect_popup_lure が引き続き捕捉 |
| E-2 | `cloud_quota_lure` の汎用容量語彙 ("storage is full" / "storage almost full") | Apple「iCloud Storage Almost Full」・Google の実通知文言と一言一句同一 — 正規 OS 通知に発火 | 2段階設計に再構築: 明示的削除脅迫は単独発火、汎用容量語は sign-in/緊急圧力との AND 必須 |
| E-3 | `IMPROVEMENT_ROADMAP.md` の陳腐化 (実装済み6項目が「未実装」表示) | 将来の計画セッションが実装済み機能を再調査・再実装する誤誘導 | deny(missing_docs) / Merkle / stdin streaming / fuzzing / docs.rs / non_exhaustive を ✓DONE に更新 |

## 2. 過剰 — 残存候補 (要判断、未対応)

| # | 項目 | 内容 | 推奨 |
|---|---|---|---|
| EC-1 | `enforce` と `monitor` の機能重複 | 両者とも NullController + 静的 JSON リストの dry-run。monitor は enforce のほぼ上位互換 (sweeps/audit-log/metrics 追加)。差分は exit code 契約 (enforce: block 時 6) のみ | 統合候補。ただし既存スクリプト互換のため deprecation 告知を先行させる |
| EC-2 | 調査系ドキュメント4本の内容重複 | IMPROVEMENT_ROADMAP / RESEARCH_IMPROVEMENTS_2026H1 / IMPROVEMENT_CATALOG_2026H2 / GAP_ANALYSIS_2026H2 が相互に重なる項目を別々の進捗表記で保持 — 陳腐化が構造的に再発する | 「現行 = ROADMAP、他は日付付きアーカイブ」と冒頭に明記 |
| EC-3 | `MECHANIC_EXEMPT` 定数の二重定義 | lib.rs 内の2テストが同一リストを別々に持つ — 片方だけ更新するとすり抜け | 軽微。単一 const に統合 |

## 3. 適正 — 監査の結果、健全と確認

- **孤児検出関数ゼロ**: confusables.rs の全 `has_*` が classify() に配線済み (差集合検査で確認)。
- **OverlayWindow 全フィールド参照済み**: 8フィールド全てが classify() で消費される。
- **10レンズ全露出**: categories / MITRE / persuasion / extraction / lifecycle / targeting / magnitude / fingerprint / triage / impersonation の全てが text 出力と `--json` の両方に現れる (実行して確認)。
- **ヘルパー4種は実体あり**: Windows/macOS/X11/Wayland とも 100–137 行の動作実装 (スタブではない)。
- **カバレッジガード群が機能**: CONTENT_SIGNALS を単一の真実源とする 5 つのメタテストが、新シグナル追加時の配線漏れを実際に検出する (E66 追加時に実証)。

## 4. 不足 — 検出し、実装済み (本セッション)

| # | 項目 | 欠落の内容 | 対応 |
|---|---|---|---|
| D-1 | **本番エントリポイント不在** | SubprocessController と Monitor::run は完備・テスト済みなのに、バイナリはどこにも実配線せず (enforce/monitor は NullController 固定)。実機で保護を動かす手段が存在しなかった | `daemon` サブコマンド新設 (probe→実スイープ→停止フラグ→検証付き監査ログ) |
| D-2 | **ヘルパーのハング対策なし** | `Command::output()` が無期限ブロック — 固まった helper 1回でデーモン全体 (停止フラグ検査含む) が永久凍結 | spawn+poll+kill のタイムアウト (既定5s、`--helper-timeout-ms`)、`ControllerError::Timeout` 新設。pipe-buffer デッドロックも回避 |
| D-3 | **多重起動ガードなし** | 同一 audit-log への2プロセス並走でハッシュチェーンが破損 (改竄検出の根拠が壊れる) | `<audit-log>.lock` (O_EXCL) + Drop 解放。サービステンプレート3種は supervisor 起動時のみ自動クリア |
| D-4 | **ゼロイベント時クラッシュ** | ChainedFileSink は遅延生成 — 健全なゼロ検出運用で monitor/daemon が exit 1 | 3箇所 (cmd_monitor / cmd_daemon / count_audit_kinds) で「ファイル無し=空チェーン」扱いに |
| D-5 | **メトリクスが停止時のみ書き出し** | 数週間連続運用中、node_exporter は一切データを見られない (ファイル自体が無い) | CountingSink (イベント毎 O(1) 集計) + 毎スイープ書き換え |
| D-6 | **メトリクス書き込み失敗で保護ループ死亡** | metrics ディレクトリ不在 (node_exporter 未導入ホスト) で初回スイープ即 exit 1 | best-effort 化 (失敗ストリークにつき1回警告、保護は継続) |
| D-7 | **MDM 配布物ゼロ** | docs は「MDM で配布」と謳うが systemd/launchd/Task Scheduler 用の成果物が無い | unit / plist / task.xml + Intune/Jamf/GPO/Ansible 手順の README 新設 |
| D-8 | **通知許可詐欺 (Matrix Push C2 型) 未検出** | 「Click Allow to continue watching」は clickfix (CAPTCHA 語彙必須) にも download_trap (install 語彙必須) にも掛からない | `notification_permission_bait` (E66) を 10 レンズ完全配線で追加 |
| D-9 | **`--helper-timeout-ms` の CLI 配線が無テスト** | ライブラリ側のみテスト済み — リファクタで既定値に黙って退行しても検出不能 | 2秒閾値の回帰テスト追加 (妨害注入で失敗することを確認済み) |

## 5. 不足 — 残存 (優先度順)

| # | 優先 | 項目 | 内容 |
|---|---|---|---|
| DR-1 | ★★★ | **helper プロトコルに process-list verb が無い** | daemon は `no_proc` 固定 → `rogue_av_process` シグナルと blocklist の `process:` ルール 49 件が**本番モードで全て無効**。scareware 検出の柱の一つが実運用で死んでいる。helper に `processes` verb を足し、`--probe`/`enumerate`/`dismiss` と同様に配線するのが次の最有力候補 |
| DR-2 | ★★★ | **helper の実フィールド忠実度** | origin (unsolicited +25) / age_ms (very_new +10) / has_close_button (+25) / blocks_input (+20) が各 OS helper で保守的固定値 → 実機ではジオメトリ系シグナルの大半が発火せず、検出力が title/URL に偏る (roadmap C7-2〜5)。誤 Block 方向ではなく検出漏れ方向なので安全側だが、実力値が仕様値を大きく下回る |
| DR-3 | ★★ | **blocklist ホットリロード** | ルール更新に daemon 再起動が必要 (installer README に明記済み)。stop-flag と同じファイル監視パターンで `--rules` の mtime を毎スイープ検査すれば依存追加なしで実装可能 |
| DR-4 | ★★ | **ログローテーション + チェーン跨ぎ検証** | 数週間運用で監査ログが単一ファイルのまま際限なく成長 (C6-8)。verify のチェーン継続検証 (`verify_chain_continued`) は既にあるので、ローテーション側の実装のみ |
| DR-5 | ★★ | **stop-flag の応答遅延** | フラグはスイープ間でしか見ない — interval を長く設定すると停止にほぼ interval 分かかる。sleep を小刻み (例: 250ms) に分割してフラグを挟み見れば解決 |
| DR-6 | ★★ | **Merkle root の外部アンカー自動化** | root の計算と HMAC 署名は実装済みだが、out-of-band への定期公開 (syslog / 不変ストレージ) は手動 (C6-2/5) |
| DR-7 | ★ | **設定ファイル** | `~/.config/muten/overlay.toml` 等が無く毎回フラグ指定 (C4-9)。サービステンプレートがフラグを固定するため daemon 運用では低優先 |
| DR-8 | ★ | **EN/JP 以外の言語** | フィッシングは 22 言語に分散 (arXiv:2306.05816)。現行検出語彙は EN+JP のみ |
| DR-9 | ★ | **BITB (Browser-in-the-Browser) 検出** | OverlayWindow (title+url) では原理的に不可。helper プロトコルに DOM 由来情報を足す拡張が前提 |
| DR-10 | ★ | **署名ビルド / semver-checks / ベンチマーク** | C10-1 (Authenticode/Sigstore)、cargo-semver-checks、criterion (C3 残) |

---

**現状サマリ**: 検出エンジン (66 シグナル / 10 レンズ / 正規化パイプライン) と
監査基盤 (ハッシュチェーン + Merkle) は充実しており、本セッションで本番実行系
(daemon + タイムアウト + ロック + ライブメトリクス + MDM テンプレート) の欠落を
埋めた。残る最大の不足は **DR-1/DR-2 = helper が classify() に渡す情報の貧しさ**
であり、シグナルの追加よりも「既存シグナルを実機で生かす」ことが次の主戦場。
