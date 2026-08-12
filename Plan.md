# Plan.md — muten v0.4.0: Endpoint Environment Enforcement

> **Breaking product redefinition.** muten は「PC強制ミュート」から
> 「**managed PC の環境強制ツール(音 + 画面)**」へ拡張する。
> CLAUDE.md G1/G8 に従い本Planを先に確定。

## 目的 (Purpose)

muten の既存市場(図書館・学校・キオスク・コールセンター・寮)では、
**画面を覆い隠す詐欺広告**(偽ウイルス警告、偽当選通知、テクニカルサポート詐欺、
全画面ポップアップ)が IT サポートの実負担になっている。同じ管理PC群に対し、
音の強制(既存)に加えて**詐欺オーバーレイの検出・排除**を提供する。

## スコープ (Scope)

### IN
- `muten-overlay` 新crate(純粋ドメイン層、OS非依存、`forbid(unsafe_code)`)
  - `OverlayWindow`: 観測されたウィンドウ/オーバーレイの記述(タイトル/座標/画面被覆率/最前面/閉じるボタン有無/出現経緯/URL)
  - `classify()`: ヒューリスティック採点で Allow / Suspicious(score) / Block 判定
  - オフライン・ブロックリスト(ドメイン/タイトルパターン)パーサ — calendar.ics と同じ「焦点を絞ったサブセット」方針
- property test(分類器・パーサ)
- CLI サブコマンド `muten overlay classify`(dry-run)/`overlay rules`(ブロックリスト確認)
- 既存 EventKind に `OverlayBlocked` / `OverlaySuspicious` 追加(監査ログ・hash chain対象)

### OUT(本リリースでは扱わない)
- OS固有のウィンドウ列挙・dismiss 実装(audio backend と同様、別途 helper/ext で配線)
- ブラウザ拡張本体(別配布物)
- ネットワーク/DNS レベルのフィルタ(別レイヤ)
- フィルタリストの自動更新(offline-first 維持。更新は MDM push)

## フェーズ (Phases)

1. **要件** — 詐欺オーバーレイの特徴量を列挙、受入条件確定 ← 本Plan
2. **基本設計** — `OverlayWindow` / `Verdict` / `Ruleset` 型、`classify` シグネチャ
3. **詳細設計** — 採点関数の各シグナルと重み、ブロックリスト文法
4. **実装** — crate + 単体テスト
5. **テスト** — property test(never panic / 単調性 / 境界)
6. **CrossReview** — clippy `-D warnings` + fmt + 全テスト
7. **RELEASE** — CHANGELOG breaking note、README 再定義反映

## Definition of Done

- [x] `muten-overlay` が `forbid(unsafe_code)` で compile
- [x] `classify()` がオフラインの純粋関数(ネットワーク呼び出しゼロ)
- [x] 単体テスト + property test 全GREEN (106 tests)
- [x] clippy `-D warnings` ゼロ / fmt clean
- [x] CLI `overlay classify` / `overlay rules` 動作 (+ scareware / enforce / monitor)
- [~] 監査イベント `OverlayBlocked` が hash chain に乗る
      — overlay 独自の `ChainedFileSink`(audit-chain 互換フォーマット)で
      tamper-evident に記録済み。本物の `muten-audit-chain` への配線は
      workspace 復元後(他crateがFS resetで消失中)。
- [x] CHANGELOG に breaking redefinition 記載
- [x] README 製品命題を「音 + 画面の環境強制」に改訂
- [x] LICENSE (MIT) 配置、Cargo.toml publish metadata 完備、`cargo package` 通過 (I4)

## 設計判断 (ADR要約)

- **誤検出 (false positive) のコスト > 見逃しのコスト**。正規の全画面アプリ
  (動画プレーヤ、プレゼン、ゲーム)を誤ブロックすると業務破壊。よって
  既定は **Suspicious止まりで自動dismissせず監査記録のみ**、Block は
  ブロックリスト確定一致 or 高スコア時のみ。Observe-first を踏襲。
- **ヒューリスティックは説明可能であること**(I6)。各シグナルが
  スコアにどう効いたかを `Verdict` に含め、監査で追跡可能にする。
  ML分類器は使わない(Pike違反・offline不能・説明不能)。
