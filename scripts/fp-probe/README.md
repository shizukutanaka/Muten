# Content-signal false-positive probe

Runs a candidate window title through **every** content detector in
`src/confusables.rs` and reports which fire. Built for **WO-12 / DR-21**
(502 Japanese detection literals guarded by only 10 Japanese benign
titles), but it works for any language.

It needs no registry: `confusables.rs` has no external-crate
dependencies, so `rustc` compiles it directly.

## Generate and run

```sh
cd crates/muten-overlay
python3 - <<'PY' > /tmp/probe.rs
import re
src = open('src/confusables.rs', encoding='utf-8').read()
fns = sorted(set(re.findall(r'^pub fn (has_[a-z_]+)\(s: &str\) -> bool', src, re.M)))
form = {'has_bidi_override','has_compat_alpha','has_excessive_combining_marks',
        'has_mixed_number_systems','has_whole_script_confusable','has_confusable_mixed_script'}
calls = "\n".join(f'        ("{f}", confusables::{f}(&n)),' for f in fns if f not in form)
print(f'''#[path = "src/confusables.rs"]
mod confusables;
use confusables::normalize_for_match;
fn main() {{
    for t in std::env::args().skip(1) {{
        let n = normalize_for_match(&t);
        let all: Vec<(&str, bool)> = vec![
{calls}
        ];
        let hits: Vec<&str> = all.into_iter().filter(|(_, f)| *f).map(|(k, _)| k).collect();
        if hits.is_empty() {{ println!("clean  {{t}}"); }} else {{ println!("FIRES  {{t}} -> {{hits:?}}"); }}
    }}
}}''')
PY
rustc --edition 2021 -O -o /tmp/probe /tmp/probe.rs && /tmp/probe "候補タイトル" "another title"
```

`form` above excludes the six *evasion-form* detectors (bidi, combining
marks, whole-script, …), which describe how text is written rather than
what it says — the same distinction `tests/benign_corpus.rs` makes with
its `GEOMETRY_SIGNALS` exemption.

## Interpreting a hit — read this before "fixing" anything

A hit is **not automatically a bug**. Most content signals are gated in
`classify()` behind `alert_shaped`
(`coverage >= 85 || blocks_input || !has_close_button`), so a legitimate
notification — small, closable, non-modal — never reaches them.

Measured example (2026-08): of 50 realistic Japanese titles probed, 46
were clean and 4 fired:

| title | signal | verdict |
|---|---|---|
| アカウントがロックされました - パスワードを再設定してください | `credential_harvest` | signal is **correct**; `alert_shaped` guard is what prevents the FP |
| 不正なログインを検知しました - ご確認ください | `credential_harvest` | same |
| お客様のアカウントは一時的に制限されています | `credential_harvest` | same |
| ウイルスが検出されました - 隔離しました - Windows セキュリティ | `fake_scanner` | same — a *real* AV notification |

So those four must **not** be dropped into `BENIGN_TITLES`:
`benign_corpus.rs` deliberately evaluates with an alert-shaped profile to
isolate content FPs, so they would fail there — and the failure would be
wrong, because the signal is right and the geometry guard is doing its
job. They belong in a test asserting *"not alert-shaped ⇒ no block"*
instead.

The other 46 probed clean and are safe to add to `BENIGN_TITLES` as-is.
