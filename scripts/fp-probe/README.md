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

### ⚠ Feed the two detector families different input — `classify()` does

This is the easy mistake, and it produced a completely wrong result once
here: probing 20 legitimate Russian/Greek titles reported **20/20 firing
`confusable_mixed_script`**, which was an artefact of the probe, not a
finding.

- **Content detectors** take the **normalized** title
  (`normalize_for_match`), so leetspeak and homoglyph evasion are folded
  before matching.
- **The six evasion-FORM detectors** — `has_confusable_mixed_script`,
  `has_whole_script_confusable`, `has_bidi_override`, `has_compat_alpha`,
  `has_excessive_combining_marks`, `has_mixed_number_systems` — take the
  **raw** title. `classify()` calls them on `title` directly
  (`src/lib.rs`), and the doc comment on `has_confusable_mixed_script`
  says why: *"Run on the raw string: `fold_confusables` erases the
  evidence by folding everything to Latin."*

Normalize first and every pure-Cyrillic word looks mixed-script, because
folding turns some letters into Latin and leaves the rest — you
manufacture the exact condition you are testing for. With the correct
split, all 20 of those titles are clean.

Note `tests/benign_corpus.rs` exempts `GEOMETRY_SIGNALS` (fullscreen,
topmost, …) but **not** the form detectors, so a candidate has to be
clean against all 68 to be safe to add there.

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


## ⚠ This probe measures only HALF the detection path

muten detects along two independent paths:

| path | what it catches |
|---|---|
| **heuristic** — the `has_*` detectors in `confusables.rs` | novel variants of a structural technique |
| **blocklist** — `title:` rules in `examples/overlay-blocklist.txt` | known exact phrasings |

**This probe only runs the heuristic half.** A `clean` result therefore
means *"no content detector fires"* — it does **not** mean *"muten would
not detect this"*.

That distinction is not hypothetical; it produced a wrong conclusion here
once. Probing six representative 2026 scam families reported three as
firing nothing, which read like a serious detection gap. It was not: the
Azure-blob TSS sample is caught by `title: your computer is infected`,
CypherLoc by `title: contact your it helpdesk`, and the Japanese support
scam by `title: ウイルスに感染` (deliberately shortened so it covers
「…しています/しました」). All three were detected the whole time, via the
path the probe does not look at.

**For positive samples use `scripts/check-detection.sh` instead** — it
checks both paths and reports which one caught each sample. Use this
probe for *benign* candidates, where the question genuinely is "does any
content detector fire?".
