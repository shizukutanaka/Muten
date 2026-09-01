#!/bin/sh
# Positive-detection regression guard — the mirror of tests/benign_corpus.rs.
#
# WHY THIS EXISTS. The benign side has a corpus asserting that legitimate
# windows do NOT fire. The positive side had nothing: no standing check
# that the scam families the product exists to catch still get caught.
# That gap is not theoretical — this cycle deleted 10 blocklist rules
# after proving each was unreachable. The same procedure applied to a
# LIVE rule would remove real detection with nothing to notice.
#
# WHAT IT CHECKS. muten detects along TWO independent paths, and a sample
# only needs one of them:
#   * heuristic  — a has_* content detector in src/confusables.rs, which
#                  catches novel variants of a structural technique;
#   * blocklist  — a `title:` rule, which catches known exact phrasings.
# For each representative family this asserts at least one path fires,
# and prints WHICH — so a sample silently migrating between paths (e.g. a
# heuristic weakening while a blocklist rule masks it) is still visible.
#
# This runs with rustc alone: confusables.rs has no external-crate
# dependencies, and blocklist matching is normalize + substring, which is
# the loader's own semantics (see installer/overlay-helper/lint-blocklist.sh).
#
# Exit 0 = every family still detected. Exit 1 = at least one is not.
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)
CRATE="$ROOT/crates/muten-overlay"

command -v rustc   >/dev/null 2>&1 || { echo "SKIP  detection check — rustc not available";   exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP  detection check — python3 not available"; exit 0; }

TMP="${TMPDIR:-/tmp}/muten-detect-$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

python3 - "$CRATE" "$ROOT/examples/overlay-blocklist.txt" "$TMP/probe.rs" <<'PY'
import re, sys, pathlib
crate, blocklist, out = (pathlib.Path(a) for a in sys.argv[1:4])

src = (crate / 'src' / 'confusables.rs').read_text(encoding='utf-8')
fns = sorted(set(re.findall(r'^pub fn (has_[a-z_]+)\(s: &str\) -> bool', src, re.M)))
form = {'has_bidi_override', 'has_compat_alpha', 'has_excessive_combining_marks',
        'has_mixed_number_systems', 'has_whole_script_confusable',
        'has_confusable_mixed_script'}
calls = "\n".join(f'        ("{f}", confusables::{f}(&n)),' for f in fns if f not in form)

# title: rule keys, normalized the way the loader normalizes them
keys = []
for ln in blocklist.read_text(encoding='utf-8').splitlines():
    b = ln.split('#', 1)[0].strip()
    if b.startswith('title:'):
        v = b[len('title:'):].strip()
        if v:
            keys.append(v)
rules = ",\n".join(f'        r#"{k}"#' for k in keys)

out.write_text(f'''
#[path = "{(crate / 'src' / 'confusables.rs').as_posix()}"]
mod confusables;
use confusables::normalize_for_match;

const TITLE_RULES: &[&str] = &[
{rules}
];

fn heuristics(n: &str) -> Vec<&'static str> {{
    let v: Vec<(&'static str, bool)> = vec![
{calls}
    ];
    v.into_iter().filter(|(_, f)| *f).map(|(k, _)| k).collect()
}}

fn blocklist_hit(n: &str) -> Option<String> {{
    TITLE_RULES.iter()
        .map(|r| normalize_for_match(r))
        .find(|k| !k.is_empty() && n.contains(k.as_str()))
}}

fn main() {{
    // Representative families, all already documented in
    // docs/THREAT_INTEL_2026.md. No new threat claims are invented here.
    let samples: &[(&str, &str)] = &[
        ("ClickFix / FakeCAPTCHA",
         "Verification required - press Win+R and paste the command to prove you are human"),
        ("CrashFix",
         "Your browser stopped working abnormally - paste this into the terminal to fix"),
        ("GlitchFix",
         "System font missing - update your browser, press ctrl+v to continue"),
        ("Azure-blob tech-support scam",
         "Warning: your computer is infected - call Microsoft support immediately"),
        ("CypherLoc browser lock",
         "This browser has been locked for security - contact your IT helpdesk to unlock this device"),
        ("JP support scam (IPA wording)",
         "\\u{{8b66}}\\u{{544a}}: \\u{{30a6}}\\u{{30a4}}\\u{{30eb}}\\u{{30b9}}\\u{{306b}}\\u{{611f}}\\u{{67d3}}\\u{{3057}}\\u{{3066}}\\u{{3044}}\\u{{307e}}\\u{{3059}}"),
        ("Gift-card payment demand",
         "Your device is locked - buy gift cards to remove the virus"),
        ("Fake scanner progress",
         "Scanning for threats - 4 threats detected on your PC"),
    ];

    let mut undetected = 0;
    for (name, title) in samples {{
        let n = normalize_for_match(title);
        let h = heuristics(&n);
        let b = blocklist_hit(&n);
        match (h.is_empty(), &b) {{
            (false, Some(rule)) =>
                println!("  ok   {{name:<32}} heuristic {{h:?}} + blocklist {{rule:?}}"),
            (false, None) =>
                println!("  ok   {{name:<32}} heuristic {{h:?}}"),
            (true, Some(rule)) =>
                println!("  ok   {{name:<32}} blocklist {{rule:?}}"),
            (true, None) => {{
                undetected += 1;
                println!("  MISS {{name:<32}} NO heuristic and NO blocklist rule matches");
                println!("       title: {{title}}");
            }}
        }}
    }}
    println!("\\n  {{}} families checked, {{}} undetected", samples.len(), undetected);
    std::process::exit(if undetected == 0 {{ 0 }} else {{ 1 }});
}}
''', encoding='utf-8')
PY

rustc --edition 2021 -O -o "$TMP/probe" "$TMP/probe.rs" 2>"$TMP/err" || {
    echo "FAIL  detection probe did not compile:"; sed 's/^/      /' "$TMP/err" | head -5; exit 1; }
"$TMP/probe"
