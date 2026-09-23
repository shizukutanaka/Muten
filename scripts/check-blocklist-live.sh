#!/bin/sh
# Shipped blocklist, loaded by the REAL loader and judged by the REAL
# classify(): every rule must load, and every title rule must dismiss.
#
# WHY THIS EXISTS. Two things about the curated blocklist were only ever
# measured by reimplementations of the loader, never by the loader:
#   * the rule COUNTS (309 title / 44 glob / 44 process, S1) come from a
#     Python regex in check-doc-claims.sh, and the unreachable-rule
#     analysis comes from a shell reimplementation in lint-blocklist.sh.
#     Ruleset::parse has its own rules - an empty normalized key is
#     dropped, and ANY line without a recognized lowercase prefix falls
#     through to a HOST hard-block rule (so a mis-cased `Title: ...` does
#     not vanish, it silently becomes something else). If the
#     reimplementations ever disagree with the loader, both checks would
#     keep passing while the shipped behaviour differed.
#   * nothing showed that a loaded title rule actually DISMISSES. A title
#     hit is W_TITLE_HIT = 40 against BLOCK_THRESHOLD = 100 (DR-28): a rule
#     that loads and fires but never reaches Block protects no one.
#
# WHAT IT ASSERTS, on examples/overlay-blocklist.txt:
#   1. loader counts == file counts for title/glob/process/host. `host`
#      is the one that catches fall-through: the file has no bare lines,
#      so any reinterpreted line shows up as an unexpected host rule.
#   2. every `title:` rule, placed in a scam-shaped window (full-screen,
#      topmost, no close button, input-blocking), fires `blocklist_title`,
#      matches AS ITSELF (not pre-empted by an earlier rule - the loader
#      is first-match-wins), and yields Decision::Block.
#   3. control: the same geometry with a benign title is NOT a Block. This
#      is what gives (2) meaning - geometry alone scores 95, so each rule
#      is the thing that crosses the line.
#
# Runs on the offline-stub toolchain of check-crate.sh; see that script
# and scripts/offline-stubs/README.md for what that does and does not prove.
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)
CRATE="$ROOT/crates/muten-overlay"
STUBS="$ROOT/scripts/offline-stubs"
BLOCKLIST="${1:-$ROOT/examples/overlay-blocklist.txt}"

command -v rustc   >/dev/null 2>&1 || { echo "SKIP  live blocklist check - rustc not available";   exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP  live blocklist check - python3 not available"; exit 0; }

TMP="${TMPDIR:-/tmp}/muten-bllive-$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

for c in thiserror serde; do
    rustc --edition 2021 --crate-type proc-macro --crate-name "$c" -O --out-dir "$TMP" \
          "$STUBS/$c.rs" 2>>"$TMP/dep.err" || { echo "FAIL  $c shim did not build"; exit 1; }
done
for c in sha2 hex serde_json; do
    rustc --edition 2021 --crate-type lib --crate-name "$c" -O --out-dir "$TMP" \
          "$STUBS/$c.rs" 2>>"$TMP/dep.err" || { echo "FAIL  $c stub did not build"; exit 1; }
done
rustc --edition 2021 --crate-type lib --crate-name muten_overlay -O --out-dir "$TMP" \
      --extern "serde=$TMP/libserde.so" --extern "thiserror=$TMP/libthiserror.so" \
      --extern "serde_json=$TMP/libserde_json.rlib" --extern "sha2=$TMP/libsha2.rlib" \
      --extern "hex=$TMP/libhex.rlib" "$CRATE/src/lib.rs" 2>"$TMP/lib.err" || {
    echo "FAIL  the crate did not build:"; grep -E '^error' -A4 "$TMP/lib.err" | head -20 | sed 's/^/      /'; exit 1; }

# File-side counts, with the loader's own comment rule (first '#').
# `host` counts explicit `host:` lines; a bare line would ALSO become a
# host rule in the loader, which is exactly the drift this exposes.
_counts=$(python3 - "$BLOCKLIST" <<'PY'
import sys, pathlib
n = {'title': 0, 'glob': 0, 'process': 0, 'host': 0}
for ln in pathlib.Path(sys.argv[1]).read_text(encoding='utf-8').splitlines():
    b = ln.split('#', 1)[0].strip()
    for k in n:
        if b.startswith(k + ':') and b[len(k) + 1:].strip():
            n[k] += 1
print(n['title'], n['glob'], n['process'], n['host'])
PY
)

cat > "$TMP/probe.rs" <<'RS'
use muten_overlay::{classify, Decision, Origin, OverlayWindow, Ruleset};

fn scam_shaped(title: &str) -> OverlayWindow {
    OverlayWindow {
        title: title.to_string(),
        coverage_percent: 100,
        topmost: true,
        has_close_button: false,
        blocks_input: true,
        origin: Origin::Unknown,
        ..Default::default()
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let text = std::fs::read_to_string(&a[1]).expect("read blocklist");
    let want: Vec<usize> = a[2..6].iter().map(|s| s.parse().expect("count")).collect();
    let r = Ruleset::parse(&text);
    let mut bad = 0;

    let got = [r.title_count(), r.glob_count(), r.process_count(), r.host_count()];
    for (k, (g, w)) in ["title", "glob", "process", "host"].iter().zip(got.iter().zip(want.iter())) {
        if g != w {
            println!("COUNT {k}: the file has {w} `{k}:` rule(s) but the loader holds {g}");
            bad += 1;
        }
    }

    // Per-rule findings are capped so one systemic break (say, a weight
    // zeroed) reads as a summary rather than 309 lines.
    const CAP: usize = 20;
    let mut findings: Vec<String> = Vec::new();
    let mut rules = 0;
    for (i, ln) in text.lines().enumerate() {
        let b = ln.split('#').next().unwrap_or("").trim();
        let Some(rest) = b.strip_prefix("title:") else { continue };
        let t = rest.trim();
        if t.is_empty() {
            continue;
        }
        rules += 1;
        let v = classify(&scam_shaped(t), &r);
        if !v.signals.iter().any(|s| s == "blocklist_title") {
            findings.push(format!("NOSIG line {}: {t:?} loads but does not fire blocklist_title", i + 1));
        } else if v.matched_rule.as_deref() != Some(t.to_ascii_lowercase().as_str()) {
            findings.push(format!("SHADOWED line {}: {t:?} is pre-empted by {:?}", i + 1, v.matched_rule));
        } else if v.decision != Decision::Block {
            findings.push(format!("NOBLOCK line {}: {t:?} fires but scores {} - it never dismisses", i + 1, v.score));
        }
    }

    for f in findings.iter().take(CAP) {
        println!("{f}");
    }
    if findings.len() > CAP {
        println!("... and {} more; {} of {rules} title rules fail", findings.len() - CAP, findings.len());
    }
    bad += findings.len();

    let ctl = classify(&scam_shaped("quarterly budget review"), &r);
    if ctl.decision == Decision::Block {
        println!("CONTROL a benign title in the same geometry is a Block (score {}) - \
                  the per-rule Block result above proves nothing", ctl.score);
        bad += 1;
    }

    if bad > 0 {
        std::process::exit(1);
    }
    println!("live blocklist: loader counts match the file ({} title / {} glob / {} process / {} host); \
              {rules}/{rules} title rules fire as themselves and Block; benign control scores {} (no Block)",
             got[0], got[1], got[2], got[3], ctl.score);
}
RS
rustc --edition 2021 -O -L "$TMP" --extern "muten_overlay=$TMP/libmuten_overlay.rlib" \
      -o "$TMP/probe" "$TMP/probe.rs" 2>"$TMP/probe.err" || {
    echo "FAIL  probe did not compile:"; sed 's/^/      /' "$TMP/probe.err" | head -20; exit 1; }

# shellcheck disable=SC2086
"$TMP/probe" "$BLOCKLIST" $_counts
