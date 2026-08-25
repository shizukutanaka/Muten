#!/bin/sh
# Verify that numeric claims in the docs still match measured reality.
#
# WHY THIS EXISTS. The most frequently recurring defect in this project
# was never a code bug — it was prose going quietly false as the product
# grew. Five separate claims had drifted before this check existed: the
# advertised MSRV (broken by a dependency bump), the signal count (66 →
# actually 89), the unit-test count (1331 → 1333), the Japanese blocklist
# size (21 → 86), and "all four helpers emit age_ms:0" (fixed long
# before the sentence was). Each was caught by hand. Relying on someone
# re-auditing by hand is the actual defect; this automates it.
#
# WHY OPT-IN MARKERS, not pattern matching. A naive `grep "N unit tests"`
# would fire on claims that are *correct*: the 1331 that describes the
# `549df29` baseline, the 675 that describes confusables.rs alone, the
# per-fix counts in GAP_ANALYSIS. A check that cries wolf gets ignored,
# which is worse than no check. So only claims explicitly marked with an
# HTML comment are validated — invisible in rendered Markdown, and
# marking one is a deliberate act:
#
#     <!--claim:unit_tests-->1,333 unit tests
#
# The number validated is the FIRST number after the marker (thousands
# separators allowed). Historical statements simply carry no marker.
#
# ADDING A CLAIM: add the key to ground_truth() below, then put
# <!--claim:KEY--> immediately before the number in the doc.
#
# Exit 0 = every marked claim matches. Exit 1 = at least one drifted.

set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)
CRATE="$ROOT/crates/muten-overlay"
BLOCKLIST="$ROOT/examples/overlay-blocklist.txt"

command -v python3 >/dev/null 2>&1 || {
    echo "SKIP  doc-claim check — python3 not available"; exit 0; }

python3 - "$ROOT" "$CRATE" "$BLOCKLIST" <<'PY'
import re, sys, pathlib

root, crate, blocklist = (pathlib.Path(a) for a in sys.argv[1:4])

def jp(s):
    return any('぀' <= c <= 'ヿ' or '一' <= c <= '鿿' for c in s)

def rules(prefix):
    n = 0
    for ln in blocklist.read_text(encoding='utf-8').splitlines():
        b = ln.split('#', 1)[0].strip()
        if b.startswith(prefix + ':') and b[len(prefix) + 1:].strip():
            n += 1
    return n

def jp_title_rules():
    n = 0
    for ln in blocklist.read_text(encoding='utf-8').splitlines():
        b = ln.split('#', 1)[0].strip()
        if b.startswith('title:'):
            v = b[6:].strip()
            if v and jp(v):
                n += 1
    return n

def signals():
    src = (crate / 'src' / 'lib.rs').read_text(encoding='utf-8')
    m = re.search(r'pub fn all_signals\(\).*?const NAMES: &\[&str\] = &\[(.*?)\n    \];',
                  src, re.S)
    return len(set(re.findall(r'"([a-z_]+)"', m.group(1))))

def unit_tests():
    return sum(f.read_text(encoding='utf-8').count('#[test]')
               for f in (crate / 'src').glob('*.rs'))

def benign_titles():
    bc = (crate / 'tests' / 'benign_corpus.rs').read_text(encoding='utf-8')
    arr = re.search(r'const BENIGN_TITLES: &\[&str\] = &\[(.*?)\n\];', bc, re.S).group(1)
    return len(re.findall(r'^\s*"((?:[^"\\]|\\.)*)"\s*,', arr, re.M))

TRUTH = {
    'signals':        signals(),
    'unit_tests':     unit_tests(),
    'title_rules':    rules('title'),
    'glob_rules':     rules('glob'),
    'process_rules':  rules('process'),
    'jp_title_rules': jp_title_rules(),
    'benign_titles':  benign_titles(),
}

docs = [root / 'README.md'] + sorted((root / 'docs').glob('*.md')) \
     + [root / 'installer' / 'overlay-helper' / 'README.md']

marker = re.compile(r'<!--\s*claim:([a-z_]+)\s*-->\s*\**([0-9][0-9,]*)')
found, bad = 0, 0
for d in docs:
    if not d.exists():
        continue
    for i, line in enumerate(d.read_text(encoding='utf-8').splitlines(), 1):
        for key, raw in marker.findall(line):
            found += 1
            rel = d.relative_to(root)
            if key not in TRUTH:
                print(f"  ERROR {rel}:{i}: unknown claim key {key!r} — "
                      f"add it to ground_truth in check-doc-claims.sh")
                bad += 1
                continue
            claimed, actual = int(raw.replace(',', '')), TRUTH[key]
            if claimed != actual:
                print(f"  ERROR {rel}:{i}: claim:{key} says {claimed:,} "
                      f"but the tree measures {actual:,}")
                bad += 1

unmarked = [k for k in TRUTH if not any(
    re.search(rf'<!--\s*claim:{k}\s*-->', d.read_text(encoding='utf-8'))
    for d in docs if d.exists())]
if unmarked:
    print(f"  INFO  measurable but unmarked (not enforced): {', '.join(sorted(unmarked))}")

print(f"  {'PASS' if bad == 0 else 'FAIL'}  {found} marked claim(s) checked, {bad} drifted")
sys.exit(1 if bad else 0)
PY
