#!/bin/sh
# Benign-URL false-positive check for the URL-driven signals (DR-25).
#
# WHY THIS EXISTS. Seven signals weighted 20-40 judge a window's URL, and
# three of them - including brand_impersonation at 40 - are NOT
# alert_shaped-gated, so they fire on the URL alone. Yet
# tests/benign_corpus.rs supplies no URLs at all (`grep -c "url: Some"`
# returns 0), so their false-positive safety rested entirely on reasoning
# written in code comments, with nothing executable checking it.
#
# WHY IT SLICES RATHER THAN IMPORTS. The functions live in src/lib.rs,
# which imports serde and therefore cannot be compiled in a registry-less
# environment. Rather than reimplement them - which would test a copy,
# not the product - this MECHANICALLY SLICES the real items out of
# src/lib.rs and src/rules.rs and asserts each slice appears VERBATIM in
# its source file. If anyone edits those functions, the slice either
# changes with them or the extraction fails loudly; it can never quietly
# test stale logic.
#
# Exit 0 = no legitimate URL fires, and both positive controls do fire.
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)
CRATE="$ROOT/crates/muten-overlay"

command -v rustc   >/dev/null 2>&1 || { echo "SKIP  URL-FP check — rustc not available";   exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP  URL-FP check — python3 not available"; exit 0; }

TMP="${TMPDIR:-/tmp}/muten-urlfp-$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

python3 - "$CRATE" "$TMP/sliced.rs" <<'PY'
import re, sys, pathlib
crate, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
lib   = (crate / 'src' / 'lib.rs').read_text(encoding='utf-8')
rules = (crate / 'src' / 'rules.rs').read_text(encoding='utf-8')

def slice_const(text, name):
    m = re.search(rf'^const {name}: &\[&str\] = &\[', text, re.M)
    if not m: sys.exit(f"SLICE FAILED: const {name} not found - lib.rs changed shape")
    end = text.find('\n];', m.start())
    if end == -1: sys.exit(f"SLICE FAILED: const {name} unterminated")
    return text[m.start():end+3] + "\n"

def slice_fn(text, sig, label):
    m = re.search(sig, text, re.M)
    if not m: sys.exit(f"SLICE FAILED: {label} not found - source changed shape")
    brace = text.find('{', m.start()); d = 0
    for i in range(brace, len(text)):
        if text[i] == '{': d += 1
        elif text[i] == '}':
            d -= 1
            if d == 0: return text[m.start():i+1] + "\n"
    sys.exit(f"SLICE FAILED: {label} unbalanced")

parts = [slice_const(lib, 'KNOWN_BRANDS'), slice_const(lib, 'BRAND_LURE_WORDS'),
         slice_fn(lib, r'^fn brand_impersonation\b', 'brand_impersonation'),
         slice_fn(lib, r'^fn levenshtein_distance\b', 'levenshtein_distance'),
         slice_fn(lib, r'^fn typosquat_brand\b', 'typosquat_brand'),
         slice_fn(lib, r'^fn combosquat\b', 'combosquat')]
host = slice_fn(rules, r'^pub\(crate\) fn host_str\b', 'host_str')

for p in parts:
    if p.rstrip('\n') not in lib: sys.exit("FIDELITY FAILED: slice not verbatim in lib.rs")
if host.rstrip('\n') not in rules: sys.exit("FIDELITY FAILED: slice not verbatim in rules.rs")

out.write_text("\n".join(parts) + "\n" + host.replace('pub(crate) fn', 'fn', 1), encoding='utf-8')
PY

sed "s|__CONFUSABLES__|$CRATE/src/confusables.rs|; s|__SLICED__|$TMP/sliced.rs|" \
    "$ROOT/scripts/url-probe/probe_main.rs" > "$TMP/main.rs"
rustc --edition 2021 -O -o "$TMP/probe" "$TMP/main.rs" 2>"$TMP/err" || {
    echo "FAIL  URL probe did not compile:"; sed 's/^/      /' "$TMP/err" | head -5; exit 1; }
"$TMP/probe"
