#!/bin/sh
# Run the WHOLE crate's tests without a package registry.
#
# WHY THIS EXISTS. Until now the two tests that carry the product's
# central behavioural claims could only be type-checked, never run:
#   * tests/benign_corpus.rs   - the "0 false positives" claim;
#   * tests/scoring_scenarios.rs - the detect->DISMISS claim, i.e. that a
#     detected scam window's score actually crosses BLOCK_THRESHOLD.
# Both need `classify()`, which needs the whole crate, which needs serde's
# derive macros - and this environment's egress policy denies
# static.crates.io. So `scripts/check-detection.sh` could only assert that
# *a signal fires*, never that the window is blocked. A signal firing at
# 20 points against a BLOCK threshold of 100 dismisses nothing.
#
# WHAT MAKES THIS HONEST. The derive shims in scripts/offline-stubs/ are
# narrow, not permissive: they reproduce named-field structs, unit-variant
# enums with `rename_all = "snake_case"`, externally-tagged single-field
# tuple variants and `#[serde(default)]`, and **panic at compile time** on
# anything else. A blanket `impl<T> Serialize for T {}` would accept code
# real serde rejects and make a green read stronger than it is; this fails
# loudly on whatever it has not been taught.
#
# WHAT THIS PROVES: the behaviour of `classify()` and everything under it,
# on the real, unmodified src/ and tests/.
# WHAT IT DOES NOT PROVE: serde integration, and it is NOT the answer to
# "does the crate compile under real serde" - only `cargo build` is. Nor
# does it cover the proptest suites or cli_contract; see the note at the
# end for why those are deliberately left out rather than faked.
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)
CRATE="$ROOT/crates/muten-overlay"
STUBS="$ROOT/scripts/offline-stubs"

command -v rustc >/dev/null 2>&1 || { echo "SKIP  crate check - rustc not available"; exit 0; }

TMP="${TMPDIR:-/tmp}/muten-crate-$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

for c in thiserror serde; do
    rustc --edition 2021 --crate-type proc-macro --crate-name "$c" -O --out-dir "$TMP" \
          "$STUBS/$c.rs" 2>>"$TMP/dep.err" || {
        echo "FAIL  offline $c derive shim did not build:"; sed 's/^/      /' "$TMP/dep.err"; exit 1; }
done
for c in sha2 hex serde_json tempfile; do
    rustc --edition 2021 --crate-type lib --crate-name "$c" -O --out-dir "$TMP" \
          "$STUBS/$c.rs" 2>>"$TMP/dep.err" || {
        echo "FAIL  offline $c did not build:"; sed 's/^/      /' "$TMP/dep.err"; exit 1; }
done

EXTERNS="--extern serde=$TMP/libserde.so --extern thiserror=$TMP/libthiserror.so \
         --extern serde_json=$TMP/libserde_json.rlib --extern sha2=$TMP/libsha2.rlib \
         --extern hex=$TMP/libhex.rlib --extern tempfile=$TMP/libtempfile.rlib"

cd "$CRATE"

# --- The crate's own unit tests, from the real src/lib.rs -------------
# shellcheck disable=SC2086
if ! rustc --edition 2021 --test -O -o "$TMP/unit" $EXTERNS src/lib.rs 2>"$TMP/unit.err"; then
    echo "FAIL  the crate did not compile:"
    grep -E '^error' -A 6 "$TMP/unit.err" | head -40 | sed 's/^/      /'
    exit 1
fi
if ! "$TMP/unit" > "$TMP/unit.out" 2>&1; then
    echo "FAIL  crate unit tests failed:"
    grep -E '^test .*FAILED|^failures:|panicked' "$TMP/unit.out" | head -20 | sed 's/^/      /'
    exit 1
fi
_unit=$(grep -oE '^test result: ok\. [0-9]+' "$TMP/unit.out" | grep -oE '[0-9]+$')

# The library form the integration suites link against.
# shellcheck disable=SC2086
rustc --edition 2021 --crate-type lib --crate-name muten_overlay -O --out-dir "$TMP" \
      $EXTERNS src/lib.rs 2>"$TMP/lib.err" || {
    echo "FAIL  crate rlib did not build:"; sed 's/^/      /' "$TMP/lib.err"; exit 1; }

# --- The integration suites that need only the crate -------------------
SUITES="benign_corpus blocklist_coverage composed_evasion helper_contract scoring_scenarios"
_total=0
_report=""
for s in $SUITES; do
    if ! rustc --edition 2021 --test -O -L "$TMP" -o "$TMP/t_$s" \
            --extern "muten_overlay=$TMP/libmuten_overlay.rlib" \
            --extern "serde_json=$TMP/libserde_json.rlib" \
            --extern "tempfile=$TMP/libtempfile.rlib" \
            "tests/$s.rs" 2>"$TMP/e_$s"; then
        echo "FAIL  tests/$s.rs did not compile:"
        grep -E '^error' -A 5 "$TMP/e_$s" | head -20 | sed 's/^/      /'
        exit 1
    fi
    if ! "$TMP/t_$s" > "$TMP/o_$s" 2>&1; then
        echo "FAIL  tests/$s.rs failed:"
        grep -E '^test .*FAILED|^failures:|panicked' "$TMP/o_$s" | head -20 | sed 's/^/      /'
        exit 1
    fi
    n=$(grep -oE '^test result: ok\. [0-9]+' "$TMP/o_$s" | grep -oE '[0-9]+$')
    _total=$((_total + n))
    _report="$_report $s=$n"
done

echo "crate tests: $_unit unit +$_report ($_total integration) — all green"
# Deliberately NOT run here, and NOT faked:
#   * the three proptest suites - a property test's substance is its input
#     DISTRIBUTION, so a home-made generator would test something else
#     while reading the same. Their regex strategies would have to be
#     reimplemented, and a green from that would be misleading.
#   * tests/cli_contract.rs - needs clap and the built binary.
