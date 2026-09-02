#!/bin/sh
# Audit-chain tamper-evidence check: run src/sink.rs's own tests for real.
#
# WHY THIS EXISTS. Threat S3 in the model is audit-log tampering, and the
# defense is the SHA-256 link chain in src/sink.rs. That module carries
# tests named `tampering_breaks_chain`, `refuses_to_open_tampered_log`,
# `verify_checkpoint_fails_with_tampered_head` and more - and not one had
# ever been executed, because sink.rs needs `serde_json`, `sha2`, `hex`
# and `tempfile`, none of which can be downloaded here. The product's
# central integrity claim rested on tests no machine had run.
#
# HOW IT STAYS HONEST.
#   * src/sink.rs and src/merkle.rs are compiled VERBATIM from src/ as
#     modules of a synthetic crate root. Nothing is copied or rewritten,
#     so the tests exercise the shipping code.
#   * The two types sink.rs imports from `crate::monitor` are MECHANICALLY
#     SLICED out of src/monitor.rs and each slice is asserted to appear
#     verbatim in that file. Only the `Serialize` derive is dropped (the
#     proc macro is unavailable offline, and sink.rs never uses it - it
#     reads the four fields directly).
#   * SHA-256 is the real thing, proven against NIST vectors by
#     scripts/check-merkle.sh, which this script runs first.
#   * The JSON stand-in is proven to round-trip parse->emit->parse before
#     any chain result is believed.
#
# Exit 0 = every sink.rs test passes on a verified hash and a round-trip
# verified JSON encoder.
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)
CRATE="$ROOT/crates/muten-overlay"
STUBS="$ROOT/scripts/offline-stubs"

command -v rustc   >/dev/null 2>&1 || { echo "SKIP  sink check - rustc not available";   exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP  sink check - python3 not available"; exit 0; }

TMP="${TMPDIR:-/tmp}/muten-sink-$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

# --- Stage 1: the hash primitive must already be proven ----------------
if ! _mk=$("$ROOT/scripts/check-merkle.sh" 2>&1); then
    echo "FAIL  refusing to run sink tests: the SHA-256/merkle foundation"
    echo "      did not verify. Fix scripts/check-merkle.sh first."
    printf '%s\n' "$_mk" | sed 's/^/      /'
    exit 1
fi

# --- Stage 2: slice the two monitor types, verbatim --------------------
python3 - "$CRATE/src/monitor.rs" "$TMP/monitor_slice.rs" <<'PY'
import re, sys, pathlib
src_path, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
src = src_path.read_text(encoding='utf-8')

def slice_item(text, header):
    start = text.index(header)
    i = text.index('{', start)
    depth, j = 0, i
    while True:
        if text[j] == '{': depth += 1
        elif text[j] == '}':
            depth -= 1
            if depth == 0: break
        j += 1
    return text[start:j+1]

event = slice_item(src, 'pub struct AuditEvent {')
sink  = slice_item(src, 'pub trait AuditSink {')
for name, s in (('AuditEvent', event), ('AuditSink', sink)):
    if s not in src:
        sys.exit(f'SLICE {name}: extracted text is not verbatim in monitor.rs')
    if not s.strip().endswith('}'):
        sys.exit(f'SLICE {name}: extraction did not close')
# FIDELITY: the field/method bodies are byte-identical to src/monitor.rs.
# Only the outer derive differs - `Serialize` needs a proc macro that is
# unavailable offline, and sink.rs reads the fields directly rather than
# serializing the struct, so dropping it cannot change what is tested.
out.write_text(
    '// SLICED VERBATIM from src/monitor.rs by scripts/check-sink.sh.\n'
    '// Do not edit. The only change from the source is the derive line:\n'
    '// `Serialize` is dropped (proc macro unavailable offline; sink.rs\n'
    '// never serializes the struct, it reads the four fields).\n'
    '#[derive(Debug, Clone, PartialEq, Eq)]\n'
    + event + '\n\n' + sink + '\n',
    encoding='utf-8')
print(f'monitor slice: AuditEvent ({event.count(chr(10))+1} lines) + '
      f'AuditSink ({sink.count(chr(10))+1} lines), both verbatim')
PY

# --- Stage 3: prove the JSON stand-in round-trips ----------------------
cat > "$TMP/jsonrt.rs" <<'RS'
#[path = "__SERDE__"]
mod serde_json;
use serde_json::Value;

fn main() {
    // Shapes the chain actually hashes: nested objects, arrays, integers,
    // non-ASCII, and the two mandatory escapes.
    // A raw control character (U+0001) is included deliberately: without
    // it the `\u00XX` escape branch is never exercised, and a wrong
    // encoder (e.g. one emitting Rust-style `\u{1}`) would slip through.
    let src = r#"{"a":1,"b":[1,2,{"c":-3}],"ctl":"a\u0001b","d":"日本\"q\"\\z","e":null,"f":true,"g":1.5}"#;
    let v: Value = serde_json::from_str(src).expect("parse");
    let emitted = serde_json::to_string(&v).expect("emit");
    let mut bad = 0;
    let v2: Value = match serde_json::from_str(&emitted) {
        Ok(v) => v,
        Err(e) => {
            // A re-parse failure means the encoder emitted something that
            // is not JSON at all - report it rather than panicking.
            println!("JSON-REPARSE failed on our own output ({e}): {emitted}");
            std::process::exit(1);
        }
    };
    let emitted2 = serde_json::to_string(&v2).expect("re-emit");
    if emitted != emitted2 {
        println!("JSON-ROUNDTRIP unstable:\n  1st {emitted}\n  2nd {emitted2}");
        bad += 1;
    }
    if v != v2 {
        println!("JSON-ROUNDTRIP value changed across re-parse");
        bad += 1;
    }
    // Integers must not drift into floats - the chain hashes the text.
    if !emitted.contains("\"a\":1,") {
        println!("JSON-INT integer 1 did not survive as `1`: {emitted}");
        bad += 1;
    }
    // Escapes must be JSON, not Rust Debug (`\u{1}` would be invalid JSON).
    if emitted.contains("\\u{") {
        println!("JSON-ESCAPE emitted Rust-style escape: {emitted}");
        bad += 1;
    }
    if !emitted.contains("\\u0001") {
        println!("JSON-ESCAPE control char not escaped as \\u0001: {emitted}");
        bad += 1;
    }
    if bad == 0 {
        println!("JSON round-trip: OK (parse -> emit -> parse is a fixpoint)");
    } else {
        std::process::exit(1);
    }
}
RS
sed -i "s|__SERDE__|$STUBS/serde_json.rs|" "$TMP/jsonrt.rs"
rustc --edition 2021 -O -o "$TMP/jsonrt" "$TMP/jsonrt.rs" 2>"$TMP/jsonrt.err" || {
    echo "FAIL  JSON round-trip probe did not compile:"; sed 's/^/      /' "$TMP/jsonrt.err"; exit 1; }
"$TMP/jsonrt" || { echo "FAIL  JSON stand-in does not round-trip - refusing to run chain tests"; exit 1; }

# --- Stage 4: build the deps and run sink.rs's tests -------------------
for c in thiserror serde; do
    rustc --edition 2021 --crate-type proc-macro --crate-name "$c" -O --out-dir "$TMP" "$STUBS/$c.rs" 2>>"$TMP/dep.err" || {
        echo "FAIL  offline $c derive shim did not build:"; sed 's/^/      /' "$TMP/dep.err"; exit 1; }
done
for c in sha2 hex serde_json tempfile; do
    rustc --edition 2021 --crate-type lib --crate-name "$c" -O --out-dir "$TMP" "$STUBS/$c.rs" 2>>"$TMP/dep.err" || {
        echo "FAIL  offline $c did not build:"; sed 's/^/      /' "$TMP/dep.err"; exit 1; }
done

cat > "$TMP/root.rs" <<'RS'
//! Synthetic crate root: the REAL src/sink.rs and src/merkle.rs compiled
//! verbatim, over a verbatim slice of the two monitor types they need.
#![allow(dead_code)]
pub mod monitor {
    include!("__MONITOR__");
}
#[path = "__MERKLE__"]
pub mod merkle;
#[path = "__SINK__"]
pub mod sink;
RS
sed -i "s|__MONITOR__|$TMP/monitor_slice.rs|; s|__MERKLE__|$CRATE/src/merkle.rs|; s|__SINK__|$CRATE/src/sink.rs|" "$TMP/root.rs"

if ! rustc --edition 2021 --test -O \
        --extern "sha2=$TMP/libsha2.rlib" \
        --extern "hex=$TMP/libhex.rlib" \
        --extern "serde_json=$TMP/libserde_json.rlib" \
        --extern "tempfile=$TMP/libtempfile.rlib" \
        --extern "thiserror=$TMP/libthiserror.so" \
        --extern "serde=$TMP/libserde.so" \
        -o "$TMP/sink-test" "$TMP/root.rs" 2>"$TMP/sink.err"; then
    echo "FAIL  src/sink.rs did not compile:"
    grep -E '^error' -A 6 "$TMP/sink.err" | head -60 | sed 's/^/      /'
    exit 1
fi

if ! "$TMP/sink-test" > "$TMP/sink.out" 2>&1; then
    echo "FAIL  audit-chain tests failed:"
    grep -E '^test .*FAILED|^failures:|^---- |panicked' "$TMP/sink.out" | sed 's/^/      /'
    exit 1
fi

_sink=$(grep -c '^test sink::' "$TMP/sink.out" || true)
_tamper=$(grep -cE '^test sink::.*(tamper|forg|break|refuse|detect)' "$TMP/sink.out" || true)
echo "audit chain: $_sink sink tests passed ($_tamper of them tamper/forgery cases)"
