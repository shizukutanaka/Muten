#!/bin/sh
# Tamper-evidence check: run the Merkle audit-chain tests for real.
#
# WHY THIS EXISTS. The product's central trust claim is that the audit
# log is tamper-evident: an RFC 6962 Merkle root plus inclusion proofs.
# src/merkle.rs carries 15 tests pinning that behaviour - but they had
# never been executed once, because merkle.rs imports `sha2` and `hex`
# and this environment cannot reach static.crates.io. A trust claim
# backed only by unrun tests is a claim, not evidence.
#
# WHY THE SHA-256 HERE IS REAL. Faking the hash would void the
# known-answer tests (`merkle_root(&[])` must equal SHA-256("")). So
# scripts/offline-stubs/sha2.rs is a genuine FIPS 180-4 implementation,
# and this script proves it BEFORE trusting any merkle result: it hashes
# the two published NIST vectors and aborts if either mismatches. Only
# on a verified primitive does it run the merkle tests.
#
# Exit 0 = SHA-256 matches both NIST vectors AND every merkle test passes.
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)
CRATE="$ROOT/crates/muten-overlay"
STUBS="$ROOT/scripts/offline-stubs"

command -v rustc >/dev/null 2>&1 || { echo "SKIP  merkle check - rustc not available"; exit 0; }

TMP="${TMPDIR:-/tmp}/muten-merkle-$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

# --- Stage 1: prove the primitive against published NIST vectors -------
# FIPS 180-4 / NIST CSRC known answers. If these do not match, the SHA-256
# in scripts/offline-stubs/sha2.rs is not SHA-256 and nothing downstream
# may be believed.
cat > "$TMP/selftest.rs" <<'RS'
#[path = "__SHA2__"]
mod sha2;
#[path = "__HEX__"]
mod hex;
use sha2::{Digest, Sha256};

fn h(data: &[u8]) -> String {
    let mut d = Sha256::new();
    d.update(data);
    hex::encode(d.finalize())
}

fn main() {
    let mut bad = 0;
    // NIST vector 1: the empty message.
    let v1 = ("\"\"", h(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    // NIST vector 2: "abc".
    let v2 = ("\"abc\"", h(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    // NIST vector 3: the 448-bit two-block message (exercises multi-block
    // compression and the length-encoded padding tail).
    let v3 = (
        "\"abcdbcde...\" (56 bytes)",
        h(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
    // NIST vector 4: one million 'a' - exercises the streaming path over
    // 15625 blocks, where any buffer-boundary bug shows up.
    let million = vec![b'a'; 1_000_000];
    let v4 = (
        "1,000,000 x 'a'",
        h(&million),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    );
    for (name, got, want) in [v1, v2, v3, v4] {
        if got != want {
            println!("SHA256-MISMATCH {name}: got {got} want {want}");
            bad += 1;
        }
    }
    // hex round-trip: merkle.rs decodes proof elements and rejects junk.
    let round = hex::decode(hex::encode([0x00u8, 0x7f, 0x80, 0xff])).expect("valid hex");
    if round != vec![0x00u8, 0x7f, 0x80, 0xff] {
        println!("HEX-ROUNDTRIP failed: {round:?}");
        bad += 1;
    }
    if hex::decode("0").is_ok() || hex::decode("zz").is_ok() {
        println!("HEX-DECODE accepted malformed input");
        bad += 1;
    }
    if bad == 0 {
        println!("SHA-256 self-test: OK (4 NIST vectors) + hex round-trip: OK");
    } else {
        std::process::exit(1);
    }
}
RS
sed -i "s|__SHA2__|$STUBS/sha2.rs|; s|__HEX__|$STUBS/hex.rs|" "$TMP/selftest.rs"

if ! rustc --edition 2021 -O -o "$TMP/selftest" "$TMP/selftest.rs" 2>"$TMP/selftest.err"; then
    echo "FAIL  SHA-256 self-test did not compile:"
    sed 's/^/      /' "$TMP/selftest.err"
    exit 1
fi
if ! "$TMP/selftest"; then
    echo "FAIL  SHA-256 self-test failed the NIST vectors - refusing to run"
    echo "      the merkle tests on an unverified hash primitive."
    exit 1
fi

# --- Stage 2: run the real merkle.rs tests on the verified primitive ----
# merkle.rs is compiled AS ITS OWN CRATE ROOT, verbatim from src/. Nothing
# is copied or reimplemented, so the tests exercise the shipping code.
# The stub sources are compiled directly as crate roots - no copy, no
# include! wrapper - so what merkle.rs links is exactly the file the
# self-test above validated.
rustc --edition 2021 --crate-type lib --crate-name sha2 -O --out-dir "$TMP" "$STUBS/sha2.rs" 2>"$TMP/dep.err" || {
    echo "FAIL  offline sha2 did not build:"; sed 's/^/      /' "$TMP/dep.err"; exit 1; }
rustc --edition 2021 --crate-type lib --crate-name hex -O --out-dir "$TMP" "$STUBS/hex.rs" 2>>"$TMP/dep.err" || {
    echo "FAIL  offline hex did not build:"; sed 's/^/      /' "$TMP/dep.err"; exit 1; }

if ! rustc --edition 2021 --test -O \
        --extern "sha2=$TMP/libsha2.rlib" --extern "hex=$TMP/libhex.rlib" \
        -o "$TMP/merkle-test" "$CRATE/src/merkle.rs" 2>"$TMP/merkle.err"; then
    echo "FAIL  src/merkle.rs did not compile:"
    sed 's/^/      /' "$TMP/merkle.err"
    exit 1
fi

if ! "$TMP/merkle-test" > "$TMP/merkle.out" 2>&1; then
    echo "FAIL  merkle tamper-evidence tests failed:"
    grep -E '^(test .*FAILED|failures:|---- )|panicked' "$TMP/merkle.out" | sed 's/^/      /'
    exit 1
fi

_ran=$(grep -c '^test .* \.\.\. ok$' "$TMP/merkle.out" || true)
echo "merkle tamper-evidence: $_ran tests passed on a NIST-verified SHA-256"
