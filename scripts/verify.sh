#!/bin/sh
# muten — one verification entrypoint.
#
# WHY THIS EXISTS. The project's stated requirement is "changes are verified
# before they land", and that had been conflated with "GitHub Actions runs
# them". Those are different things: the workflow in docs/ci/ci.yml still is
# not installed (only a repository owner can add .github/workflows/), and
# while everyone waited for that, an auto-merged dependency bump broke the
# advertised MSRV with nobody noticing (DR-23). This script decouples the
# requirement from the mechanism — anyone can run it now, and CI can simply
# call it so the two never drift apart.
#
# Usage:
#   ./scripts/verify.sh            # everything available on this machine
#   ./scripts/verify.sh --offline  # skip the Rust phase (no network/toolchain)
#
# Exit 0 = every check that RAN passed. Exit 1 = something failed.
#
# HONESTY RULE: a check that cannot run is reported as SKIP and named in the
# summary — never silently treated as a pass. A green run that skipped the
# Rust phase is explicitly *not* the same as a verified build, and the
# summary says so.

set -eu

cd "$(dirname "$0")/.."
ROOT=$(pwd)
CRATE="$ROOT/crates/muten-overlay"
HELPERS="$ROOT/installer/overlay-helper"

offline=0
[ "${1:-}" = "--offline" ] && offline=1

pass=0; fail=0; skip=0
ok()   { printf '  PASS  %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); }
skp()  { printf '  SKIP  %s — %s\n' "$1" "$2"; skip=$((skip+1)); }

echo "muten verification — $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo
echo "[1/3] Shell + data checks (no toolchain required)"

# 1a. Every shipped POSIX helper must parse.
for f in "$HELPERS"/*.sh "$ROOT"/scripts/*.sh; do
    [ -e "$f" ] || continue
    if sh -n "$f" 2>/dev/null; then ok "sh -n $(basename "$f")"
    else bad "sh -n $(basename "$f")"; fi
done

# 1b. The blocklist must not contain rules the loader would silently drop
#     or that can never match. See lint-blocklist.sh / DR-22.
if [ -x "$HELPERS/lint-blocklist.sh" ]; then
    if "$HELPERS/lint-blocklist.sh" "$ROOT/examples/overlay-blocklist.txt" >/dev/null 2>&1; then
        ok "blocklist lints clean"
    else
        bad "blocklist lint (run $HELPERS/lint-blocklist.sh for detail)"
    fi
else
    skp "blocklist lint" "lint-blocklist.sh not executable"
fi

# 1c. Cargo.lock must agree with the exact pins in Cargo.toml. A drift here
#     is how an unverified dependency change reaches a build (DR-23).
if [ -f "$CRATE/Cargo.lock" ] && command -v python3 >/dev/null 2>&1; then
    if python3 - "$CRATE" <<'PY'
import re, sys, pathlib
crate = pathlib.Path(sys.argv[1])
toml = (crate / 'Cargo.toml').read_text(encoding='utf-8')
lock = (crate / 'Cargo.lock').read_text(encoding='utf-8')
locked = dict(re.findall(r'\[\[package\]\]\s*\nname = "([^"]+)"\nversion = "([^"]+)"', lock))
bad = []
for name, ver in re.findall(r'^(\w[\w-]*)\s*=\s*\{?[^\n]*?"=([0-9][^"]*)"', toml, re.M):
    if name in locked and locked[name] != ver:
        bad.append(f"{name}: Cargo.toml pins ={ver} but Cargo.lock has {locked[name]}")
if bad:
    print("\n".join("      " + b for b in bad), file=sys.stderr)
    sys.exit(1)
PY
    then ok "Cargo.lock matches Cargo.toml pins"
    else bad "Cargo.lock drifted from Cargo.toml pins"; fi
else
    skp "Cargo.lock/Cargo.toml sync" "no Cargo.lock or no python3"
fi

# 1d. dependabot.yml must not carry keys Dependabot v2 rejects (DR-24):
#     an unrecognized key is a config error that can halt updates.
if [ -f "$ROOT/.github/dependabot.yml" ]; then
    if grep -qE '^\s*automerge:' "$ROOT/.github/dependabot.yml"; then
        bad "dependabot.yml contains 'automerge:' — not a valid v2 key (DR-24)"
    else
        ok "dependabot.yml has no invalid 'automerge:' key"
    fi
else
    skp "dependabot.yml check" "file absent"
fi

echo
echo "[2/3] Rust checks"

# Probe whether cargo can resolve dependencies at all, BOUNDED BY A TIMEOUT.
# On a machine with a blocked or slow registry `cargo metadata` can sit for
# minutes retrying the network; without the bound this script hangs instead
# of reporting a skip — which is exactly the "verification never finishes"
# failure it exists to prevent. Falls back to an unbounded call only when no
# timeout(1) is available.
cargo_probe() {
    if command -v timeout >/dev/null 2>&1; then
        timeout "${MUTEN_CARGO_PROBE_TIMEOUT:-20}" cargo metadata --format-version 1 >/dev/null 2>&1
    elif command -v gtimeout >/dev/null 2>&1; then
        gtimeout "${MUTEN_CARGO_PROBE_TIMEOUT:-20}" cargo metadata --format-version 1 >/dev/null 2>&1
    else
        cargo metadata --format-version 1 >/dev/null 2>&1
    fi
}

if [ "$offline" -eq 1 ]; then
    skp "cargo fmt/clippy/build/test" "--offline requested"
elif ! command -v cargo >/dev/null 2>&1; then
    skp "cargo fmt/clippy/build/test" "cargo not installed"
elif ! (cd "$CRATE" && cargo_probe) ; then
    skp "cargo fmt/clippy/build/test" "cargo cannot resolve dependencies here (offline/blocked registry)"
else
    run_cargo() { # $1 = label, rest = command
        _label=$1; shift
        if (cd "$CRATE" && "$@" >/dev/null 2>&1); then ok "$_label"
        else bad "$_label"; fi
    }
    run_cargo "cargo fmt --check"                 cargo fmt --check
    run_cargo "cargo clippy -D warnings"          cargo clippy --all-targets -- -D warnings
    run_cargo "cargo build --all-targets"         cargo build --all-targets
    run_cargo "cargo test"                        cargo test
fi

echo
echo "[3/3] MSRV consistency"

# The crate advertises a rust-version; a dependency whose own MSRV is higher
# silently breaks it for anyone on the promised toolchain (DR-23). Verifying
# dependency MSRVs needs the registry, so this only checks what is knowable
# offline and says plainly when it cannot do more.
MSRV=$(grep -E '^rust-version' "$CRATE/Cargo.toml" | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
if [ -n "$MSRV" ]; then
    ok "crate declares rust-version = $MSRV"
    if command -v rustc >/dev/null 2>&1; then
        printf '  NOTE  local rustc is %s\n' "$(rustc --version | awk '{print $2}')"
    fi
    skp "dependency MSRV audit" "needs the registry; use 'cargo msrv' or check crates.io rust_version (see DR-23)"
else
    bad "no rust-version in Cargo.toml — the MSRV guarantee is unenforceable"
fi

echo
echo "───────────────────────────────────────────────"
printf 'passed %s   failed %s   skipped %s\n' "$pass" "$fail" "$skip"
if [ "$skip" -gt 0 ]; then
    echo "NOTE: skipped checks are NOT passes. A run that skipped the Rust"
    echo "      phase has not verified that the crate compiles or tests green."
fi
if [ "$fail" -eq 0 ]; then
    echo "RESULT: PASS (for the checks that ran)"
    exit 0
else
    echo "RESULT: FAIL"
    exit 1
fi
