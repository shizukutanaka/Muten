#!/bin/sh
# muten overlay helper self-test.
#
# Run this on a target host BEFORE trusting the daemon with a helper, to
# confirm the helper satisfies the SubprocessController protocol on THIS
# machine's compositor / window manager. It exercises the three protocol
# verbs (see docs/OVERLAY_BLOCKING.md and any helper's header):
#
#   helper --probe        exit 0 if usable on this host
#   helper enumerate      print a JSON array of {id, window[, process]} to stdout
#   helper dismiss <id>   exit 0 acted / 2 already-gone / other = failure
#
# Usage:
#   ./selftest.sh ./muten-overlay-helper-linux.sh
#
# Exit 0 = probe + enumerate both pass (helper is wired correctly).
# Exit 1 = a required check failed (helper not usable as-is on this host).
#
# Dependency-light on purpose: pure POSIX sh. If python3 or jq happens to
# be present it does a deeper structural check of the enumerate JSON, but
# neither is required — the shape checks below run everywhere. The daemon
# itself does full typed validation on ingest, so this is a fast
# pre-flight, not a substitute for a real dry-run
# (`muten-overlay enforce` / `monitor`).

set -eu

helper="${1:-}"
if [ -z "$helper" ]; then
    echo "usage: $0 <path-to-helper>" 1>&2
    exit 1
fi
if [ ! -x "$helper" ]; then
    echo "FAIL: helper not found or not executable: $helper" 1>&2
    exit 1
fi

fail=0
note() { printf '%s\n' "$1"; }

# A hung helper is itself a deployment hazard (the daemon needs
# --helper-timeout-ms to survive one), and we must not let it hang this
# script either. Wrap every helper invocation in `timeout` when it's
# available (coreutils `timeout` on Linux, `gtimeout` on macOS via
# coreutils); fall back to a bare call if neither is present, keeping the
# "no hard dependency" promise. A timeout kill surfaces as exit 124.
HELPER_TIMEOUT="${MUTEN_SELFTEST_TIMEOUT:-10}"
if command -v timeout >/dev/null 2>&1; then
    run_helper() { timeout "$HELPER_TIMEOUT" "$@"; }
elif command -v gtimeout >/dev/null 2>&1; then
    run_helper() { gtimeout "$HELPER_TIMEOUT" "$@"; }
else
    run_helper() { "$@"; }
fi

# 1. --probe must exit 0 on a host where the helper is usable.
probe_rc=0
run_helper "$helper" --probe >/dev/null 2>&1 || probe_rc=$?
if [ "$probe_rc" -eq 0 ]; then
    note "PASS  --probe          exit 0 (helper reports usable on this host)"
elif [ "$probe_rc" -eq 124 ]; then
    note "FAIL  --probe          hung (killed after ${HELPER_TIMEOUT}s) — a helper that"
    note "                       blocks would stall each sweep; needs a fix or a tight"
    note "                       --helper-timeout-ms before deploying"
    fail=1
else
    note "FAIL  --probe          non-zero (helper reports it cannot run here —"
    note "                        wrong compositor/WM, missing tool, or no display)"
    fail=1
fi

# 2. enumerate must print a JSON array to stdout. A quiet desktop (no
#    windows) legitimately prints "[]" — that is a PASS, not a failure.
enum_rc=0
out="$(run_helper "$helper" enumerate 2>/dev/null)" || enum_rc=$?
# Strip leading/trailing whitespace for the shape check.
trimmed="$(printf '%s' "$out" | tr -d '\n\r\t ' )"
if [ "$enum_rc" -eq 124 ]; then
    # Already reported below; skip the shape checks (output is truncated
    # garbage from the kill, not a real verdict).
    note "FAIL  enumerate        hung (killed after ${HELPER_TIMEOUT}s) — same hazard as"
    note "                       a hung probe; the daemon would stall on this helper"
    fail=1
else
    case "$trimmed" in
        "["*"]")
            note "PASS  enumerate        printed a JSON array"
            ;;
        "")
            note "FAIL  enumerate        printed nothing (expected at least '[]')"
            fail=1
            ;;
        *)
            note "FAIL  enumerate        output is not a JSON array (got: $(printf '%.40s' "$out")…)"
            fail=1
            ;;
    esac
fi

# 2b. Opportunistic deep check — only if a JSON tool is available. Every
#     array element must be an object with a string "id" and an object
#     "window" (the enumerate contract; all window fields are optional /
#     serde-default, so an empty {} window is valid).
deep_check() {
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert isinstance(d, list), "top-level is not an array"
for i, e in enumerate(d):
    assert isinstance(e, dict), f"element {i} is not an object"
    assert isinstance(e.get("id"), str), f"element {i} missing string id"
    assert isinstance(e.get("window"), dict), f"element {i} missing object window"
' 2>/dev/null
        return $?
    fi
    return 2 # no tool → skip
}
if [ "$fail" -eq 0 ] && [ "$trimmed" != "[]" ]; then
    if deep_check; then
        note "PASS  enumerate shape  every element has a string id and an object window"
    elif [ $? -eq 2 ]; then
        note "SKIP  enumerate shape  (install python3 for a deep structural check)"
    else
        note "FAIL  enumerate shape  an element is missing a string id or object window"
        fail=1
    fi
fi

# 3. dismiss of an id that cannot exist must NOT report success — a helper
#    that blindly exits 0 for any id would make the daemon believe it
#    dismissed windows it never touched. Informational (some helpers exit
#    2 = already-gone, others 1 = error); a 0 here is the only real problem.
dismiss_rc=0
run_helper "$helper" dismiss "__muten_selftest_definitely_no_such_window__" \
    >/dev/null 2>&1 || dismiss_rc=$?
if [ "$dismiss_rc" -eq 0 ]; then
    note "WARN  dismiss(bogus id) exited 0 — helper may report false dismissals"
elif [ "$dismiss_rc" -eq 124 ]; then
    note "FAIL  dismiss(bogus id) hung (killed after ${HELPER_TIMEOUT}s) — the daemon"
    note "                       would stall trying to dismiss a window"
    fail=1
else
    note "PASS  dismiss(bogus id) non-zero (does not claim a dismissal it didn't do)"
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "RESULT: PASS — helper satisfies the protocol on this host."
    exit 0
else
    echo "RESULT: FAIL — do not deploy this helper here until the above is fixed."
    exit 1
fi
