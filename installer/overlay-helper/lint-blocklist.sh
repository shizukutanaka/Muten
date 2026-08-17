#!/bin/sh
# muten blocklist linter.
#
# The blocklist is muten's most reliable detection path on real hosts, it
# is operator-editable and hot-reloaded — and `Ruleset::from_lines`
# (crates/muten-overlay/src/rules.rs) **skips malformed lines silently**:
# "skipped silently; a malformed entry never aborts the load". A rule you
# fat-finger therefore produces no feedback at all; it simply never
# matches, and the window it was meant to catch goes unblocked.
#
# `muten-overlay rules <file>` reports rule *counts* (and a composite
# weight warning), but never says which line was dropped, and needs a
# compiled binary. This script is the complement: it names the offending
# line, and runs anywhere with a POSIX shell.
#
# Usage:
#   ./lint-blocklist.sh ../../examples/overlay-blocklist.txt
#
# Exit 0 = no ERRORs (WARN/INFO may still be printed).
# Exit 1 = at least one ERROR: a rule that the loader will silently drop
#          or silently reinterpret.
#
# Every ERROR/WARN check below mirrors a specific behaviour of
# `Ruleset::from_lines`; the INFO checks are heuristic (see their note).

set -eu

file="${1:-}"
if [ -z "$file" ]; then
    echo "usage: $0 <blocklist-file>" 1>&2
    exit 1
fi
if [ ! -r "$file" ]; then
    echo "FAIL: cannot read blocklist: $file" 1>&2
    exit 1
fi

errors=0
warns=0

err()  { echo "ERROR line $1: $2"; errors=$((errors + 1)); }
warn() { echo "WARN  line $1: $2"; warns=$((warns + 1)); }

# The loader's recognized prefixes, exactly as spelled in rules.rs'
# `strip_prefix` chain. Matching there is CASE-SENSITIVE and allows no
# space before the colon, so "Title:" / "title :" are NOT title rules.
lineno=0
while IFS= read -r raw || [ -n "$raw" ]; do
    lineno=$((lineno + 1))

    # `strip_comment` cuts at the FIRST '#', whitespace or not, then trims.
    body=${raw%%#*}
    # trim leading/trailing whitespace (POSIX-safe)
    body=$(printf '%s' "$body" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

    # Blank or comment-only line: nothing to check.
    [ -z "$body" ] && continue

    case "$body" in
        host:*|title:*|glob:*|process:*|phone:*|composite:*|weight:*)
            prefix=${body%%:*}
            value=${body#*:}
            value=$(printf '%s' "$value" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

            # A pattern that is empty once the comment is stripped is
            # dropped by the loader's `if !key.is_empty()` guard.
            if [ -z "$value" ]; then
                err "$lineno" "'$prefix:' has an empty pattern — the loader drops it silently"
                continue
            fi

            # phone: rules with fewer than 7 digits are rejected as
            # over-broad (rules.rs: `if key.len() >= 7`, and the
            # short_phone_rule_is_rejected test).
            if [ "$prefix" = "phone" ]; then
                digits=$(printf '%s' "$value" | tr -cd '0-9')
                dlen=${#digits}
                if [ "$dlen" -lt 7 ]; then
                    err "$lineno" "'phone:' has only $dlen digits (< 7) — dropped as over-broad"
                fi
            fi

            # composite: conditions that depend on `origin` can never hold,
            # because every shipped helper hard-codes "origin":"unknown"
            # (audit item DR-20). A rule using them parses fine and then
            # never fires — dead weight that looks active. The shipped
            # blocklist's own `unsolicited_blocklist_hit` rule is an
            # example. Re-check this if a helper ever starts reporting a
            # real origin (WO-11), and drop the warning then.
            if [ "$prefix" = "composite" ]; then
                for cond in $value; do
                    case "$cond" in
                        unsolicited|user_initiated)
                            warn "$lineno" "composite condition '$cond' depends on \`origin\`, which every shipped helper reports as \"unknown\" — this rule can never fire (see DR-20)" ;;
                    esac
                done
            fi

            # weight: must be `<signal> <integer>`; anything else is
            # silently ignored by the loader's parse chain.
            if [ "$prefix" = "weight" ]; then
                wsig=$(printf '%s' "$value" | awk '{print $1}')
                wval=$(printf '%s' "$value" | awk '{print $2}')
                case "$wval" in
                    ''|*[!0-9-]*)
                        warn "$lineno" "'weight: $wsig ...' value '$wval' is not an integer — silently ignored" ;;
                esac
            fi
            ;;
        *)
            # Anything else falls through the loader's prefix chain into
            # `else { /* Bare line → treat as host */ }`. That silently
            # turns a mistyped rule into a host rule, which normalize_host
            # then almost certainly rejects — so the rule vanishes.
            err "$lineno" "unrecognized prefix in '$(printf '%.40s' "$body")' — parsed as a *host* rule (prefixes are case-sensitive and take no space before ':')"
            ;;
    esac

    # '#' can never appear literally in a pattern: strip_comment always
    # cuts at the first one, so text after it is lost.
    #
    # Detecting an *intended* literal '#' is genuinely ambiguous: the
    # motivating case — a TOAD case-number lure, `title: your case #4821
    # is under review` — has a space before the '#' and is therefore
    # indistinguishable from a trailing comment by spacing alone. So we
    # use two signals that a comment almost never shows:
    #   1. '#' immediately followed by a digit ("#4821"): comments start
    #      with a word, case/ticket numbers with a digit.
    #   2. '#' with no whitespace before it ("case#4821").
    case "$raw" in
        *\#[0-9]*)
            warn "$lineno" "'#' followed by a digit looks like a literal case/ticket number — patterns cannot contain '#', everything from it is cut" ;;
        *[!\ ]\#*)
            warn "$lineno" "'#' with no space before it — patterns cannot contain a literal '#', text after it is cut" ;;
    esac
done < "$file"

# ── Heuristic pass (INFO only) ───────────────────────────────────────
# APPROXIMATE: this lowercases and collapses whitespace, whereas the real
# matcher runs the full Rust `normalize_for_match` pipeline (confusable
# folding, leet folding, ligature expansion, …). Treat these as hints.
if command -v python3 >/dev/null 2>&1; then
    python3 - "$file" <<'PY' || true
import re, sys
from collections import Counter

titles = []
for raw in open(sys.argv[1], encoding='utf-8', errors='replace'):
    body = raw.split('#', 1)[0].strip()
    if body.startswith('title:'):
        v = body[len('title:'):].strip()
        if v:
            titles.append(v)

def approx(s):
    return re.sub(r'\s+', ' ', s.strip().lower())

keys = [approx(t) for t in titles]

for k, c in Counter(keys).items():
    if c > 1:
        print(f"INFO  duplicate 'title:' pattern appears {c}x: {k!r}")

uniq = sorted(set(keys), key=len)
for i, b in enumerate(uniq):
    for a in uniq[:i]:
        if a != b and a in b:
            print(f"INFO  'title: {b}' is shadowed by shorter 'title: {a}' "
                  f"(substring match makes the longer rule unreachable)")
            break
PY
else
    echo "INFO  (install python3 for the duplicate / shadowed-rule pass)"
fi

echo
if [ "$errors" -eq 0 ]; then
    echo "RESULT: PASS — no rules will be silently dropped ($warns warning(s))."
    exit 0
else
    echo "RESULT: FAIL — $errors rule(s) would be silently dropped or reinterpreted."
    exit 1
fi
