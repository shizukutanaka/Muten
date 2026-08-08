#!/bin/sh
# muten overlay helper — Linux / X11 reference implementation.
#
# Protocol (see docs/OVERLAY_BLOCKING.md). muten-overlay's
# SubprocessController invokes this with one of:
#
#   helper --probe        exit 0 if usable on this host
#   helper enumerate      print JSON array of {id, window} to stdout
#   helper dismiss <id>   exit 0 acted / 2 already-gone / other failure
#
# This reference uses wmctrl + xprop, which are widely packaged and
# require no compiled code (keeping muten itself unsafe-free; any FFI
# would live in a compiled helper, not here). Adapt for Wayland
# (e.g. via the compositor's IPC) or replace with a signed binary in
# locked-down fleets.
#
# NOTE: enumeration here is best-effort. `has_close_button` and
# `blocks_input` are derived from real EWMH window-manager properties
# (see enumerate() below); `origin` ("unsolicited vs user-initiated")
# has no X11 equivalent and is conservatively defaulted to "unknown" —
# muten's classifier treats unknown origin as neutral, which biases
# toward Suspicious (review) rather than Block (dismiss), the safe
# direction (audit DR-2).

set -eu

cmd="${1:-}"

probe() {
    command -v wmctrl >/dev/null 2>&1 || exit 1
    command -v xprop  >/dev/null 2>&1 || exit 1
    [ -n "${DISPLAY:-}" ] || exit 1
    exit 0
}

# Escape a string for embedding in a JSON string literal.
#
# Order matters: escape backslash and double-quote first, then fold the
# whitespace control chars (tab/CR/LF) to spaces, then DELETE any other
# ASCII control character (0x00-0x1F: ESC, form-feed, bell, NUL, …).
# JSON (RFC 8259) forbids raw control chars in strings, so a title
# carrying one — which a scam overlay can trivially do to break the
# enumerator — would otherwise produce invalid JSON that the daemon's
# strict serde_json parser rejects for the WHOLE enumerate array, blinding
# that entire sweep. Deleting (not spacing) the stray control chars also
# defeats the evasion itself: "vi<ESC>rus" collapses to "virus", which
# still matches the blocklist. muten's own normalizer strips control chars
# too, so this only makes the two sides consistent.
json_escape() {
    # shellcheck disable=SC1003
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
        | tr '\t\r\n' '   ' | tr -d '[:cntrl:]'
}

# ── age_ms: first-seen tracking (DR-20 / WO-11) ──────────────────────
#
# The helper is re-spawned every sweep, so it has no memory of its own —
# which is the only reason `age_ms` used to be hard-coded 0. muten treats
# `age_ms == 0` as "the enumerator could not tell" (NOT as "brand new"),
# so a constant 0 silently disabled the `very_new` signal on every real
# host. We restore real ages by persisting a first-seen timestamp per
# window id across invocations.
#
# Honesty rule: we report only what we can actually measure — the time
# since *this helper first observed the window*. On the sweep where a
# window first appears we emit 0 ("unknown"), because its true age is
# somewhere in [0, sweep-interval] and inventing a sub-second value would
# fabricate the `very_new` signal (+10) for every newly-opened benign
# window. On later sweeps the elapsed time is real. `very_new` therefore
# fires only when the daemon sweeps fast enough to genuinely observe a
# sub-second age — which is the truthful behaviour.
STATE_FILE="${MUTEN_OVERLAY_STATE:-${XDG_RUNTIME_DIR:-/tmp}/muten-overlay-seen.$(id -u 2>/dev/null || echo 0)}"

now_ms() {
    # GNU date supports %3N; fall back to whole seconds elsewhere.
    d=$(date +%s%3N 2>/dev/null)
    case "$d" in
        ''|*[!0-9]*) echo "$(( $(date +%s) * 1000 ))" ;;
        *) echo "$d" ;;
    esac
}

# first_seen_ms <id> <now_ms> — echo the stored first-seen stamp for the
# window, or <now_ms> if this is the first sighting. Records the pairing
# into $NEW_STATE so the caller can atomically replace the state file
# with exactly the ids present in this sweep (this is what prunes it).
first_seen_ms() {
    _id=$1
    _now=$2
    # `|| true`: on the first ever sweep $STATE_FILE does not exist and
    # awk exits 2, which `set -e` would otherwise turn into a hard failure.
    if [ -f "$STATE_FILE" ]; then
        _prev=$(awk -F'\t' -v id="$_id" '$2 == id { print $1; exit }' \
            "$STATE_FILE" 2>/dev/null || true)
    else
        _prev=""
    fi
    case "$_prev" in
        ''|*[!0-9]*) _prev=$_now ;;
    esac
    printf '%s\t%s\n' "$_prev" "$_id" >> "$NEW_STATE"
    echo "$_prev"
}

enumerate() {
    # wmctrl -lG: ID  desktop  x  y  w  h  host  title
    # We approximate coverage from geometry vs the root window size.
    root_dims=$(xdotool getdisplaygeometry 2>/dev/null || echo "1920 1080")
    sw=$(echo "$root_dims" | cut -d' ' -f1)
    sh=$(echo "$root_dims" | cut -d' ' -f2)

    NOW_MS=$(now_ms)
    NEW_STATE="${STATE_FILE}.$$"
    : > "$NEW_STATE" 2>/dev/null || NEW_STATE=/dev/null

    printf '['
    first=1
    wmctrl -lG 2>/dev/null | while IFS= read -r line; do
        id=$(echo "$line"   | awk '{print $1}')
        w=$(echo "$line"    | awk '{print $5}')
        h=$(echo "$line"    | awk '{print $6}')
        title=$(echo "$line" | cut -d' ' -f8- | sed 's/^ *//')

        # coverage percent (cap 100)
        if [ "$sw" -gt 0 ] && [ "$sh" -gt 0 ]; then
            cov=$(( (w * h * 100) / (sw * sh) ))
        else
            cov=0
        fi
        [ "$cov" -gt 100 ] && cov=100

        # Fetch _NET_WM_STATE once and derive both signals from it —
        # topmost and blocks_input are two independent atoms in the same
        # EWMH property, so one xprop round-trip covers both.
        wm_state=$(xprop -id "$id" _NET_WM_STATE 2>/dev/null || echo "")

        # topmost: does the window have _NET_WM_STATE_ABOVE?
        topmost=false
        if echo "$wm_state" | grep -q "_NET_WM_STATE_ABOVE"; then
            topmost=true
        fi

        # blocks_input: _NET_WM_STATE_MODAL is the standard EWMH signal
        # for a modal window that captures input ahead of the rest of the
        # desktop — a genuine per-window property, not a heuristic, and
        # the closest real X11 analogue of a scam overlay's forced-focus
        # behavior (audit DR-2).
        blocks_input=false
        if echo "$wm_state" | grep -q "_NET_WM_STATE_MODAL"; then
            blocks_input=true
        fi

        # close button: EWMH _NET_WM_ALLOWED_ACTIONS lists what the WM
        # permits. Absence of _NET_WM_ACTION_CLOSE means the window can't
        # be closed normally - a scam-overlay tell. If the property is
        # missing entirely we default to true (most WMs that don't set
        # it still allow closing) to avoid over-flagging legit windows.
        has_close=true
        actions=$(xprop -id "$id" _NET_WM_ALLOWED_ACTIONS 2>/dev/null || echo "")
        if [ -n "$actions" ] && ! echo "$actions" | grep -q "_NET_WM_ACTION_CLOSE"; then
            has_close=false
        fi

        # Owning process name (best-effort): EWMH _NET_WM_PID → the
        # kernel's /proc/PID/comm. Lets muten's `process:` blocklist
        # rules and the rogue_av_process signal work on X11. Not every
        # client sets _NET_WM_PID, and comm may be unreadable — omit the
        # field then (the daemon treats a missing value as "unknown").
        procname=""
        pid=$(xprop -id "$id" _NET_WM_PID 2>/dev/null | awk -F' = ' '{print $2}' | tr -cd '0-9')
        if [ -n "$pid" ] && [ -r "/proc/$pid/comm" ]; then
            procname=$(cat "/proc/$pid/comm" 2>/dev/null || echo "")
        fi

        et=$(json_escape "$title")

        # Real age when we have seen this window before; 0 ("unknown")
        # on first sighting — see the first_seen_ms comment above.
        seen=$(first_seen_ms "$id" "$NOW_MS")
        age=$(( NOW_MS - seen ))
        [ "$age" -lt 0 ] && age=0   # clock stepped backwards

        if [ "$first" -eq 1 ]; then first=0; else printf ','; fi
        if [ -n "$procname" ]; then
            ep=$(json_escape "$procname")
            printf '{"id":"%s","process":"%s","window":{"title":"%s","url":null,"coverage_percent":%s,"topmost":%s,"has_close_button":%s,"blocks_input":%s,"origin":"unknown","age_ms":%s}}' \
                "$id" "$ep" "$et" "$cov" "$topmost" "$has_close" "$blocks_input" "$age"
        else
            printf '{"id":"%s","window":{"title":"%s","url":null,"coverage_percent":%s,"topmost":%s,"has_close_button":%s,"blocks_input":%s,"origin":"unknown","age_ms":%s}}' \
                "$id" "$et" "$cov" "$topmost" "$has_close" "$blocks_input" "$age"
        fi
    done
    printf ']\n'

    # Atomically replace the state with exactly the ids seen this sweep,
    # so vanished windows are pruned and the file cannot grow unbounded.
    if [ "$NEW_STATE" != /dev/null ]; then
        mv -f "$NEW_STATE" "$STATE_FILE" 2>/dev/null || rm -f "$NEW_STATE" 2>/dev/null
    fi
}

dismiss() {
    id="${1:-}"
    [ -n "$id" ] || { echo "dismiss: missing id" 1>&2; exit 1; }
    # Is the window still present?
    if ! wmctrl -l 2>/dev/null | awk '{print $1}' | grep -qi "^${id}$"; then
        exit 2  # already gone
    fi
    # Close gracefully (sends WM_DELETE_WINDOW). We do NOT kill the
    # process — muten detects & closes the lure window; process/registry
    # cleanup is the EDR's job (CLAUDE.md I9).
    if wmctrl -i -c "$id" 2>/dev/null; then
        exit 0
    fi
    echo "dismiss: wmctrl failed for $id" 1>&2
    exit 1
}

case "$cmd" in
    --probe)   probe ;;
    enumerate) enumerate ;;
    dismiss)   dismiss "${2:-}" ;;
    *) echo "usage: $0 {--probe|enumerate|dismiss <id>}" 1>&2; exit 1 ;;
esac
