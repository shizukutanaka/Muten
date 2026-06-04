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
# NOTE: enumeration here is best-effort. X11 does not expose
# "unsolicited vs user-initiated" or "has close button" directly, so
# those fields are conservatively defaulted; muten's classifier treats
# unknown origin as neutral, which biases toward Suspicious (review)
# rather than Block (dismiss) — the safe direction.

set -eu

cmd="${1:-}"

probe() {
    command -v wmctrl >/dev/null 2>&1 || exit 1
    command -v xprop  >/dev/null 2>&1 || exit 1
    [ -n "${DISPLAY:-}" ] || exit 1
    exit 0
}

# Escape a string for embedding in JSON (backslash, quote, control).
json_escape() {
    # shellcheck disable=SC1003
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/ /g' | tr -d '\n\r'
}

enumerate() {
    # wmctrl -lG: ID  desktop  x  y  w  h  host  title
    # We approximate coverage from geometry vs the root window size.
    root_dims=$(xdotool getdisplaygeometry 2>/dev/null || echo "1920 1080")
    sw=$(echo "$root_dims" | cut -d' ' -f1)
    sh=$(echo "$root_dims" | cut -d' ' -f2)

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

        # topmost: does the window have _NET_WM_STATE_ABOVE?
        topmost=false
        if xprop -id "$id" _NET_WM_STATE 2>/dev/null | grep -q "_NET_WM_STATE_ABOVE"; then
            topmost=true
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

        et=$(json_escape "$title")

        if [ "$first" -eq 1 ]; then first=0; else printf ','; fi
        printf '{"id":"%s","window":{"title":"%s","url":null,"coverage_percent":%s,"topmost":%s,"has_close_button":%s,"blocks_input":false,"origin":"unknown","age_ms":0}}' \
            "$id" "$et" "$cov" "$topmost" "$has_close"
    done
    printf ']\n'
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
