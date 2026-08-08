#!/bin/sh
# muten overlay helper - macOS reference implementation.
#
# Protocol (see docs/OVERLAY_BLOCKING.md):
#   helper --probe        exit 0 if usable
#   helper enumerate      print JSON array of {id, window} to stdout
#   helper dismiss <id>   exit 0 acted / 2 already-gone / other failure
#
# Uses osascript + System Events (AppleScript), available on every Mac
# with no install. Requires the muten daemon to hold Accessibility
# permission (granted once via MDM profile / TCC). All the privileged
# interop is in the OS + this script; muten stays forbid(unsafe_code).
#
# Window "id" here is "<appName>::<windowName>" since AppleScript
# addresses windows by name within an app. Closing is graceful (the
# window's close button); we never kill the app (CLAUDE.md I9).
#
# Fields macOS can't cheaply determine default conservatively so the
# classifier biases toward Suspicious over Block. `has_close_button` and
# `blocks_input` are exceptions (audit DR-2): `has_close_button` is
# derived from whether the window's `button 1` UI element exists — the
# same accessor `dismiss()` below already relies on to close a window,
# so "no button 1" and "dismiss can't gracefully close this window" are
# kept consistent by construction. `blocks_input` is derived from the
# window's accessibility `subrole` — "AXDialog"/"AXSystemDialog" is the
# standard macOS signal for a modal dialog window (the same Accessibility
# API concept AppleScript UI-scripting tools use to detect modals),
# analogous to X11's `_NET_WM_STATE_MODAL` (see `muten-overlay-helper-
# linux.sh`).

set -eu
cmd="${1:-}"

probe() {
    command -v osascript >/dev/null 2>&1 || exit 1
    [ "$(uname -s)" = "Darwin" ] || exit 1
    exit 0
}

# See muten-overlay-helper-linux.sh's json_escape for the rationale: after
# escaping backslash/quote and folding tab/CR/LF to spaces, delete any
# other ASCII control char (0x00-0x1F) so a title carrying one can't emit
# invalid JSON that the daemon's serde_json rejects for the whole sweep.
json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
        | tr '\t\r\n' '   ' | tr -d '[:cntrl:]'
}

# ── age_ms: first-seen tracking (DR-20 / WO-11) ──────────────────────
# See muten-overlay-helper-linux.sh for the full rationale. Summary: the
# helper is re-spawned each sweep, so a first-seen timestamp per window id
# is persisted across invocations. muten reads `age_ms == 0` as "unknown"
# (never as "brand new"), so the sweep that first observes a window still
# reports 0 — inventing a sub-second value there would fabricate
# `very_new` (+10) for every newly opened benign window.
STATE_FILE="${MUTEN_OVERLAY_STATE:-${TMPDIR:-/tmp}/muten-overlay-seen.$(id -u 2>/dev/null || echo 0)}"

now_ms() {
    # macOS /bin/date has no %N — it echoes the format back verbatim, so
    # the non-numeric guard below catches it and falls back to seconds.
    d=$(date +%s%3N 2>/dev/null)
    case "$d" in
        ''|*[!0-9]*) echo "$(( $(date +%s) * 1000 ))" ;;
        *) echo "$d" ;;
    esac
}

first_seen_ms() {
    _id=$1
    _now=$2
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
    NOW_MS=$(now_ms)
    NEW_STATE="${STATE_FILE}.$$"
    : > "$NEW_STATE" 2>/dev/null || NEW_STATE=/dev/null

    # Screen size for coverage estimate.
    dims=$(osascript -e 'tell application "Finder" to get bounds of window of desktop' 2>/dev/null || echo "0, 0, 1920, 1080")
    sw=$(echo "$dims" | awk -F', ' '{print $3}')
    sh=$(echo "$dims" | awk -F', ' '{print $4}')
    [ -z "$sw" ] && sw=1920
    [ -z "$sh" ] && sh=1080

    # List visible windows: appName, windowName, width, height.
    raw=$(osascript <<'APPLESCRIPT' 2>/dev/null || true
tell application "System Events"
    set out to ""
    repeat with proc in (every process whose visible is true)
        set pn to name of proc
        try
            repeat with w in (every window of proc)
                set wn to name of w
                set sz to size of w
                set ww to item 1 of sz
                set wh to item 2 of sz
                set hasClose to "true"
                try
                    if not (exists (button 1 of w)) then set hasClose to "false"
                end try
                set isModal to "false"
                try
                    set sub to subrole of w
                    if sub is "AXDialog" or sub is "AXSystemDialog" then set isModal to "true"
                end try
                set out to out & pn & tab & wn & tab & ww & tab & wh & tab & hasClose & tab & isModal & linefeed
            end repeat
        end try
    end repeat
    return out
end tell
APPLESCRIPT
)

    printf '['
    first=1
    printf '%s\n' "$raw" | while IFS=$(printf '\t') read -r app wname ww wh hasclose ismodal; do
        [ -z "$app" ] && continue
        [ -z "$ww" ] && ww=0
        [ -z "$wh" ] && wh=0
        if [ "$sw" -gt 0 ] && [ "$sh" -gt 0 ] && [ "$ww" -gt 0 ]; then
            cov=$(( (ww * wh * 100) / (sw * sh) ))
        else
            cov=0
        fi
        [ "$cov" -gt 100 ] && cov=100

        # Default to true (matches the X11/Windows helpers' convention)
        # when the AppleScript side didn't emit a recognizable value —
        # only a confirmed "false" should suppress the close button.
        has_close=true
        [ "$hasclose" = "false" ] && has_close=false

        # Default to false (unmodified classifier behavior) unless the
        # subrole check positively confirmed a modal dialog.
        blocks_input=false
        [ "$ismodal" = "true" ] && blocks_input=true

        id="$app::$wname"
        seen=$(first_seen_ms "$id" "$NOW_MS")
        age=$(( NOW_MS - seen ))
        [ "$age" -lt 0 ] && age=0   # clock stepped backwards
        eid=$(json_escape "$id")
        et=$(json_escape "$wname")
        # Owning process name = the System Events process name we already
        # iterate — reported so muten's `process:` blocklist rules and the
        # rogue_av_process signal work on macOS (best-effort field; the
        # daemon treats a missing value as "unknown").
        ep=$(json_escape "$app")
        if [ "$first" -eq 1 ]; then first=0; else printf ','; fi
        printf '{"id":"%s","process":"%s","window":{"title":"%s","url":null,"coverage_percent":%s,"topmost":false,"has_close_button":%s,"blocks_input":%s,"origin":"unknown","age_ms":%s}}' \
            "$eid" "$ep" "$et" "$cov" "$has_close" "$blocks_input" "$age"
    done
    printf ']\n'

    # Atomically replace the state with exactly the ids seen this sweep.
    if [ "$NEW_STATE" != /dev/null ]; then
        mv -f "$NEW_STATE" "$STATE_FILE" 2>/dev/null || rm -f "$NEW_STATE" 2>/dev/null
    fi
}

dismiss() {
    id="${1:-}"
    [ -n "$id" ] || { echo "dismiss: missing id" 1>&2; exit 1; }
    app=$(printf '%s' "$id" | sed 's/::.*//')
    wname=$(printf '%s' "$id" | sed 's/^[^:]*:://')

    # Does the window still exist?
    exists=$(osascript -e "tell application \"System Events\" to tell process \"$app\" to exists (window \"$wname\")" 2>/dev/null || echo "false")
    if [ "$exists" != "true" ]; then
        exit 2  # already gone
    fi
    # Graceful close via the window's close button.
    if osascript -e "tell application \"System Events\" to tell process \"$app\" to click button 1 of window \"$wname\"" >/dev/null 2>&1; then
        exit 0
    fi
    echo "dismiss: could not close $id" 1>&2
    exit 1
}

case "$cmd" in
    --probe)   probe ;;
    enumerate) enumerate ;;
    dismiss)   dismiss "${2:-}" ;;
    *) echo "usage: $0 {--probe|enumerate|dismiss <id>}" 1>&2; exit 1 ;;
esac
