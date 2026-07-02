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
# classifier biases toward Suspicious over Block.

set -eu
cmd="${1:-}"

probe() {
    command -v osascript >/dev/null 2>&1 || exit 1
    [ "$(uname -s)" = "Darwin" ] || exit 1
    exit 0
}

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\t\r\n' '   '
}

enumerate() {
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
                set out to out & pn & tab & wn & tab & ww & tab & wh & linefeed
            end repeat
        end try
    end repeat
    return out
end tell
APPLESCRIPT
)

    printf '['
    first=1
    printf '%s\n' "$raw" | while IFS=$(printf '\t') read -r app wname ww wh; do
        [ -z "$app" ] && continue
        [ -z "$ww" ] && ww=0
        [ -z "$wh" ] && wh=0
        if [ "$sw" -gt 0 ] && [ "$sh" -gt 0 ] && [ "$ww" -gt 0 ]; then
            cov=$(( (ww * wh * 100) / (sw * sh) ))
        else
            cov=0
        fi
        [ "$cov" -gt 100 ] && cov=100

        id="$app::$wname"
        eid=$(json_escape "$id")
        et=$(json_escape "$wname")
        # Owning process name = the System Events process name we already
        # iterate — reported so muten's `process:` blocklist rules and the
        # rogue_av_process signal work on macOS (best-effort field; the
        # daemon treats a missing value as "unknown").
        ep=$(json_escape "$app")
        if [ "$first" -eq 1 ]; then first=0; else printf ','; fi
        printf '{"id":"%s","process":"%s","window":{"title":"%s","url":null,"coverage_percent":%s,"topmost":false,"has_close_button":true,"blocks_input":false,"origin":"unknown","age_ms":0}}' \
            "$eid" "$ep" "$et" "$cov"
    done
    printf ']\n'
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
