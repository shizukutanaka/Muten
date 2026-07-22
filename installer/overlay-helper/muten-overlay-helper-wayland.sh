#!/bin/sh
# muten overlay helper - Wayland (wlroots) reference implementation.
#
# Protocol (see docs/OVERLAY_BLOCKING.md):
#   helper --probe        exit 0 if usable on this host
#   helper enumerate      print JSON array of {id, window} to stdout
#   helper dismiss <id>   exit 0 acted / 2 already-gone / other failure
#
# ── IMPORTANT scope / honesty note ─────────────────────────────────
# Wayland deliberately restricts window enumeration (unlike X11). A
# client can only list other toplevels via a compositor protocol:
#   - wlr-foreign-toplevel-management-unstable-v1  (wlroots: Sway,
#     Hyprland, river, Wayfire, labwc, ...)
#   - ext-foreign-toplevel-list-v1                 (newer, broader)
# GNOME (Mutter) and KDE (KWin) do NOT implement wlr-foreign-toplevel
# as of 2026 (KDE bug 502647 still open), so this helper PROBES FALSE
# there and muten safely falls back to observe/NullController rather
# than pretending to see windows it cannot.
#
# Even where enumeration works, Wayland does not expose window
# geometry / stacking to foreign clients. So we report what we can
# (title, app-id) and leave coverage=0, topmost=false, age_ms=0,
# origin=unknown. That means on Wayland the TITLE BLOCKLIST is the
# detection path (the behavioural heuristic has little to work with) —
# which is exactly muten's reliable real-host path anyway.
#
# Tools (first available wins): lswt (machine-parsable), then wlrctl.
# All the protocol work lives in those tools; muten stays
# forbid(unsafe_code).

set -eu
cmd="${1:-}"

have() { command -v "$1" >/dev/null 2>&1; }

# Pick an enumeration tool that actually works on this compositor.
pick_tool() {
    [ -n "${WAYLAND_DISPLAY:-}" ] || return 1
    if have lswt; then
        # lswt exits non-zero if foreign-toplevel isn't offered.
        if lswt -j >/dev/null 2>&1 || lswt >/dev/null 2>&1; then
            echo "lswt"
            return 0
        fi
    fi
    if have wlrctl; then
        if wlrctl toplevel list >/dev/null 2>&1; then
            echo "wlrctl"
            return 0
        fi
    fi
    return 1
}

probe() {
    tool=$(pick_tool) || exit 1
    [ -n "$tool" ] || exit 1
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

# Emit one EnumeratedWindow object. $1=id $2=title $3=app-id (may be empty).
#
# The Wayland app-id (e.g. "org.mozilla.firefox") stands in for the owning
# process name — foreign clients cannot see PIDs on Wayland, and muten's
# `process:` rule matching is separator-insensitive substring, so an app-id
# still matches a rule written as plain "firefox". Omitted when unknown
# (the daemon treats a missing "process" as "unknown").
emit_window() {
    eid=$(json_escape "$1")
    et=$(json_escape "$2")
    if [ -n "$3" ]; then
        ep=$(json_escape "$3")
        printf '{"id":"%s","process":"%s","window":{"title":"%s","url":null,"coverage_percent":0,"topmost":false,"has_close_button":true,"blocks_input":false,"origin":"unknown","age_ms":0}}' \
            "$eid" "$ep" "$et"
    else
        printf '{"id":"%s","window":{"title":"%s","url":null,"coverage_percent":0,"topmost":false,"has_close_button":true,"blocks_input":false,"origin":"unknown","age_ms":0}}' \
            "$eid" "$et"
    fi
}

enumerate() {
    tool=$(pick_tool) || { printf '[]\n'; return 0; }

    printf '['
    first=1
    if [ "$tool" = "lswt" ]; then
        # lswt -j emits JSON lines/array; fall back to plain parse.
        # Plain `lswt` prints blocks; the "title:" / "app-id:" lines are
        # what we need. We key the id on app-id + title.
        appid=""
        title=""
        lswt 2>/dev/null | while IFS= read -r line; do
            case "$line" in
                "title: "*)  title=${line#title: } ;;
                "app-id: "*) appid=${line#app-id: } ;;
                "") # blank line = end of a toplevel block
                    if [ -n "$title" ] || [ -n "$appid" ]; then
                        if [ "$first" -eq 1 ]; then first=0; else printf ','; fi
                        emit_window "${appid}::${title}" "$title" "$appid"
                        title=""; appid=""
                    fi
                    ;;
            esac
        done
        # flush last block if no trailing blank line
    else
        # wlrctl toplevel list → lines like "app_id: Title"
        wlrctl toplevel list 2>/dev/null | while IFS= read -r line; do
            appid=${line%%:*}
            title=${line#*: }
            [ -z "$line" ] && continue
            if [ "$first" -eq 1 ]; then first=0; else printf ','; fi
            emit_window "${appid}::${title}" "$title" "$appid"
        done
    fi
    printf ']\n'
}

dismiss() {
    id="${1:-}"
    [ -n "$id" ] || { echo "dismiss: missing id" 1>&2; exit 1; }
    title=${id#*::}
    # Only wlrctl can request a close on wlr-foreign-toplevel.
    if have wlrctl; then
        # Match by title; close gracefully (compositor sends close).
        if wlrctl toplevel close title:"$title" >/dev/null 2>&1; then
            exit 0
        fi
        # Not found → already gone.
        exit 2
    fi
    # No close-capable tool: report as "couldn't act" so muten audits
    # the detection but doesn't claim a dismissal it didn't perform.
    echo "dismiss: no close-capable Wayland tool (need wlrctl)" 1>&2
    exit 1
}

case "$cmd" in
    --probe)   probe ;;
    enumerate) enumerate ;;
    dismiss)   dismiss "${2:-}" ;;
    *) echo "usage: $0 {--probe|enumerate|dismiss <id>}" 1>&2; exit 1 ;;
esac
