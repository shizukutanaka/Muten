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
# ── age_ms: first-seen tracking (DR-20 / WO-11) ──────────────────────
# See muten-overlay-helper-linux.sh for the full rationale. The helper is
# re-spawned each sweep, so a first-seen timestamp per window id is
# persisted across invocations. muten reads `age_ms == 0` as "unknown"
# (never "brand new"), so the first sighting still reports 0 rather than
# fabricating `very_new` (+10) for newly opened benign windows.
STATE_FILE="${MUTEN_OVERLAY_STATE:-${XDG_RUNTIME_DIR:-/tmp}/muten-overlay-seen.$(id -u 2>/dev/null || echo 0)}"

now_ms() {
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

emit_window() {
    eid=$(json_escape "$1")
    et=$(json_escape "$2")
    # Real age from the first-seen state file; 0 on first sighting means
    # "unknown" (see the header comment) — never a fabricated small value.
    _seen=$(first_seen_ms "$1" "$NOW_MS")
    _age=$(( NOW_MS - _seen ))
    [ "$_age" -lt 0 ] && _age=0   # clock stepped backwards
    if [ -n "$3" ]; then
        ep=$(json_escape "$3")
        printf '{"id":"%s","process":"%s","window":{"title":"%s","url":null,"coverage_percent":0,"topmost":false,"has_close_button":true,"blocks_input":false,"origin":"unknown","age_ms":%s}}' \
            "$eid" "$ep" "$et" "$_age"
    else
        printf '{"id":"%s","window":{"title":"%s","url":null,"coverage_percent":0,"topmost":false,"has_close_button":true,"blocks_input":false,"origin":"unknown","age_ms":%s}}' \
            "$eid" "$et" "$_age"
    fi
}

enumerate() {
    tool=$(pick_tool) || { printf '[]\n'; return 0; }

    NOW_MS=$(now_ms)
    NEW_STATE="${STATE_FILE}.$$"
    : > "$NEW_STATE" 2>/dev/null || NEW_STATE=/dev/null

    printf '['
    first=1
    if [ "$tool" = "lswt" ]; then
        # lswt -j emits JSON lines/array; fall back to plain parse.
        # Plain `lswt` prints blocks; the "title:" / "app-id:" lines are
        # what we need. We key the id on app-id + title.
        #
        # The injected `printf '\n\n'` guarantees the LAST block always
        # hits the "" (end-of-block) case below. Without it, output that
        # does not end in a blank line silently drops the final toplevel
        # — and a scam overlay enumerated last would escape detection
        # entirely. Two newlines, not one: the first terminates a final
        # line that lacks its own newline (`read` would otherwise see it
        # only at EOF), the second forms the blank line. Idempotent when
        # the output already ends blank: a "" with empty title/appid
        # emits nothing.
        appid=""
        title=""
        { lswt 2>/dev/null; printf '\n\n'; } | while IFS= read -r line; do
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
        # (final-block flush is handled by the injected trailing `echo`
        # on the pipeline above — no post-loop code can do it, because
        # the `while` runs in a pipeline subshell whose title/appid are
        # invisible here)
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

    # Atomically replace the state with exactly the ids seen this sweep.
    if [ "$NEW_STATE" != /dev/null ]; then
        mv -f "$NEW_STATE" "$STATE_FILE" 2>/dev/null || rm -f "$NEW_STATE" 2>/dev/null
    fi
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
