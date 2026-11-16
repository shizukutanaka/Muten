#!/bin/sh
# ============================================================
#  muten-audio launcher for Linux (resident watchdog)
#  Keep this terminal open while enforcement is active.
#  Closing it (or Ctrl+C) stops the agent - that is
#  intentional and visible, never silent.
#
#  Requirements: the muten-audio binary next to this script,
#  a policy.json (create it with ./muten-audio init), and a
#  desktop audio stack the agent can drive: wpctl
#  (PipeWire/WirePlumber) or pactl (PulseAudio). If neither is
#  usable the agent prints the reason and stops.
# ============================================================
set -u
cd "$(dirname "$0")" || exit 1

pause_and_exit() {
    echo
    printf 'Press Enter to close this window...'
    read -r _ || true
    exit "$1"
}

if [ ! -x ./muten-audio ]; then
    echo "[muten] ERROR: muten-audio binary not found in this folder (or not executable)."
    echo "[muten] Build it once from ../crates/muten-audio:"
    echo "[muten]   cargo build --release   (then copy target/release/muten-audio here)"
    pause_and_exit 1
fi
if [ ! -f policy.json ]; then
    echo "[muten] ERROR: policy.json not found."
    echo "[muten] Run ./muten-audio init first - it creates policy.json"
    echo "[muten] and asks you to set the admin PIN."
    pause_and_exit 1
fi

echo "[muten] Starting the forced-mute agent (Linux backend)..."
echo "[muten] Policy: policy.json   Log: audit.log"
echo "[muten] Close this terminal or press Ctrl+C to stop."
echo

./muten-audio watch --policy policy.json --grant grant.json --log audit.log --backend linux
code=$?

echo
echo "[muten] Agent stopped with exit code $code."
echo "[muten] If that was not intentional, read the messages above"
echo "[muten] and check audit.log in this folder."
pause_and_exit "$code"
