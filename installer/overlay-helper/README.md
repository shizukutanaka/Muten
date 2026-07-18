# Deploying `muten-overlay daemon` to a managed fleet

`muten-overlay daemon` is the real, continuous protection loop — it shells
out to one of the platform helpers below via `SubprocessController`,
enumerates and dismisses actual windows forever, and writes a persistent
tamper-evident audit log. (`enforce`/`monitor` only replay a static window
list against a dry-run `NullController`, for demonstration and testing —
see the crate's top-level `--help`.)

Because muten never adds a network call to the detection path (I5 privacy —
classification stays on-device) and never bundles a self-updater or
installer of its own (I3 scope discipline), getting the binary + helper +
blocklist onto endpoints and running persistently is the deploying
organization's MDM's job. This directory ships the raw material for that:

| File | Platform | Wraps `daemon` via |
|---|---|---|
| `muten-overlay-helper-linux.sh` | Linux / X11 | `wmctrl` + `xprop` |
| `muten-overlay-helper-wayland.sh` | Linux / Wayland | `ext-foreign-toplevel-list` + portal |
| `muten-overlay-helper-macos.sh` | macOS | `osascript` + System Events (Accessibility API) |
| `muten-overlay-helper-windows.ps1` | Windows | Win32 P/Invoke |
| `muten-overlay.service` | Linux | systemd unit |
| `com.muten.overlay.plist` | macOS | launchd agent |
| `muten-overlay-task.xml` | Windows | Scheduled Task |

Each service-manager template documents its own install command and its
own graceful-stop procedure in its header comment — read the one for your
platform before deploying. All three use the same signal-free shutdown
pattern: touch a "stop-flag" file, wait one sweep interval, and the daemon
exits 0 on its own (`--stop-flag`; see `muten-overlay daemon --help`). No
signal handler is needed, which keeps the crate `#![forbid(unsafe_code)]`.

## Single-instance lock

`daemon` refuses to start a second time against the same `--audit-log`
path — it creates `<audit-log>.lock` on startup and removes it on a
graceful stop. This matters because the audit log is a hash chain: two
instances writing to it concurrently would each start from the same head
and race to append, corrupting the chain and defeating its whole tamper-
evidence purpose. If a prior run was killed uncleanly (SIGKILL, power
loss, a crash) the lock file is left behind — the daemon's error message
in that case tells you to confirm no other instance is actually running
(check your OS's process list) before deleting the stale `.lock` file and
retrying. Do not script an automatic "always delete the lock and restart"
recovery step; that reintroduces the exact corruption risk the lock exists
to prevent if the previous instance is, in fact, still alive.

## Push patterns per MDM

None of these require anything muten doesn't already ship — they are
standard packaging steps for whatever you use today.

- **Microsoft Intune (Windows)**: package the binary, helper script,
  `muten-overlay-task.xml`, and blocklist into a `.intunewin` Win32 app.
  The install command imports the scheduled task
  (`schtasks /create /tn muten-overlay /xml muten-overlay-task.xml`); the
  uninstall command touches the stop-flag file, waits, then
  `schtasks /delete /tn muten-overlay /f`.
- **Jamf Pro (macOS)**: a "Files and Processes" policy payload that copies
  the binary/helper/plist/blocklist into place, then runs
  `launchctl bootstrap gui/<uid> /Library/LaunchAgents/com.muten.overlay.plist`.
  Accessibility permission for the helper script must be pre-approved via a
  **PPPC (Privacy Preferences Policy Control) configuration profile** —
  see `com.muten.overlay.plist`'s header for the exact target path; this
  step cannot be scripted (TCC prompts are always interactive), so it must
  be a profile, not a script action.
- **Group Policy (Windows, on-prem AD)**: a GPO "Scheduled Tasks"
  preference item can import `muten-overlay-task.xml` directly (Computer
  or User Configuration → Preferences → Control Panel Settings → Scheduled
  Tasks), or a startup/logon script can call the same `schtasks /create`
  command Intune uses.
- **Ansible (any platform)**: `ansible.builtin.copy` the binary/helper/
  blocklist, then `ansible.builtin.systemd` (Linux — enable + start
  `muten-overlay.service`), `community.general.launchd` (macOS), or
  `community.windows.win_scheduled_task` (Windows) to register the
  service-manager unit. Rolling a new blocklist is just an
  `ansible.builtin.copy` over the existing `--rules` file — the running
  daemon picks up the change on its own within one sweep interval (see
  "Updating the blocklist in the field" below); no restart task needed.

## Updating the blocklist in the field

The blocklist is a plain text file (`docs/OVERLAY_BLOCKING.md` documents
the full `host:`/`title:`/`glob:`/`process:`/`phone:`/`composite:`/
`weight:` grammar — see `examples/overlay-blocklist.txt` for a fully
worked, threat-intel-sourced example). Pushing a new version is just:
copy the new file over the one at the path passed to `--rules`. The
running `daemon` checks that file's mtime once per sweep and reloads it
automatically when it changes (no restart, no code change) — see
`Monitor::set_rules` and the mtime check in `cmd_daemon`
(`crates/muten-overlay/src/bin/cli.rs`). A restart is only needed to
change the `--rules` *path* itself (or any other CLI flag), not to pick
up an edited file at the same path.

One deployment caveat: reload is triggered by the file's modified-time
advancing, so a copy/rsync tool that preserves the *source* file's
original mtime (e.g. `rsync -t` reproducing an older timestamp, or
restoring from a backup) can leave the daemon still on the previous
ruleset even though the file's bytes changed. Make sure whatever pushes
the file lets the destination's mtime update normally (a plain
`ansible.builtin.copy` or `cp` does this by default).

## Pre-flight: does the helper work on this host?

Before trusting the daemon with a helper on a given endpoint, run the
bundled self-test to confirm the helper satisfies the protocol on *that*
machine's window manager / compositor:

```sh
./selftest.sh ./muten-overlay-helper-linux.sh
```

It exercises all three protocol verbs (`--probe`, `enumerate`,
`dismiss`) and checks that `enumerate` emits a JSON array of
`{id, window[, process]}` objects, that a quiet desktop's `[]` is
accepted, and that `dismiss` of a non-existent id does not falsely report
success. Exit 0 = safe to deploy here; exit 1 = fix before deploying
(e.g. the compositor doesn't offer the foreign-toplevel protocol the
Wayland helper needs, or `wmctrl`/`xprop` aren't installed for X11). It
is pure POSIX `sh` (uses `python3` for a deeper structural check only if
present) so it runs inside the same MDM push step that stages the helper.
This is a fast pre-flight, not a substitute for a real dry-run — for that,
pipe a captured `enumerate` snapshot through `muten-overlay enforce`.

## Verifying a deployment

`muten-overlay verify <audit-log-path>` replays the tamper-evident hash
chain and reports the event count and Merkle root — run this against a
pulled-back copy of an endpoint's audit log to confirm no gap or tamper
occurred while it was unattended. `muten-overlay signals` lists every
built-in detection signal with its weight/category/MITRE mapping, useful
for building a SIEM lookup table before rolling out broadly.
