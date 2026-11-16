# muten-audio agent folder (Windows)

Everything the resident forced-mute agent needs, in one portable
folder. No installer, no registry writes: copy the folder anywhere
(e.g. `C:\muten`) and use the `.bat` launchers.

| File | Role |
|---|---|
| `muten-audio.exe` | The agent + admin CLI (build once with `Build.bat`, or get it from CI — see below) |
| `audio-helper.ps1` | The only part that touches Windows audio (Core Audio COM). Called by the exe; never run it by hand |
| `policy-fetch.ps1` | Downloads the central policy when the policy source is a URL. Called by the exe; never run it by hand |
| `Start-Muten.bat` | Start the resident watchdog. Keep the window open; closing it stops enforcement, visibly |
| `Set-Pin.bat` | First run: create `policy.json` + set the admin PIN. Later: change the PIN |
| `Unmute.bat` | Grant a temporary unmute (admin PIN required) |
| `policy-editor.html` | Offline policy editor (schedule, unmute options). Open in any browser |
| `policy.example.json` | A commented-by-example starting policy (weekdays 08:00–19:00 JST) |
| `Build.bat` | Build `muten-audio.exe` from `../crates/muten-audio` (needs Rust) |

Files created at runtime, in the same folder: `policy.json` (your
policy + PIN hash), `grant.json` (the current temporary-unmute grant,
if any), `audit.log` (the tamper-evident event log).

## First-time setup

1. Get `muten-audio.exe` into this folder (Build.bat, or the CI
   artifact — `docs/ci/build-windows.yml` in the repository builds one
   on `windows-latest`).
2. Run **Set-Pin.bat** — creates `policy.json` and asks for the admin
   PIN (typed PINs are echoed; use a private console).
3. Optionally adjust the schedule in `policy-editor.html`.
4. Run **Start-Muten.bat**. The PC is muted within a second, and any
   volume raise is re-muted on the next poll (default 1 s).

To start the agent automatically at sign-in, put a shortcut to
`Start-Muten.bat` in the user's Startup folder
(`shell:startup`). Forgetting this is the most common deployment
mistake — the agent only enforces while it is running.

## Day-to-day

- **Temporary sound** (e.g. a training video): run **Unmute.bat**,
  enter the PIN, choose minutes. Sound returns on the next poll and is
  muted again automatically when the grant expires. Every grant and
  every denied attempt is written to `audit.log`.
- **Check status**: `muten-audio.exe status` in this folder shows the
  policy, any active grant, and whether the audit chain is intact.
- **Verify the log**: `muten-audio.exe verify-log`.

## Central policy distribution (optional)

Placing `policy.json` by hand does not scale past a few machines.
Instead, host one master `policy.json` in a place every machine can
read — a shared folder (e.g. `\\fileserver\muten\policy.json`) or an
HTTPS URL — and let each machine pull it:

- **Resident pull**: add the source to the `Start-Muten.bat` command
  line:
  `muten-audio.exe watch --policy policy.json --grant grant.json --log audit.log --helper audio-helper.ps1 --policy-source \\fileserver\muten\policy.json`
  The agent checks the source every 300 seconds
  (`--policy-source-interval` to change it; minimum 10) and once at
  the first poll. URL sources are downloaded by `policy-fetch.ps1`,
  which must sit next to the exe.
- **One-shot pull** (e.g. from a scheduled task):
  `muten-audio.exe fetch-policy --policy policy.json --source \\fileserver\muten\policy.json --log audit.log`

The rules are deliberately strict:

- A pulled policy is applied **only** if it parses and validates
  exactly like a hand-placed one (unknown fields are rejected). The
  local `policy.json` is then replaced atomically, and the agent
  continues with the new policy.
- If the source is unreachable or the content is invalid, **nothing
  changes**: the current policy stays in force, and the failure is
  written to `audit.log` (`policy_fetch_failed` / `policy_error`). A
  distribution outage never lifts enforcement.
- Every applied policy is recorded in `audit.log` as
  `policy_updated`, with the source and the **SHA-256 of the applied
  bytes** — so you can verify after the fact which policy each
  machine actually took.
- **The distributed file replaces the whole local policy, including
  the PIN hash.** On centrally managed machines the PIN is owned
  centrally too: set it in the master copy (run `set-pin` against
  it), because a local `Set-Pin.bat` change will be overwritten at
  the next pull.

## Honest limits — read before deploying

- **User-mode software.** The agent runs as the signed-in user. Anyone
  with local administrator rights can close it, delete it, edit
  `policy.json`, replace the PIN hash, or delete `audit.log`. The PIN
  and the watchdog deter *casual* unmuting by the everyday user; they
  do not withstand a determined local admin. For hard enforcement, run
  the agent as a Windows **service** under a separate admin account,
  protect this folder with ACLs, and/or manage the machines with
  **Group Policy / MDM**. muten does not pretend otherwise.
- **Default playback device only.** Muting applies to the default
  render endpoint. A second, non-default output device is not
  controlled in this version.
- **The audit log is tamper-evident, not tamper-proof.** Editing or
  deleting entries in the middle breaks the hash chain and
  `verify-log` will say so — but only if someone checks, ideally
  against a copy or head hash kept on another machine.
- **Schedule clock.** Windows' clock is the source of truth; the
  policy's `utc_offset_minutes` must be kept correct across DST
  changes by the administrator.
- **Central distribution has no signature.** If you use the policy
  source above, there is no cryptographic proof that a pulled policy
  came from you — muten deliberately does not invent one. Whoever can
  write to the share, or change what the URL serves, controls the
  policy (including the PIN hash and the master switch) of every
  machine that pulls from it. Protect that location like an
  administrator credential: tight share ACLs, HTTPS on the server,
  and check the `policy_updated` hashes in `audit.log` against the
  master copy. A tampered policy cannot do more than a policy can
  express (it cannot run code), but a policy with `enforce: false`
  silently stops muting on every machine — the audit log is how you
  would find out.
