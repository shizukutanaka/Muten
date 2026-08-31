#!/bin/sh
# Validate the MDM deployment templates against the artifacts they depend on.
#
# WHY THIS EXISTS. The three templates in installer/overlay-helper/
# (launchd plist, Task Scheduler XML, systemd unit) are deploy-critical:
# if one breaks, the daemon never starts at all, however healthy the
# detector is. They also depend on OTHER artifacts — they name helper
# script files and pass CLI flags — so a rename on either side breaks
# deployment silently, and neither the crate's tests nor the shell tests
# would notice. This closes that cross-artifact gap.
#
# Checks, per template:
#   1. well-formedness  — plist / task XML parse as XML; the .service
#                         parses as INI with [Unit]/[Service]/[Install]
#   2. helper references — every muten-overlay-helper-*.{sh,ps1} named in
#                          an executable directive exists in the repo
#   3. CLI flags         — every --flag passed maps to a snake_case field
#                          in src/bin/cli.rs (clap derives --interval-ms
#                          from `interval_ms`, so the reverse mapping is
#                          mechanical)
#
# Flags are read ONLY from executable directives (ProgramArguments,
# <Arguments>, Exec* lines) — never from comments. muten-overlay.service's
# comments legitimately mention `systemctl enable --now` and
# `systemctl --user`, which are not muten flags; scanning whole files
# would cry wolf, and a check that cries wolf gets ignored.
#
# Exit 0 = all templates valid. Exit 1 = something would break deployment.

set -eu
cd "$(dirname "$0")/.."

command -v python3 >/dev/null 2>&1 || {
    echo "SKIP  MDM template check — python3 not available"; exit 0; }

exec python3 - "$(pwd)" <<'PYEOF'
import re, sys, pathlib, configparser
import xml.dom.minidom as minidom

root = pathlib.Path(sys.argv[1])
helpers = root / 'installer' / 'overlay-helper'
cli = (root / 'crates' / 'muten-overlay' / 'src' / 'bin' / 'cli.rs').read_text(encoding='utf-8')
errs = []

def check_refs_and_flags(label, text):
    for helper in sorted(set(re.findall(r'muten-overlay-helper-[a-z]+\.(?:sh|ps1)', text))):
        if not (helpers / helper).exists():
            errs.append(f"{label}: references {helper}, which does not exist")
    for flag in sorted(set(re.findall(r'--([a-z][a-z-]+)', text))):
        field = flag.replace('-', '_')
        if not re.search(rf'^\s*{field}:', cli, re.M):
            errs.append(f"{label}: passes --{flag}, but cli.rs has no `{field}` field")

# launchd plist: args live in ProgramArguments <string> elements.
plist = helpers / 'com.muten.overlay.plist'
try:
    d = minidom.parse(str(plist))
    args = " ".join(s.firstChild.data for s in d.getElementsByTagName('string') if s.firstChild)
    check_refs_and_flags(plist.name, args)
except Exception as e:
    errs.append(f"{plist.name}: not well-formed XML ({e})")

# Task Scheduler XML: args live in <Arguments> (and <Command>).
task = helpers / 'muten-overlay-task.xml'
try:
    d = minidom.parse(str(task))
    args = " ".join(a.firstChild.data
                    for tag in ('Arguments', 'Command')
                    for a in d.getElementsByTagName(tag) if a.firstChild)
    check_refs_and_flags(task.name, args)
except Exception as e:
    errs.append(f"{task.name}: not well-formed XML ({e})")

# systemd unit: INI with required sections; only Exec* directives carry args.
svc = helpers / 'muten-overlay.service'
try:
    c = configparser.ConfigParser(strict=False, delimiters=('=',))
    c.optionxform = str
    c.read(svc)
    for sec in ('Unit', 'Service', 'Install'):
        if not c.has_section(sec):
            errs.append(f"{svc.name}: missing [{sec}] section")
    if c.has_section('Service'):
        execs = " ".join(v for k, v in c.items('Service') if k.startswith('Exec'))
        check_refs_and_flags(svc.name, execs)
except Exception as e:
    errs.append(f"{svc.name}: not parseable as INI ({e})")

if errs:
    print("\n".join(errs))
    sys.exit(1)
print("3 templates valid: XML/INI well-formed, helper refs exist, CLI flags match cli.rs")
PYEOF
