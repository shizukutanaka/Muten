#!/bin/sh
# Signal-inventory invariants: explainability, weighting, and the
# never-granted origin relief.
#
# WHY THIS EXISTS. S1 claims 89 named signals and S8 claims every verdict
# is explainable by construction. Both rest on one thing nobody was
# checking: that the list `all_signals()` publishes and the set the
# engine actually emits are THE SAME SET. Drift either way is a real
# defect and a silent one:
#   * a signal emitted but not declared -> a verdict cites a reason the
#     published inventory does not describe. Explainability broken.
#   * a signal declared but never emitted -> a phantom capability. The
#     docs, the MDM guidance and the operator's mental model all promise
#     detection that cannot occur.
#
# AND THE SAFETY INVARIANT. `Origin::UserInitiated` buys a -40 relief, and
# on X11 the only cheap source for it is `_NET_WM_USER_TIME`, which is
# CLIENT-WRITABLE: a scam window can set it. `Origin::Unsolicited` adds
# +25 and, supplied naively, would push a bare screen-lock shape past the
# block threshold and make muten dismiss a user's real screen locker
# (DR-20). Today no production code constructs either - `origin` is
# always `Unknown`, deliberately. This check PINS that, so a future
# "let's just wire up origin" cannot land without tripping a check that
# points at the designed lock-shape clamp (WO-11).
#
# Exit 0 = the inventory matches and no origin value is constructed.
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)
CRATE="$ROOT/crates/muten-overlay"

command -v python3 >/dev/null 2>&1 || { echo "SKIP  signal check - python3 not available"; exit 0; }

python3 - "$CRATE" <<'PY'
import re, sys, pathlib

crate = pathlib.Path(sys.argv[1])
bad = 0

def production(path):
    """The file with its `#[cfg(test)]` module removed.

    Test code constructs whatever it likes - that is the point of tests.
    Only shipping code is under these invariants.
    """
    s = path.read_text(encoding='utf-8')
    i = s.find('\n#[cfg(test)]')
    return s if i < 0 else s[:i]

lib = production(crate / 'src' / 'lib.rs')

# ── 1. Declared inventory vs emitted set ────────────────────────────
m = re.search(r'pub fn all_signals\(\).*?const NAMES: &\[&str\] = &\[(.*?)\n    \];',
              lib, re.S)
if not m:
    print('FAIL  could not find all_signals()\'s NAMES table in src/lib.rs')
    sys.exit(1)
declared = set(re.findall(r'"([a-z_0-9]+)"', m.group(1)))

# Both forms the engine uses to record a signal: the additive path pushes
# onto `signals`, and the hard host block builds the vector directly.
emitted = set(re.findall(r'signals\.push\("([a-z_0-9]+)"', lib))
emitted |= set(re.findall(r'signals: Vec<String> = vec!\["([a-z_0-9]+)"', lib))

for name in sorted(emitted - declared):
    print(f'FAIL  signal "{name}" is emitted but NOT declared in all_signals() '
          f'- a verdict can cite a reason the inventory does not explain')
    bad += 1
for name in sorted(declared - emitted):
    print(f'FAIL  signal "{name}" is declared in all_signals() but NO code path '
          f'emits it - a phantom capability')
    bad += 1

# ── 2. Every declared signal is weighted ────────────────────────────
# `blocklist_host` is the one documented exception: the host block is a
# HARD block that returns BLOCK_THRESHOLD directly and never goes through
# the additive score, so it has no per-signal weight by design.
HARD_BLOCK = {'blocklist_host'}
weighted = set(re.findall(r'"([a-z_0-9]+)" => Some\(W_', lib))
for name in sorted(declared - weighted - HARD_BLOCK):
    print(f'FAIL  signal "{name}" has no weight in signal_weight() - it would '
          f'contribute nothing to the score and could never dismiss anything')
    bad += 1
for name in sorted(weighted - declared):
    print(f'FAIL  signal "{name}" is weighted but not declared')
    bad += 1

# ── 3. No production code constructs an Origin other than Unknown ───
# Construction/assignment forms only; comparisons (`== Origin::X`) and
# match arms are how the engine READS the field and are fine.
CONSTRUCT = re.compile(r'origin\s*[:=]\s*(?!=)\s*(?:Some\()?\s*(?:crate::)?Origin::(UserInitiated|Unsolicited)')
for path in sorted((crate / 'src').rglob('*.rs')):
    src = production(path)
    for mm in CONSTRUCT.finditer(src):
        line = src[:mm.start()].count('\n') + 1
        rel = path.relative_to(crate)
        print(f'FAIL  {rel}:{line} constructs Origin::{mm.group(1)} in production code.')
        print( '      That is not a lint - it changes the score. UserInitiated grants a')
        print( '      -40 relief whose only cheap X11 source (_NET_WM_USER_TIME) is')
        print( '      CLIENT-WRITABLE, and Unsolicited adds +25, which takes a bare')
        print( '      screen-lock shape past the block threshold and dismisses a real')
        print( '      screen locker. Land the lock-shape clamp (WO-11) first.')
        bad += 1

if bad:
    sys.exit(1)
print(f'signal inventory: {len(declared)} declared = {len(emitted)} emitted, '
      f'{len(weighted)} weighted (+1 hard block); origin relief never granted')
PY
