# Offline stubs — for running dep-light tests without a crate registry

**These are not product code and are never compiled into the crate.**

Some environments (including the sandbox this project is often developed
in) can reach `index.crates.io` but are denied `static.crates.io` by
egress policy, so `cargo test` cannot download dependencies and the whole
suite goes unrun — which is how DR-12 and the DR-2b/2c/2d helper tests sat
unverified for an entire cycle.

Most of the crate genuinely needs its real dependencies. But two test
suites touch a tiny external surface:

| suite | external API used |
|---|---|
| `tests/linux_helper_reference.rs` | `tempfile::tempdir`, `serde_json::from_str` + `Value` |
| `tests/macos_helper_reference.rs` | same |

Those suites shell out to the real shipped helper scripts and assert on
the JSON they print, so what they actually verify is **helper behaviour**,
not serde integration. This directory provides a minimal `tempfile`
shim and a small but **correct** JSON parser (it rejects raw control
characters per RFC 8259, which is the DR-17 property) so the unmodified
test files can be compiled and run with `rustc` alone.

## Usage

`scripts/verify.sh` does this automatically. Manually:

```sh
cd crates/muten-overlay
rustc --edition 2021 --crate-type lib --crate-name tempfile \
      -o /tmp/libtempfile.rlib   ../../scripts/offline-stubs/tempfile.rs
rustc --edition 2021 --crate-type lib --crate-name serde_json \
      -o /tmp/libserde_json.rlib ../../scripts/offline-stubs/serde_json.rs
CARGO_MANIFEST_DIR="$PWD" rustc --edition 2021 --test -O \
      --extern tempfile=/tmp/libtempfile.rlib \
      --extern serde_json=/tmp/libserde_json.rlib \
      -o /tmp/t tests/linux_helper_reference.rs && /tmp/t
```

## What this does and does not prove

**Does**: the test files compile, their logic is sound, and the shipped
helper scripts produce the asserted JSON — teeth-checked (disabling the
helper's modal detection makes the test FAIL).

**Does not**: verify integration with the *real* `serde_json`/`tempfile`.
A real `cargo test` remains the authority. Never advertise "all tests
green" on the strength of these stubs alone.


## `muten_overlay_compileonly.rs` — compile checking only

`tests/benign_corpus.rs` and `tests/scoring_scenarios.rs` need the crate
itself, which needs `serde`/`sha2` and therefore the blocked registry.
This stub provides just the surface they name (`OverlayWindow`, `Origin`,
`Ruleset`, `Decision`, `Verdict`, `classify`, the two thresholds) so
`rustc` can **type-check** them.

**Its `classify` returns an empty verdict, so the resulting pass/fail is
meaningless.** Use it to answer *"does this file still compile?"* and
nothing else. Under it the benign tests pass trivially and the
scam-detection tests fail as artefacts — neither outcome is evidence.

Behaviour is established separately, by probing the **real** detectors in
`confusables.rs` (`scripts/fp-probe/`). Keeping the two apart is
deliberate: a stub can only ever prove compilation, so it must never be
the thing that tells you detection works.

### Why there is no stub for the whole crate

Compiling all of `lib.rs` would need stand-ins for serde's derive macros
too. That was considered and **rejected**: a blanket
`impl<T> Serialize for T {}` accepts code that real serde would reject,
so a green from it would be weaker than it looks while reading as
stronger. A real `cargo build` is the only honest answer to *"does the
whole crate compile?"*.
