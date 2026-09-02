# Offline stubs — for running dep-light tests without a crate registry

**These are not product code and are never compiled into the crate.**

Some environments (including the sandbox this project is often developed
in) can reach `index.crates.io` but are denied `static.crates.io` by
egress policy, so `cargo test` cannot download dependencies and the whole
suite goes unrun — which is how DR-12 and the DR-2b/2c/2d helper tests sat
unverified for an entire cycle.

Most of the crate genuinely needs its real dependencies. But several
test surfaces touch only a small external API:

| suite | external API used |
|---|---|
| `tests/linux_helper_reference.rs` | `tempfile::tempdir`, `serde_json::from_str` + `Value` |
| `tests/macos_helper_reference.rs` | same |
| `src/merkle.rs` (16 tests) | `sha2::{Digest, Sha256}`, `hex::{encode, decode}` |
| `src/sink.rs` (32 tests) | the above plus `serde_json`, `thiserror::Error`, `serde::{Serialize, Deserialize}`, `tempfile` |
| the whole crate + 5 integration suites (1,620 tests) | all of the above |

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

## `sha2.rs` is a **real** SHA-256, not a stub

The audit chain's tests include known answers (`merkle_root(&[])` must
equal `SHA-256("")`). A dummy hash would make them vacuous, so this is a
genuine FIPS 180-4 implementation, and `scripts/check-merkle.sh` proves
that claim against **four published NIST vectors** *before* running
anything on top of it. A wrong hash fails the self-test first; merkle
results are never reported on an unverified primitive.

## What this does and does not prove

**Does**: the test files compile, their logic is sound, and the shipped
helper scripts produce the asserted JSON — teeth-checked (disabling the
helper's modal detection makes the test FAIL).

**Does not**: verify integration with the *real* `serde_json`/`tempfile`.
A real `cargo test` remains the authority. Never advertise "all tests
green" on the strength of these stubs alone.


## The whole crate now runs here — and what that does NOT mean

`scripts/check-crate.sh` compiles the real `src/lib.rs` against these
stubs and runs **1,335 unit tests plus 285 integration tests**, including
the two suites that carry the product's central behavioural claims:
`tests/benign_corpus.rs` (zero false positives) and
`tests/scoring_scenarios.rs` (a detected window's score actually crosses
`BLOCK_THRESHOLD`). Both were previously compile-checked against a stub
whose `classify()` returned an empty verdict — a pass that carried no
information. That stub is deleted; a check that cannot fail informatively
is worse than none.

**Proves**: the behaviour of `classify()` and everything under it, on the
real, unmodified `src/` and `tests/`. Teeth-proven in both directions —
zeroing `W_TITLE_HIT` (detection intact, dismissal broken) turns
`helper_contract` red, and removing the `alert_shaped` fence from the
ClickFix signal turns a unit test red.

**Does NOT prove**: serde integration, and this is **not** an answer to
"does the crate compile under real serde" — only `cargo build` is.

**Deliberately not run, and deliberately not faked**: the three proptest
suites and `tests/cli_contract.rs`. A property test's substance is its
input *distribution*; a home-made generator would test something else
while reading the same, and its regex strategies would have to be
reimplemented. `cli_contract` needs clap and the built binary.

## `thiserror.rs` / `serde.rs` — narrow derive shims, and their limits

`src/sink.rs` cannot compile without `#[derive(thiserror::Error)]` on
`ChainError` and `#[derive(serde::Serialize, Deserialize)]` on
`CheckpointSig`, so its tamper tests could not run at all. These two
proc-macro shims supply exactly those derives and **nothing wider**:

* `thiserror` accepts the `#[error(..)]` helper attributes and emits
  `Display` via `Debug`. **Error message wording is therefore NOT under
  test.** That is tolerable only because no `sink.rs` test asserts on
  wording — they match on the variant. If one ever does, this shim must
  grow or that test must be excluded and the exclusion stated.
* `serde` handles **plain structs with named fields only**. Enums,
  generics, `#[serde(...)]` options and borrowed deserialization all
  panic at compile time rather than silently doing something else.

### Why a *permissive* stub is still refused

An earlier version of this file rejected any whole-crate stub. That
objection was aimed at a **permissive** one: a blanket
`impl<T> Serialize for T {}` accepts code real serde rejects, so a green
from it reads stronger than it is. That reasoning still stands, and these
shims are the opposite bargain — they reproduce a named set of shapes and
**panic at compile time** on everything else, so an unsupported
declaration stops the build instead of quietly passing. What changed is
only the scope of what has been taught, not the standard. A real
`cargo build` remains the only honest answer to *"does the whole crate
compile?"*, and nothing here claims otherwise.
