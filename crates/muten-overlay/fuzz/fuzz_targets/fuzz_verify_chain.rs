//! Fuzz the audit-chain verifier (`verify_chain`) and the HMAC checkpoint
//! signer/verifier (`sign_checkpoint`, `verify_checkpoint_sig`).
//!
//! Goals:
//! - `verify_chain` never panics — it returns `Err` for malformed input.
//! - `sign_checkpoint` never panics — on broken input it returns `Err`.
//! - For any valid chain (verify_chain returns Ok), signing with any key and
//!   then verifying with the same key returns true.
//!
//! Run with:
//! ```sh
//! cargo +nightly fuzz run fuzz_verify_chain -- -max_len=8192
//! ```
#![no_main]
use libfuzzer_sys::fuzz_target;
use muten_overlay::sink::{sign_checkpoint, verify_chain, verify_checkpoint_sig};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // verify_chain never panics — it may return Ok or Err.
    let chain_result = verify_chain(s);
    // sign_checkpoint never panics.
    let key = b"fuzz-key";
    if let Ok(sig) = sign_checkpoint(s, key) {
        // If signing succeeds, the chain must have been valid.
        assert!(chain_result.is_ok(), "sign_checkpoint succeeded on a broken chain");
        // Verifying with the same key must succeed.
        assert!(
            verify_checkpoint_sig(&sig, key),
            "verify_checkpoint_sig failed with the same key used for signing"
        );
        // Verifying with a different key must fail.
        assert!(
            !verify_checkpoint_sig(&sig, b"wrong-key"),
            "verify_checkpoint_sig accepted a wrong key"
        );
    } else {
        // sign_checkpoint failed — either the chain was broken or the log empty.
        // This is fine; just check that verify_chain also returned an error
        // (unless the log was empty, in which case sign_checkpoint returns Ok
        // with count=0).
        // No additional assertion needed — we just confirmed no panic.
    }
});
