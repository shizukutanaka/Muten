//! CLI conformance tests for the `--json` contract and exit codes
//! (SPECIFICATION.md §10/§11). These spawn the built binary and feed
//! window JSON on stdin, so they exercise the real argument parsing,
//! serialization, and process exit codes end to end.

use std::io::Write;
use std::process::{Command, Stdio};

/// Run `muten-overlay <args>` with `stdin`, returning (exit code, stdout).
fn run(args: &[&str], stdin: &str) -> (i32, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_muten-overlay"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn muten-overlay");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
    )
}

const SCAM: &str = r#"{"title":"your computer is infected — call 1-800-555-0100",
  "coverage_percent":100,"topmost":true,"has_close_button":false,
  "blocks_input":true,"origin":"unsolicited","age_ms":200}"#;

#[test]
fn classify_json_emits_schema_and_block_exit() {
    let (code, out) = run(&["classify", "-", "--json"], SCAM);
    assert_eq!(code, 6, "scam window should exit 6 (Block)");
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(v["decision"], "block");
    assert!(v["score"].is_number());
    assert!(v["signals"].is_array());
    assert!(
        v["explanation"].is_string(),
        "schema §11 requires explanation"
    );
}

#[test]
fn classify_json_accepts_partial_window() {
    // §2.2: missing fields default — a minimal window must still classify.
    let (code, out) = run(&["classify", "-", "--json"], r#"{"title":"hi"}"#);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["decision"], "allow");
}

#[test]
fn enforce_json_is_array_with_block_exit() {
    let windows = format!(r#"[{{"id":"w1",{}}}]"#, &SCAM[1..SCAM.len() - 1]);
    let (code, out) = run(&["enforce", "-", "--json"], &windows);
    assert_eq!(code, 6);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(v.is_array());
    assert_eq!(v[0]["decision"], "block");
    assert_eq!(v[0]["window_id"], "w1");
}

#[test]
fn monitor_json_emits_events_document() {
    let windows = format!(r#"[{{"id":"w1",{}}}]"#, &SCAM[1..SCAM.len() - 1]);
    let (code, out) = run(&["monitor", "-", "--sweeps", "2", "--json"], &windows);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["sweeps"], 2);
    assert!(v["events"].is_array());
    assert_eq!(v["events"][0]["kind"], "overlay_blocked");
}
