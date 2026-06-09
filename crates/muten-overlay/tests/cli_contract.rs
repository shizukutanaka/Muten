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

// ── --stream (NDJSON) contract ─────────────────────────────────────

// NDJSON requires one JSON object per *line*; SCAM spans multiple lines,
// so use a compact single-line variant for streaming tests.
const SCAM_LINE: &str = r#"{"title":"your computer is infected call 1-800-555-0100","coverage_percent":100,"topmost":true,"has_close_button":false,"blocks_input":true,"origin":"unsolicited","age_ms":200}"#;
const BENIGN: &str = r#"{"title":"My App","coverage_percent":10,"topmost":false,"has_close_button":true,"blocks_input":false,"origin":"user_initiated"}"#;

#[test]
fn stream_single_block_exits_6_and_emits_ndjson() {
    let (code, out) = run(&["classify", "-", "--stream"], SCAM_LINE);
    assert_eq!(code, 6, "--stream of one Block window must exit 6");
    // Output must be exactly one line of valid JSON.
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 1, "one input line → one output line");
    let v: serde_json::Value = serde_json::from_str(lines[0]).expect("NDJSON line is valid JSON");
    assert_eq!(v["decision"], "block");
    assert!(v["signals"].is_array());
    assert!(
        v["explanation"].is_string(),
        "stream output includes explanation"
    );
}

#[test]
fn stream_worst_exit_code_aggregated() {
    // Block + Allow → exit 6 (worst).
    let ndjson = format!("{SCAM_LINE}\n{BENIGN}\n");
    let (code, out) = run(&["classify", "-", "--stream"], &ndjson);
    assert_eq!(code, 6, "worst of Block+Allow is Block (exit 6)");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "two inputs → two outputs");
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(first["decision"], "block");
    assert_eq!(second["decision"], "allow");
}

#[test]
fn stream_all_allow_exits_0() {
    let ndjson = format!("{BENIGN}\n{BENIGN}\n");
    let (code, _out) = run(&["classify", "-", "--stream"], &ndjson);
    assert_eq!(code, 0, "all-Allow stream must exit 0");
}

#[test]
fn stream_empty_lines_skipped() {
    // A blank line between two valid windows must be silently skipped.
    let ndjson = format!("{BENIGN}\n\n{BENIGN}\n");
    let (code, out) = run(&["classify", "-", "--stream"], &ndjson);
    assert_eq!(code, 0);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "empty line skipped — 2 inputs → 2 outputs");
}

#[test]
fn stream_invalid_json_line_exits_1() {
    let (code, _out) = run(&["classify", "-", "--stream"], "not-json\n");
    assert_eq!(code, 1, "malformed NDJSON line must exit 1");
}

#[test]
fn stream_empty_input_exits_0() {
    // An entirely empty NDJSON stream (no windows) is not an error.
    let (code, out) = run(&["classify", "-", "--stream"], "");
    assert_eq!(code, 0, "empty stream exits 0 (no worst code)");
    assert_eq!(out.trim(), "", "no output for empty input");
}
