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

/// Regression guard: `ChainedFileSink` creates its file lazily on the
/// first `emit()`. An all-benign window list fires zero Block/Suspicious/
/// scareware events, so the file may never be created at all — a common,
/// healthy scenario that must exit 0 with zero counts, not crash trying to
/// read a file that was never written.
#[test]
fn monitor_with_audit_log_and_metrics_on_all_benign_windows_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    let audit_log = dir.path().join("audit.log");
    let metrics = dir.path().join("metrics.prom");
    let windows = r#"[{"id":"a","title":"My App","coverage_percent":10,"has_close_button":true}]"#;

    let mut child = Command::new(env!("CARGO_BIN_EXE_muten-overlay"))
        .args([
            "monitor",
            "-",
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--metrics",
            metrics.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(windows.as_bytes())
        .unwrap();
    let status = child.wait().unwrap();

    assert_eq!(
        status.code(),
        Some(0),
        "an all-benign monitor run must not fail just because no audit \
         events (and therefore no audit-log file) were ever produced"
    );
    let metrics_text = std::fs::read_to_string(&metrics).expect("metrics written");
    assert!(metrics_text.contains("muten_blocks_total 0"));
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

// ── triage subcommand (9th lens, operational) ───────────────────────────────

/// A catastrophic-loss scam (pig-butchering crypto-drain) and a smaller
/// gift-card tech-support scam, given in *reverse* priority order on input.
const TRIAGE_BATCH: &str = r#"[
  {"id":"low-benign","title":"my vacation photos","coverage_percent":40,"has_close_button":true},
  {"id":"hi-giftcard","title":"your computer is locked buy gift card and send codes to microsoft support 1-800-555-0100","coverage_percent":100,"topmost":true,"has_close_button":false,"blocks_input":true,"origin":"unsolicited"},
  {"id":"top-pig","title":"vip trading group guaranteed profit connect your wallet seed phrase required to claim bonus","coverage_percent":100,"topmost":true,"has_close_button":false,"blocks_input":true,"origin":"unsolicited"}
]"#;

#[test]
fn triage_json_sorts_by_descending_priority() {
    let (code, out) = run(&["triage", "-", "--json"], TRIAGE_BATCH);
    assert_eq!(code, 6, "at least one Block window → exit 6");
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON array");
    assert!(v.is_array());
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 3, "all three windows present");

    // Catastrophic pig-butchering must sort first, gift-card second, benign last.
    assert_eq!(arr[0]["id"], "top-pig");
    assert_eq!(arr[1]["id"], "hi-giftcard");
    assert_eq!(arr[2]["id"], "low-benign");

    // Scores must be monotonically non-increasing (the sort invariant).
    let s0 = arr[0]["priority_score"].as_u64().unwrap();
    let s1 = arr[1]["priority_score"].as_u64().unwrap();
    let s2 = arr[2]["priority_score"].as_u64().unwrap();
    assert!(s0 >= s1 && s1 >= s2, "priority_score must be sorted desc");

    // Schema spot-check on the top record.
    assert_eq!(arr[0]["priority"], "critical");
    assert_eq!(arr[0]["p_label"], "P1");
    assert!(arr[0]["campaign_bucket"].is_string());
    assert!(arr[0]["signal_fingerprint"].is_string());
}

#[test]
fn triage_all_benign_exits_0() {
    let windows = r#"[{"id":"a","title":"hello","has_close_button":true},
                      {"id":"b","title":"world","has_close_button":true}]"#;
    let (code, out) = run(&["triage", "-", "--json"], windows);
    assert_eq!(code, 0, "no Block window → exit 0");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 2);
}

#[test]
fn triage_text_output_is_priority_first() {
    let (code, out) = run(&["triage", "-"], TRIAGE_BATCH);
    assert_eq!(code, 6);
    // The first printed row is the highest-priority window (top-pig, P1).
    let first = out.lines().next().expect("at least one row");
    assert!(first.starts_with("P1"), "top row must be P1: {first:?}");
    assert!(
        first.contains("top-pig"),
        "top row must be top-pig: {first:?}"
    );
}

// ── daemon subcommand (real continuous protection loop) ─────────────────────
//
// Unlike `enforce`/`monitor` (dry-run, replay a static window list against
// NullController), `daemon` shells out to a real platform helper via
// SubprocessController and loops forever until a stop-flag file appears.
// These tests spawn the real binary against a fake shell-script helper
// (mirroring controller.rs's own `fake_helper` unit-test technique) so the
// whole probe→loop→dismiss→audit→graceful-stop path is exercised end to end,
// not just the library call underneath it.

#[cfg(unix)]
fn write_fake_daemon_helper(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("helper.sh");
    let json = r#"[{"id":"w1","window":{"title":"your computer is infected call microsoft support 1-800-555-0100","coverage_percent":100,"topmost":true,"has_close_button":false,"blocks_input":true,"origin":"unsolicited","age_ms":200}}]"#;
    let script = format!(
        "#!/bin/sh\ncase \"$1\" in\n\
         --probe) exit 0 ;;\n\
         enumerate) echo '{json}' ;;\n\
         dismiss) exit 0 ;;\n\
         *) exit 1 ;;\n\
         esac\n"
    );
    std::fs::write(&path, script).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

#[cfg(unix)]
#[test]
fn daemon_fails_fast_on_unavailable_helper() {
    let dir = tempfile::tempdir().unwrap();
    let audit_log = dir.path().join("audit.log");
    let child = Command::new(env!("CARGO_BIN_EXE_muten-overlay"))
        .args([
            "daemon",
            "/nonexistent/muten-helper-xyz",
            "--audit-log",
            audit_log.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(
        child.code(),
        Some(1),
        "an unavailable helper must fail fast, not loop"
    );
    assert!(
        !audit_log.exists(),
        "no audit log should be created before the probe check passes"
    );
}

#[cfg(unix)]
#[test]
fn daemon_runs_sweeps_and_stops_gracefully_on_stop_flag() {
    let dir = tempfile::tempdir().unwrap();
    let helper = write_fake_daemon_helper(dir.path());
    let audit_log = dir.path().join("audit.log");
    let stop_flag = dir.path().join("stop");
    let metrics = dir.path().join("metrics.prom");

    let mut child = Command::new(env!("CARGO_BIN_EXE_muten-overlay"))
        .args([
            "daemon",
            helper.to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--interval-ms",
            "50",
            "--stop-flag",
            stop_flag.to_str().unwrap(),
            "--metrics",
            metrics.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");

    // Let it complete a handful of sweeps against the fake helper, then
    // signal a graceful stop the same way a service manager's `ExecStop`
    // would (touch the flag file — no signal handler, per the crate's
    // forbid(unsafe_code) constraint).
    std::thread::sleep(std::time::Duration::from_millis(300));
    std::fs::write(&stop_flag, "").unwrap();

    let status = child.wait().expect("daemon exits");
    assert_eq!(status.code(), Some(0), "graceful stop must exit 0");

    // The audit log is a real, verifiable hash chain — not a stub.
    let log_text = std::fs::read_to_string(&audit_log).expect("audit log written");
    assert!(!log_text.trim().is_empty(), "at least one sweep occurred");
    for line in log_text.lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("valid JSONL event");
        assert!(v["kind"].is_string());
        assert!(v["hash"].is_string());
    }

    // Prometheus metrics reflect real, non-zero activity.
    let metrics_text = std::fs::read_to_string(&metrics).expect("metrics written");
    assert!(metrics_text.contains("muten_sweeps_total"));
    assert!(!metrics_text.contains("muten_sweeps_total 0"));
    assert!(
        metrics_text.contains("muten_dismissals_total")
            && !metrics_text.contains("muten_dismissals_total 0"),
        "the scam window returned by the fake helper should have been dismissed: {metrics_text}"
    );
}

/// Regression guard: `ChainedFileSink` creates its file lazily on the
/// first `emit()`. A helper that only ever enumerates an empty desktop
/// fires zero audit events, so the audit-log file may genuinely never be
/// created — a common, healthy scenario (the machine has no scam overlays
/// on it) that must exit 0, not crash trying to read a file that was
/// never written.
#[cfg(unix)]
fn write_quiet_daemon_helper(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("quiet-helper.sh");
    let script = "#!/bin/sh\ncase \"$1\" in\n\
                  --probe) exit 0 ;;\n\
                  enumerate) echo '[]' ;;\n\
                  dismiss) exit 2 ;;\n\
                  *) exit 1 ;;\n\
                  esac\n";
    std::fs::write(&path, script).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

#[cfg(unix)]
#[test]
fn daemon_exits_cleanly_when_no_events_are_ever_emitted() {
    let dir = tempfile::tempdir().unwrap();
    let helper = write_quiet_daemon_helper(dir.path());
    let audit_log = dir.path().join("audit.log");
    let stop_flag = dir.path().join("stop");
    let metrics = dir.path().join("metrics.prom");

    let mut child = Command::new(env!("CARGO_BIN_EXE_muten-overlay"))
        .args([
            "daemon",
            helper.to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--interval-ms",
            "50",
            "--stop-flag",
            stop_flag.to_str().unwrap(),
            "--metrics",
            metrics.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");

    std::thread::sleep(std::time::Duration::from_millis(300));
    std::fs::write(&stop_flag, "").unwrap();
    let status = child.wait().expect("daemon exits");

    assert_eq!(
        status.code(),
        Some(0),
        "a daemon that never sees a scam window must still exit 0 on \
         graceful stop, even though the audit-log file was never created"
    );
    let metrics_text = std::fs::read_to_string(&metrics).expect("metrics written");
    assert!(metrics_text.contains("muten_blocks_total 0"));
}

/// Regression guard for the `--helper-timeout-ms` CLI flag itself.
///
/// `subprocess_available_returns_false_on_hung_helper_within_timeout` in
/// controller.rs already proves the *library* timeout mechanism works, but
/// nothing previously proved the CLI actually threads `--helper-timeout-ms`
/// through to `SubprocessController::with_timeout` — a refactor could
/// silently drop that wiring (e.g. reverting to `SubprocessController::new`,
/// which uses the library's own default) and no test would catch it. This
/// spawns a helper that hangs for a full hour and asserts the *whole
/// process* (not just the library call) exits promptly once the configured
/// timeout elapses, not after some much longer fallback or never.
#[cfg(unix)]
fn write_hanging_daemon_helper(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("hang-helper.sh");
    std::fs::write(&path, "#!/bin/sh\nsleep 3600\n").unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

#[cfg(unix)]
#[test]
fn daemon_cli_helper_timeout_ms_flag_bounds_a_hung_probe() {
    let dir = tempfile::tempdir().unwrap();
    let helper = write_hanging_daemon_helper(dir.path());
    let audit_log = dir.path().join("audit.log");

    let start = std::time::Instant::now();
    let status = Command::new(env!("CARGO_BIN_EXE_muten-overlay"))
        .args([
            "daemon",
            helper.to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--helper-timeout-ms",
            "300",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    let elapsed = start.elapsed();

    assert_eq!(
        status.code(),
        Some(1),
        "the startup probe against a hung helper must fail (exit 1), not hang"
    );
    assert!(
        // Deliberately tight: the library's own default timeout (used if
        // --helper-timeout-ms were silently dropped and the CLI fell back
        // to SubprocessController::new) is 5000ms. A threshold near 5s
        // would not distinguish "the flag worked" from "the flag was
        // silently ignored" — 2s comfortably separates the two while
        // leaving generous margin above the requested 300ms.
        elapsed < std::time::Duration::from_secs(2),
        "with --helper-timeout-ms 300, the probe must fail in ~300ms, not \
         the library's 5000ms default, took {elapsed:?} — this likely means \
         the CLI flag stopped reaching SubprocessController::with_timeout"
    );
}

/// Regression guard for the single-instance lock: `ChainedFileSink::open`
/// has no cross-process coordination, so two daemon instances pointed at
/// the same `--audit-log` would each start from the same chain head and
/// race to append, corrupting the tamper-evident hash chain. The daemon
/// must refuse to start a second instance against the same audit log, and
/// must release the lock on a graceful stop so a subsequent (non-
/// concurrent) restart isn't blocked by its own prior run.
#[cfg(unix)]
#[test]
fn daemon_refuses_second_instance_on_same_audit_log_and_releases_lock_on_stop() {
    let dir = tempfile::tempdir().unwrap();
    let helper = write_quiet_daemon_helper(dir.path());
    let audit_log = dir.path().join("audit.log");
    let stop_flag = dir.path().join("stop");

    let mut first = Command::new(env!("CARGO_BIN_EXE_muten-overlay"))
        .args([
            "daemon",
            helper.to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--interval-ms",
            "50",
            "--stop-flag",
            stop_flag.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn first daemon");

    // Give the first instance time to acquire the lock before racing a
    // second one against it.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let lock_path = dir.path().join("audit.log.lock");
    assert!(
        lock_path.exists(),
        "the first instance must hold a visible lock file while running"
    );

    let second_status = Command::new(env!("CARGO_BIN_EXE_muten-overlay"))
        .args([
            "daemon",
            helper.to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--interval-ms",
            "50",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run second daemon");
    assert_eq!(
        second_status.code(),
        Some(1),
        "a second instance against the same audit log must refuse to start, \
         not race the first instance's writes"
    );

    // Stop the first instance gracefully and confirm the lock is released
    // (not left stale after a clean shutdown).
    std::fs::write(&stop_flag, "").unwrap();
    let first_status = first.wait().expect("first daemon exits");
    assert_eq!(first_status.code(), Some(0));
    assert!(
        !lock_path.exists(),
        "a graceful stop must release the lock file so a later restart isn't blocked"
    );
}

/// Regression guard: `--metrics` must reflect live activity *while the
/// daemon is still running*, not only once at graceful shutdown. A daemon
/// is meant to run for weeks; if the metrics file only existed/updated at
/// shutdown, node_exporter's textfile collector would see nothing the
/// entire time the daemon is healthy — exactly when an operator most
/// wants a live view. This polls the metrics file *before* signaling
/// stop and asserts it already shows non-zero activity.
#[cfg(unix)]
#[test]
fn daemon_metrics_update_live_before_graceful_stop() {
    let dir = tempfile::tempdir().unwrap();
    let helper = write_fake_daemon_helper(dir.path());
    let audit_log = dir.path().join("audit.log");
    let stop_flag = dir.path().join("stop");
    let metrics = dir.path().join("metrics.prom");

    let mut child = Command::new(env!("CARGO_BIN_EXE_muten-overlay"))
        .args([
            "daemon",
            helper.to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--interval-ms",
            "30",
            "--stop-flag",
            stop_flag.to_str().unwrap(),
            "--metrics",
            metrics.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");

    // Poll (rather than a single fixed sleep) so this isn't flaky on a
    // loaded CI runner — but bounded, so a real regression (metrics only
    // written at shutdown) fails the test instead of hanging.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut saw_live_activity = false;
    while std::time::Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(&metrics) {
            if text.contains("muten_blocks_total")
                && !text.contains("muten_blocks_total 0")
                && !stop_flag.exists()
            {
                saw_live_activity = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    // Clean up regardless of outcome so the spawned process never leaks.
    std::fs::write(&stop_flag, "").unwrap();
    let _ = child.wait();

    assert!(
        saw_live_activity,
        "metrics must show non-zero muten_blocks_total WHILE the daemon is \
         still running (stop-flag not yet created) — if this only becomes \
         true after the stop-flag exists, metrics regressed to \
         write-once-at-shutdown"
    );
}

/// Regression guard: metrics are observability, not the mission. A failed
/// metrics write (here: the metrics path points into a directory that
/// doesn't exist, exactly what happens on a fleet host without
/// node_exporter installed) must never kill the protection loop — the
/// daemon keeps sweeping and still exits 0 on a graceful stop.
#[cfg(unix)]
#[test]
fn daemon_survives_unwritable_metrics_path() {
    let dir = tempfile::tempdir().unwrap();
    let helper = write_fake_daemon_helper(dir.path());
    let audit_log = dir.path().join("audit.log");
    let stop_flag = dir.path().join("stop");
    // Deliberately inside a directory that does not exist.
    let metrics = dir.path().join("no-such-dir").join("metrics.prom");

    let mut child = Command::new(env!("CARGO_BIN_EXE_muten-overlay"))
        .args([
            "daemon",
            helper.to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--interval-ms",
            "30",
            "--stop-flag",
            stop_flag.to_str().unwrap(),
            "--metrics",
            metrics.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");

    // Let it run several sweeps — with the old `?` propagation it would
    // have died with exit 1 on the very first sweep's metrics write.
    std::thread::sleep(std::time::Duration::from_millis(300));
    std::fs::write(&stop_flag, "").unwrap();
    let status = child.wait().expect("daemon exits");

    assert_eq!(
        status.code(),
        Some(0),
        "an unwritable metrics path must not kill the protection loop"
    );
    // And it genuinely kept protecting: the scam window was dismissed and
    // audited across multiple sweeps despite every metrics write failing.
    let log_text = std::fs::read_to_string(&audit_log).expect("audit log written");
    assert!(
        log_text.lines().count() >= 2,
        "expected multiple sweeps' worth of audit events, got:\n{log_text}"
    );
}

/// End-to-end proof that DR-1 is closed: a helper that reports the owning
/// process name in its enumerate payload drives the rogue-AV path in real
/// daemon mode — `scareware_detected` lands in the audit log and
/// `muten_scareware_total` in the metrics — with a benign window title, so
/// only the `process:` blocklist rule (not any title heuristic) can be
/// responsible for the detection.
#[cfg(unix)]
#[test]
fn daemon_process_reporting_drives_rogue_av_detection_end_to_end() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();

    // Helper: benign-looking window, but owned by a blocklisted rogue-AV
    // process. Old-format helpers omit "process"; this one reports it.
    let helper = dir.path().join("helper.sh");
    let json = r#"[{"id":"w1","process":"SystemGuard 2026","window":{"title":"scan complete","coverage_percent":40,"topmost":false,"has_close_button":true,"blocks_input":false,"origin":"unknown","age_ms":0}}]"#;
    std::fs::write(
        &helper,
        format!(
            "#!/bin/sh\ncase \"$1\" in\n--probe) exit 0 ;;\nenumerate) echo '{json}' ;;\ndismiss) exit 0 ;;\n*) exit 1 ;;\nesac\n"
        ),
    )
    .unwrap();
    let mut perms = std::fs::metadata(&helper).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&helper, perms).unwrap();

    let rules = dir.path().join("rules.txt");
    std::fs::write(&rules, "process: systemguard2026\n").unwrap();

    let audit_log = dir.path().join("audit.log");
    let stop_flag = dir.path().join("stop");
    let metrics = dir.path().join("metrics.prom");

    let mut child = Command::new(env!("CARGO_BIN_EXE_muten-overlay"))
        .args([
            "daemon",
            helper.to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--interval-ms",
            "50",
            "--stop-flag",
            stop_flag.to_str().unwrap(),
            "--metrics",
            metrics.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");

    std::thread::sleep(std::time::Duration::from_millis(300));
    std::fs::write(&stop_flag, "").unwrap();
    let status = child.wait().expect("daemon exits");
    assert_eq!(status.code(), Some(0));

    let log_text = std::fs::read_to_string(&audit_log).expect("audit log written");
    let scareware_line = log_text
        .lines()
        .find(|l| l.contains("scareware_detected"))
        .unwrap_or_else(|| {
            panic!("no scareware_detected event — process reporting is not reaching assess():\n{log_text}")
        });
    let ev: serde_json::Value = serde_json::from_str(scareware_line).unwrap();
    assert_eq!(ev["detail"]["matched_process"], "systemguard2026");
    assert!(ev["detail"]["signals"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == "rogue_av_process"));

    let metrics_text = std::fs::read_to_string(&metrics).expect("metrics written");
    assert!(
        metrics_text.contains("muten_scareware_total")
            && !metrics_text.contains("muten_scareware_total 0"),
        "muten_scareware_total must be non-zero: {metrics_text}"
    );
}

/// End-to-end regression guard for DR-11: a helper that reports the SAME
/// static, benign window every sweep (never disappearing) must never
/// trigger `scareware_detected`. Before the fix, `Monitor::sweep` recorded
/// a repeat-tracker "appearance" for every enumerated window every sweep
/// regardless of whether it was new or just still on screen, so any
/// long-lived window crossed REPEAT_THRESHOLD=3 after 3 sweeps and fired
/// scareware_detected forever — a real, reproduced false positive
/// (docs/FEATURE_AUDIT_2026H2.md DR-11) that would have flagged nearly
/// every normal window left open on a real host, since every OS helper
/// reports `origin:"unknown"` (never `user_initiated`), so the pre-
/// existing UserInitiated carve-out never applied on a real machine.
#[cfg(unix)]
#[test]
fn daemon_long_lived_benign_window_never_triggers_repeated_flood() {
    let dir = tempfile::tempdir().unwrap();
    let helper = dir.path().join("steady-helper.sh");
    let json = r#"[{"id":"w1","window":{"title":"my ordinary steady app","coverage_percent":15,"topmost":false,"has_close_button":true,"blocks_input":false,"origin":"unknown","age_ms":0}}]"#;
    std::fs::write(
        &helper,
        format!(
            "#!/bin/sh\ncase \"$1\" in\n--probe) exit 0 ;;\nenumerate) echo '{json}' ;;\ndismiss) exit 2 ;;\n*) exit 1 ;;\nesac\n"
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&helper).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&helper, perms).unwrap();
    }

    let audit_log = dir.path().join("audit.log");
    let stop_flag = dir.path().join("stop");

    let mut child = Command::new(env!("CARGO_BIN_EXE_muten-overlay"))
        .args([
            "daemon",
            helper.to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--interval-ms",
            "40",
            "--stop-flag",
            stop_flag.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");

    // Comfortably more than REPEAT_THRESHOLD (3) sweeps' worth of time —
    // the bug fired continuously from the 3rd sweep onward, so this
    // window is generous enough to catch a regression reliably.
    std::thread::sleep(std::time::Duration::from_millis(500));
    std::fs::write(&stop_flag, "").unwrap();
    let status = child.wait().expect("daemon exits");
    assert_eq!(status.code(), Some(0));

    // ChainedFileSink creates its file lazily on first emit(); zero
    // scareware/block/suspicious events across many sweeps of a benign
    // window means the file legitimately never gets created at all —
    // itself a strong pass signal, and consistent with the DR-4 fix.
    if audit_log.exists() {
        let log_text = std::fs::read_to_string(&audit_log).unwrap();
        assert!(
            !log_text.contains("scareware_detected"),
            "a long-lived benign window must never trigger scareware_detected: {log_text}"
        );
    }
}

/// End-to-end regression guard for the DR-2 `age_ms` inference fix: a
/// window present since the daemon's very first sweep reports `age_ms: 0`
/// ("unknown") forever, since every real OS helper never reports a
/// nonzero age. `Monitor::sweep` infers an age from how long it has
/// tracked the window itself when the helper doesn't know — but a window
/// that was already open before the daemon started must never have that
/// inferred age trusted, or it would look freshly-popped (`very_new`,
/// which the scorer only awards for a real nonzero age under 1s) for a
/// few sweeps right after every daemon restart. This window's score
/// (`unsolicited` 25 + `topmost` 15 = 40) sits just below
/// `SUSPICIOUS_THRESHOLD` (50) without `very_new`, and would cross it
/// (50) with `very_new`'s +10 if the age were (wrongly) trusted — so any
/// `overlay_suspicious` event here proves the regression.
#[cfg(unix)]
#[test]
fn daemon_startup_cohort_window_never_treated_as_very_new() {
    let dir = tempfile::tempdir().unwrap();
    let helper = dir.path().join("startup-helper.sh");
    let json = r#"[{"id":"w1","window":{"title":"quarterly report viewer","coverage_percent":0,"topmost":true,"has_close_button":true,"blocks_input":false,"origin":"unsolicited","age_ms":0}}]"#;
    std::fs::write(
        &helper,
        format!(
            "#!/bin/sh\ncase \"$1\" in\n--probe) exit 0 ;;\nenumerate) echo '{json}' ;;\ndismiss) exit 2 ;;\n*) exit 1 ;;\nesac\n"
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&helper).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&helper, perms).unwrap();
    }

    let audit_log = dir.path().join("audit.log");
    let stop_flag = dir.path().join("stop");

    let mut child = Command::new(env!("CARGO_BIN_EXE_muten-overlay"))
        .args([
            "daemon",
            helper.to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--interval-ms",
            "40",
            "--stop-flag",
            stop_flag.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");

    // Many closely-spaced sweeps of the same never-absent window — if its
    // age were (wrongly) inferred from first-seen time, most of these
    // sweeps would compute an age well under 1000ms and trip very_new.
    std::thread::sleep(std::time::Duration::from_millis(500));
    std::fs::write(&stop_flag, "").unwrap();
    let status = child.wait().expect("daemon exits");
    assert_eq!(status.code(), Some(0));

    if audit_log.exists() {
        let log_text = std::fs::read_to_string(&audit_log).unwrap();
        assert!(
            !log_text.contains("overlay_suspicious"),
            "a window present since the daemon's first sweep must never be scored as very_new: {log_text}"
        );
    }
}
