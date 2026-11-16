//! End-to-end contract tests for the `muten-audio` binary: the exact
//! flows the .bat launchers drive (init → unmute denied → unmute
//! granted → status → verify-log), using piped stdin for the PIN
//! prompts. No Windows audio is involved: the agent itself is not
//! started here (that needs a real endpoint); the watchdog loop is
//! covered by the library tests against a fake backend.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Run {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

fn run(bin: &Path, dir: &Path, args: &[&str], stdin_text: &str) -> Run {
    let mut child = Command::new(bin)
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn muten-audio");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_text.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    Run {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn paths(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (
        dir.join("policy.json"),
        dir.join("grant.json"),
        dir.join("audit.log"),
    )
}

#[test]
fn full_admin_flow() {
    let bin = Path::new(env!("CARGO_BIN_EXE_muten-audio"));
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let (policy, grant, log) = paths(dir);
    let (p, g, l) = (
        policy.to_str().unwrap(),
        grant.to_str().unwrap(),
        log.to_str().unwrap(),
    );

    // init refuses to overwrite, and sets the PIN from two prompts.
    let r = run(bin, dir, &["init", "--policy", p], "1357\n1357\n");
    assert!(r.status.success(), "init failed: {}", r.stderr);
    assert!(policy.exists());
    let r = run(bin, dir, &["init", "--policy", p], "1357\n1357\n");
    assert!(!r.status.success(), "second init must refuse to overwrite");

    // The policy file must never contain the PIN in plaintext.
    let policy_text = std::fs::read_to_string(&policy).unwrap();
    assert!(
        !policy_text.contains("\"1357\""),
        "PIN stored as a JSON string value in policy.json"
    );

    // Wrong PIN: exit code 2, no grant file.
    let r = run(
        bin,
        dir,
        &[
            "unmute",
            "--policy",
            p,
            "--grant",
            g,
            "--log",
            l,
            "--minutes",
            "10",
        ],
        "9999\n",
    );
    assert_eq!(
        r.status.code(),
        Some(2),
        "wrong PIN must exit 2: {}",
        r.stderr
    );
    assert!(!grant.exists());

    // Correct PIN, request above the 30-minute cap: granted, clamped.
    let r = run(
        bin,
        dir,
        &[
            "unmute",
            "--policy",
            p,
            "--grant",
            g,
            "--log",
            l,
            "--minutes",
            "999",
        ],
        "1357\n",
    );
    assert!(r.status.success(), "unmute failed: {}", r.stderr);
    assert!(r.stdout.contains("clamped"), "stdout: {}", r.stdout);
    let grant_text = std::fs::read_to_string(&grant).unwrap();
    assert!(
        grant_text.contains("\"minutes\": 30"),
        "grant: {grant_text}"
    );

    // Status runs and verify-log validates the chain the flow produced.
    let r = run(
        bin,
        dir,
        &["status", "--policy", p, "--grant", g, "--log", l],
        "",
    );
    assert!(r.status.success(), "status failed: {}", r.stderr);
    assert!(r.stdout.contains("chain OK"), "stdout: {}", r.stdout);
    let r = run(bin, dir, &["verify-log", "--log", l], "");
    assert!(r.status.success(), "verify-log failed: {}", r.stderr);
    assert!(r.stdout.contains("chain intact"), "stdout: {}", r.stdout);
}

#[test]
fn unmute_without_pin_set_is_denied() {
    let bin = Path::new(env!("CARGO_BIN_EXE_muten-audio"));
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let (policy, grant, log) = paths(dir);
    // Hand-write a policy with no PIN record.
    std::fs::write(
        &policy,
        r#"{"version":1,"enforce":true,"allow_unmute":true,"max_unmute_minutes":30}"#,
    )
    .unwrap();
    let r = run(
        bin,
        dir,
        &[
            "unmute",
            "--policy",
            policy.to_str().unwrap(),
            "--grant",
            grant.to_str().unwrap(),
            "--log",
            log.to_str().unwrap(),
            "--minutes",
            "5",
        ],
        "1234\n",
    );
    assert_eq!(r.status.code(), Some(2));
    assert!(!grant.exists());
}
