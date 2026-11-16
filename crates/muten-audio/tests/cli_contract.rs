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
fn fetch_policy_applies_validates_and_reports() {
    let bin = Path::new(env!("CARGO_BIN_EXE_muten-audio"));
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let (policy, _grant, log) = paths(dir);
    let (p, l) = (policy.to_str().unwrap(), log.to_str().unwrap());

    // The "central share" is a plain folder with a policy.json in it.
    let share = dir.join("share");
    std::fs::create_dir(&share).unwrap();
    let central = share.join("policy.json");
    let central_bytes =
        r#"{"version":1,"enforce":false,"allow_unmute":false,"max_unmute_minutes":15}"#;
    std::fs::write(&central, central_bytes).unwrap();
    let s = central.to_str().unwrap();

    // The local policy starts out different (enforcement on).
    std::fs::write(
        &policy,
        r#"{"version":1,"enforce":true,"allow_unmute":true,"max_unmute_minutes":30}"#,
    )
    .unwrap();

    // First pull: applied, and the local file now holds the central
    // bytes exactly.
    let r = run(
        bin,
        dir,
        &["fetch-policy", "--policy", p, "--source", s, "--log", l],
        "",
    );
    assert!(r.status.success(), "fetch-policy failed: {}", r.stderr);
    assert!(r.stdout.contains("Policy updated"), "stdout: {}", r.stdout);
    assert_eq!(std::fs::read_to_string(&policy).unwrap(), central_bytes);
    // The application is traceable in the audit log.
    let log_text = std::fs::read_to_string(&log).unwrap();
    assert!(log_text.contains("policy_updated"), "log: {log_text}");

    // Second pull of the same bytes: reported as up to date.
    let r = run(
        bin,
        dir,
        &["fetch-policy", "--policy", p, "--source", s, "--log", l],
        "",
    );
    assert!(r.status.success(), "fetch-policy failed: {}", r.stderr);
    assert!(r.stdout.contains("up to date"), "stdout: {}", r.stdout);

    // A tampered central copy is refused and the local policy is
    // left byte-for-byte untouched.
    std::fs::write(&central, "{tampered").unwrap();
    let r = run(
        bin,
        dir,
        &["fetch-policy", "--policy", p, "--source", s, "--log", l],
        "",
    );
    assert!(!r.status.success(), "tampered policy must be refused");
    assert_eq!(std::fs::read_to_string(&policy).unwrap(), central_bytes);

    // A missing source is an error too, never a silent pass.
    let r = run(
        bin,
        dir,
        &[
            "fetch-policy",
            "--policy",
            p,
            "--source",
            dir.join("nope.json").to_str().unwrap(),
            "--log",
            l,
        ],
        "",
    );
    assert!(!r.status.success(), "missing source must fail");
    assert_eq!(std::fs::read_to_string(&policy).unwrap(), central_bytes);
}

#[test]
fn fleet_status_aggregates_collected_logs() {
    let bin = Path::new(env!("CARGO_BIN_EXE_muten-audio"));
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();

    // Two "central shares": the master policy M and an older/other
    // policy N that one machine is still running.
    let master_bytes =
        r#"{"version":1,"enforce":false,"allow_unmute":false,"max_unmute_minutes":15}"#;
    let other_bytes = r#"{"version":1,"enforce":true,"allow_unmute":true,"max_unmute_minutes":45}"#;
    let share = dir.join("share");
    std::fs::create_dir(&share).unwrap();
    let master = share.join("policy.json");
    std::fs::write(&master, master_bytes).unwrap();
    let share2 = dir.join("share2");
    std::fs::create_dir(&share2).unwrap();
    let other = share2.join("policy.json");
    std::fs::write(&other, other_bytes).unwrap();

    // Machine A pulls the master; machine B pulls the other policy
    // and then fails a pull (missing source) so its log also carries
    // a failure. Local policies start out different from the shares
    // so each first pull is a real application.
    let mut logs: Vec<PathBuf> = Vec::new();
    for (name, source, start) in [("a", &master, other_bytes), ("b", &other, master_bytes)] {
        let home = dir.join(name);
        std::fs::create_dir(&home).unwrap();
        let policy = home.join("policy.json");
        std::fs::write(&policy, start).unwrap();
        let log = home.join(format!("pc-{name}.log"));
        let r = run(
            bin,
            dir,
            &[
                "fetch-policy",
                "--policy",
                policy.to_str().unwrap(),
                "--source",
                source.to_str().unwrap(),
                "--log",
                log.to_str().unwrap(),
            ],
            "",
        );
        assert!(r.status.success(), "fetch-policy failed: {}", r.stderr);
        logs.push(log);
    }
    let (log_a, log_b) = (logs[0].to_str().unwrap(), logs[1].to_str().unwrap());
    let r = run(
        bin,
        dir,
        &[
            "fetch-policy",
            "--policy",
            dir.join("b").join("policy.json").to_str().unwrap(),
            "--source",
            dir.join("missing.json").to_str().unwrap(),
            "--log",
            log_b,
        ],
        "",
    );
    assert!(!r.status.success(), "missing source must fail");

    // Aggregated against the master: A is current, B is STALE and
    // shows its failure — and the drift makes the command fail.
    let r = run(
        bin,
        dir,
        &[
            "fleet-status",
            "--master",
            master.to_str().unwrap(),
            log_a,
            log_b,
        ],
        "",
    );
    assert_eq!(r.status.code(), Some(1), "stdout: {}", r.stdout);
    assert!(r.stdout.contains("Expected policy sha256:"), "{}", r.stdout);
    assert!(r.stdout.contains("pc-a"), "{}", r.stdout);
    assert!(r.stdout.contains("current"), "{}", r.stdout);
    assert!(r.stdout.contains("pc-b"), "{}", r.stdout);
    assert!(r.stdout.contains("STALE"), "{}", r.stdout);
    assert!(r.stdout.contains("policy_fetch_failed"), "{}", r.stdout);
    assert!(
        r.stdout
            .contains("1 current, 1 STALE, 0 with no policy record"),
        "{}",
        r.stdout
    );

    // Without an expected policy there is no drift to fail on.
    let r = run(bin, dir, &["fleet-status", log_a], "");
    assert!(r.status.success(), "fleet-status failed: {}", r.stderr);
    assert!(r.stdout.contains("not checked"), "{}", r.stdout);

    // The directory form reads every *.log inside, and
    // --expect-sha256 is interchangeable with --master.
    let collected = dir.join("collected");
    std::fs::create_dir(&collected).unwrap();
    std::fs::copy(&logs[0], collected.join("pc-a.log")).unwrap();
    std::fs::copy(&logs[1], collected.join("pc-b.log")).unwrap();
    let master_sha = muten_audio::distribute::policy_sha256(master_bytes.as_bytes());
    let r = run(
        bin,
        dir,
        &[
            "fleet-status",
            "--expect-sha256",
            &master_sha,
            collected.to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(r.status.code(), Some(1), "stdout: {}", r.stdout);
    assert!(
        r.stdout.contains("pc-a") && r.stdout.contains("pc-b"),
        "{}",
        r.stdout
    );

    // --master and --expect-sha256 together are ambiguous.
    let r = run(
        bin,
        dir,
        &[
            "fleet-status",
            "--master",
            master.to_str().unwrap(),
            "--expect-sha256",
            &master_sha,
            log_a,
        ],
        "",
    );
    assert!(!r.status.success());
    assert!(r.stderr.contains("alternatives"), "stderr: {}", r.stderr);

    // A garbage line in a collected log is counted and reported, and
    // the broken chain fails the run — never silently skipped.
    let log_c = dir.join("pc-c.log");
    let mut text = std::fs::read_to_string(&logs[0]).unwrap();
    text.push_str("{junk\n");
    std::fs::write(&log_c, text).unwrap();
    let r = run(bin, dir, &["fleet-status", log_c.to_str().unwrap()], "");
    assert_eq!(r.status.code(), Some(1), "stdout: {}", r.stdout);
    assert!(r.stdout.contains("BROKEN"), "{}", r.stdout);
    assert!(r.stdout.contains("1 unreadable line(s)"), "{}", r.stdout);
}

#[test]
#[cfg(target_os = "linux")]
fn watch_linux_backend_without_audio_tools_stops_with_reason() {
    let bin = Path::new(env!("CARGO_BIN_EXE_muten-audio"));
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let (policy, grant, log) = paths(dir);
    std::fs::write(
        &policy,
        r#"{"version":1,"enforce":true,"allow_unmute":true,"max_unmute_minutes":30}"#,
    )
    .unwrap();

    // An empty PATH guarantees neither wpctl nor pactl can be found,
    // whatever the machine running the test has installed.
    let empty_path = dir.join("empty-bin");
    std::fs::create_dir(&empty_path).unwrap();
    let out = Command::new(bin)
        .args([
            "watch",
            "--policy",
            policy.to_str().unwrap(),
            "--grant",
            grant.to_str().unwrap(),
            "--log",
            log.to_str().unwrap(),
            "--backend",
            "linux",
            "--once",
        ])
        .current_dir(dir)
        .env("PATH", &empty_path)
        .output()
        .expect("spawn muten-audio");
    assert!(
        !out.status.success(),
        "watch must stop when no audio tool is usable: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The reason names both tools the operator could install.
    assert!(stderr.contains("wpctl"), "stderr: {stderr}");
    assert!(stderr.contains("pactl"), "stderr: {stderr}");
    // The agent never started: no audit log was created and nothing
    // was enforced.
    assert!(
        !log.exists(),
        "audit log must not be created on a failed start"
    );
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
