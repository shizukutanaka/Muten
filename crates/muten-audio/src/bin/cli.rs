//! muten-audio command line.
//!
//! Exit codes: 0 = success, 1 = error (message on stderr),
//! 2 = unmute denied (wrong PIN / not permitted / no PIN set).

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use muten_audio::audit::{verify_chain, AuditLog, Event, EventKind};
use muten_audio::distribute::{fetcher_for_source, policy_sha256, refresh_policy, RefreshOutcome};
use muten_audio::fleet::{
    analyze_log, collect_log_paths, format_unix_utc, machine_label, short_hash, ChainCheck,
    SyncStatus,
};
use muten_audio::grant::Grant;
use muten_audio::pin::{generate_salt, PinRecord};
use muten_audio::policy::Policy;
use muten_audio::time::now_unix;
use muten_audio::{HelperBackend, Watch, WatchPaths};

#[derive(Parser)]
#[command(
    name = "muten-audio",
    version,
    about = "muten forced-mute agent & admin tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a starter policy.json (and set the admin PIN).
    Init {
        #[arg(long, default_value = "policy.json")]
        policy: PathBuf,
    },
    /// Set or change the admin PIN in an existing policy.json.
    SetPin {
        #[arg(long, default_value = "policy.json")]
        policy: PathBuf,
    },
    /// Grant a temporary unmute (prompts for the admin PIN).
    Unmute {
        #[arg(long, default_value = "policy.json")]
        policy: PathBuf,
        #[arg(long, default_value = "grant.json")]
        grant: PathBuf,
        #[arg(long, default_value = "audit.log")]
        log: PathBuf,
        /// Requested minutes (clamped to the policy cap).
        #[arg(long)]
        minutes: u32,
    },
    /// Show policy, grant, and audit-log status.
    Status {
        #[arg(long, default_value = "policy.json")]
        policy: PathBuf,
        #[arg(long, default_value = "grant.json")]
        grant: PathBuf,
        #[arg(long, default_value = "audit.log")]
        log: PathBuf,
    },
    /// Verify the audit log's hash chain.
    VerifyLog {
        #[arg(long, default_value = "audit.log")]
        log: PathBuf,
    },
    /// Run the resident watchdog (this is what Start-Muten.bat launches).
    Watch {
        #[arg(long, default_value = "policy.json")]
        policy: PathBuf,
        #[arg(long, default_value = "grant.json")]
        grant: PathBuf,
        #[arg(long, default_value = "audit.log")]
        log: PathBuf,
        /// PowerShell helper script that performs the actual audio calls.
        #[arg(long, default_value = "audio-helper.ps1")]
        helper: PathBuf,
        /// Run a single poll and exit (smoke tests / scheduled tasks).
        #[arg(long)]
        once: bool,
        /// Central policy source to pull periodically: a file path
        /// (e.g. a shared folder) or an http(s) URL. Only policies
        /// that parse and validate are applied; failures are logged
        /// and the current policy stays in force.
        #[arg(long)]
        policy_source: Option<String>,
        /// Seconds between policy-source checks.
        #[arg(long, default_value_t = 300)]
        policy_source_interval: i64,
        /// PowerShell helper used to download a URL policy source.
        #[arg(long, default_value = "policy-fetch.ps1")]
        policy_helper: PathBuf,
    },
    /// Aggregate collected audit logs: which policy each machine
    /// last applied, from where, and its most recent failure.
    /// Read-only — it reads the logs you collected (one file per
    /// machine, labelled by file name); nothing is collected or
    /// sent anywhere.
    FleetStatus {
        /// Audit log files, or folders containing *.log files
        /// (one per machine).
        #[arg(required = true)]
        logs: Vec<PathBuf>,
        /// Master policy.json to compare against: machines whose
        /// last applied policy differs are reported STALE.
        #[arg(long)]
        master: Option<PathBuf>,
        /// Expected policy SHA-256 (hex) — an alternative to
        /// --master when you only have the hash.
        #[arg(long)]
        expect_sha256: Option<String>,
    },
    /// Pull the central policy once and apply it if it validates
    /// (for scheduled tasks and manual fleet updates).
    FetchPolicy {
        #[arg(long, default_value = "policy.json")]
        policy: PathBuf,
        /// Central policy source: a file path (e.g. a shared folder)
        /// or an http(s) URL.
        #[arg(long)]
        source: String,
        #[arg(long, default_value = "audit.log")]
        log: PathBuf,
        /// PowerShell helper used to download a URL policy source.
        #[arg(long, default_value = "policy-fetch.ps1")]
        policy_helper: PathBuf,
    },
}

fn read_line(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Read a PIN twice (for setting) or once (for verifying). Input is
/// echoed by the terminal — run these commands in a private console.
fn prompt_new_pin() -> Result<String, Box<dyn std::error::Error>> {
    let a = read_line("New admin PIN (4-64 chars): ")?;
    if a.len() < 4 || a.len() > 64 {
        return Err("PIN must be 4-64 characters".into());
    }
    let b = read_line("Repeat the PIN: ")?;
    if a != b {
        return Err("PINs did not match".into());
    }
    Ok(a)
}

fn save_policy(policy: &Policy, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, policy.to_json()?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn cmd_init(policy_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if policy_path.exists() {
        return Err(format!(
            "{} already exists; refusing to overwrite (use set-pin to change the PIN)",
            policy_path.display()
        )
        .into());
    }
    let mut policy = Policy::starter();
    let pin = prompt_new_pin()?;
    policy.pin = Some(PinRecord::new(&pin, &generate_salt()));
    save_policy(&policy, &policy_path)?;
    println!("Wrote {}", policy_path.display());
    println!(
        "Enforcement: always on. Unmute: allowed, up to {} minutes per grant.",
        policy.max_unmute_minutes
    );
    println!("Edit the schedule and options in policy.json, or open policy-editor.html.");
    Ok(())
}

fn cmd_set_pin(policy_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut policy = Policy::load(&policy_path)?;
    let pin = prompt_new_pin()?;
    policy.pin = Some(PinRecord::new(&pin, &generate_salt()));
    save_policy(&policy, &policy_path)?;
    println!("Admin PIN updated in {}", policy_path.display());
    Ok(())
}

fn cmd_unmute(
    policy_path: PathBuf,
    grant_path: PathBuf,
    log_path: PathBuf,
    minutes: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = now_unix();
    let mut log = AuditLog::open(&log_path).ok();
    let note = |kind: EventKind, detail: serde_json::Value, log: &mut Option<AuditLog>| {
        if let Some(l) = log.as_mut() {
            let _ = l.append(&Event {
                ts_unix: now,
                kind,
                detail,
            });
        }
    };

    let deny =
        |reason: &str, log: &mut Option<AuditLog>| -> Result<(), Box<dyn std::error::Error>> {
            note(
                EventKind::UnmuteDenied,
                serde_json::json!({"reason": reason}),
                log,
            );
            eprintln!("Unmute denied: {reason}");
            std::process::exit(2);
        };

    let policy = Policy::load(&policy_path)?;
    if !policy.allow_unmute {
        return deny("the policy does not allow temporary unmute", &mut log);
    }
    let Some(record) = &policy.pin else {
        return deny("no admin PIN is set (run set-pin first)", &mut log);
    };
    if minutes == 0 {
        return deny("minutes must be at least 1", &mut log);
    }
    let pin = read_line("Admin PIN: ")?;
    if !record.verify(&pin) {
        return deny("wrong PIN", &mut log);
    }
    let granted_minutes = minutes.min(policy.max_unmute_minutes);
    let grant = Grant::new(now, granted_minutes);
    grant.save(&grant_path)?;
    note(
        EventKind::UnmuteGranted,
        serde_json::json!({"minutes": granted_minutes, "expires_at_unix": grant.expires_at_unix}),
        &mut log,
    );
    if granted_minutes < minutes {
        println!("Note: the request was clamped to the policy cap of {granted_minutes} minutes.");
    }
    println!("Unmute granted for {granted_minutes} minutes. Sound will be restored on the agent's next poll and re-muted automatically when the grant expires.");
    Ok(())
}

fn cmd_status(
    policy_path: PathBuf,
    grant_path: PathBuf,
    log_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = Policy::load(&policy_path)?;
    println!("Policy: {}", policy_path.display());
    println!("  enforce          : {}", policy.enforce);
    println!("  schedule windows : {}", policy.schedule.len());
    println!("  utc offset (min) : {}", policy.utc_offset_minutes);
    println!("  allow unmute     : {}", policy.allow_unmute);
    println!("  max unmute (min) : {}", policy.max_unmute_minutes);
    println!("  admin PIN set    : {}", policy.pin.is_some());
    match Grant::load(&grant_path)? {
        Some(g) => {
            let now = now_unix();
            println!(
                "Grant: {} ({} minutes, {}active, {}s remaining)",
                grant_path.display(),
                g.minutes,
                if g.is_active(now) { "" } else { "not " },
                g.remaining_secs(now)
            );
        }
        None => println!("Grant: none"),
    }
    match std::fs::read_to_string(&log_path) {
        Ok(text) => match verify_chain(&text) {
            Ok(s) => println!("Audit log: {} events, chain OK, head {}", s.events, s.head),
            Err(e) => println!("Audit log: CHAIN BROKEN: {e}"),
        },
        Err(_) => println!("Audit log: not created yet"),
    }
    Ok(())
}

fn cmd_verify_log(log_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(&log_path)?;
    let status = verify_chain(&text)?;
    println!(
        "OK: {} events, chain intact, head {}",
        status.events, status.head
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_watch(
    policy_path: PathBuf,
    grant_path: PathBuf,
    log_path: PathBuf,
    helper: PathBuf,
    once: bool,
    policy_source: Option<String>,
    policy_source_interval: i64,
    policy_helper: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    if policy_source.is_some() && policy_source_interval < 10 {
        return Err("--policy-source-interval must be at least 10 seconds".into());
    }
    let policy = Policy::load(&policy_path)?;
    let paths = WatchPaths {
        policy: policy_path,
        grant: grant_path,
        log: log_path,
    };
    let backend = HelperBackend::new(helper);
    let mut watch = Watch::new(policy, paths, backend)?;
    if let Some(source) = policy_source {
        let fetcher = fetcher_for_source(&source, policy_helper);
        println!(
            "Policy source: {} (checked every {}s; only valid policies are applied)",
            fetcher.label(),
            policy_source_interval
        );
        watch = watch.with_policy_source(fetcher, policy_source_interval);
    }
    if once {
        let decision = watch.step(now_unix())?;
        println!("poll decision: {decision:?}");
        return Ok(());
    }
    println!("muten-audio agent running. Keep this window open; closing it stops enforcement.");
    println!("Events are written to the audit log. Press Ctrl+C to stop.");
    watch.run(now_unix)?;
    Ok(())
}

fn pad(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - len))
    }
}

fn cmd_fleet_status(
    logs: Vec<PathBuf>,
    master: Option<PathBuf>,
    expect_sha256: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if master.is_some() && expect_sha256.is_some() {
        return Err("--master and --expect-sha256 are alternatives; pass only one".into());
    }
    let expected: Option<String> = match (master, expect_sha256) {
        (Some(path), None) => {
            let bytes = std::fs::read(&path)
                .map_err(|e| format!("failed to read master policy {}: {e}", path.display()))?;
            Some(policy_sha256(&bytes))
        }
        (None, Some(h)) => {
            let h = h.trim().to_lowercase();
            if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("--expect-sha256 must be 64 hex characters".into());
            }
            Some(h)
        }
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("checked above"),
    };

    let paths = collect_log_paths(&logs)?;
    if paths.is_empty() {
        return Err("no audit logs to read".into());
    }
    let mut machines = Vec::new();
    for path in &paths {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        machines.push(analyze_log(&machine_label(path), &text));
    }

    if let Some(exp) = &expected {
        println!("Expected policy sha256: {exp}");
        println!();
    }
    let w_machine = machines
        .iter()
        .map(|m| m.label.chars().count())
        .max()
        .unwrap_or(0)
        .max("MACHINE".len());
    println!(
        "{}  {}  {}  {}  {}  CHAIN",
        pad("MACHINE", w_machine),
        pad("POLICY", 12),
        pad("APPLIED (UTC)", 19),
        pad("SYNC", 11),
        pad("LAST FAILURE (UTC)", 19),
    );
    for m in &machines {
        let policy = m
            .last_applied
            .as_ref()
            .map(|a| short_hash(&a.sha256).to_string())
            .unwrap_or_else(|| "—".to_string());
        let applied = m
            .last_applied
            .as_ref()
            .map(|a| format_unix_utc(a.ts_unix))
            .unwrap_or_else(|| "—".to_string());
        let sync = match m.sync_status(expected.as_deref()) {
            SyncStatus::Current => "current",
            SyncStatus::Stale => "STALE",
            SyncStatus::NoRecord => "no record",
            SyncStatus::NotChecked => "not checked",
        };
        let failure = m
            .last_failure
            .as_ref()
            .map(|f| format_unix_utc(f.ts_unix))
            .unwrap_or_else(|| "—".to_string());
        let chain = match &m.chain {
            ChainCheck::Intact { events } => {
                format!(
                    "intact ({events} event{})",
                    if *events == 1 { "" } else { "s" }
                )
            }
            ChainCheck::Excerpt { events } => {
                format!(
                    "excerpt ({events} event{})",
                    if *events == 1 { "" } else { "s" }
                )
            }
            ChainCheck::Broken { .. } => "BROKEN".to_string(),
        };
        println!(
            "{}  {}  {}  {}  {}  {}",
            pad(&m.label, w_machine),
            pad(&policy, 12),
            pad(&applied, 19),
            pad(sync, 11),
            pad(&failure, 19),
            chain,
        );
    }

    // Detail lines: everything the table cannot hold, per machine.
    let mut notes: Vec<String> = Vec::new();
    for m in &machines {
        if let Some(a) = &m.last_applied {
            notes.push(format!("{}: policy source {}", m.label, a.source));
        }
        if let Some(f) = &m.last_failure {
            let mut note = format!(
                "{}: last failure {} at {}",
                m.label,
                f.kind_name(),
                format_unix_utc(f.ts_unix)
            );
            if !f.error.is_empty() {
                note.push_str(&format!(": {}", f.error));
            }
            notes.push(note);
        }
        if let ChainCheck::Broken { line, reason } = &m.chain {
            if *line > 0 {
                notes.push(format!(
                    "{}: audit chain BROKEN at line {line}: {reason}",
                    m.label
                ));
            } else {
                notes.push(format!("{}: audit chain BROKEN: {reason}", m.label));
            }
        }
        if m.skipped_lines() > 0 {
            notes.push(format!(
                "{}: {} unreadable line(s), {} unknown-format line(s) counted and skipped",
                m.label, m.unreadable_lines, m.unknown_lines
            ));
        }
        if m.events == 0 {
            notes.push(format!("{}: no recognisable events in the log", m.label));
        }
    }
    if !notes.is_empty() {
        println!();
        for note in &notes {
            println!("{note}");
        }
    }

    let total_unreadable: usize = machines.iter().map(|m| m.unreadable_lines).sum();
    let total_unknown: usize = machines.iter().map(|m| m.unknown_lines).sum();
    println!();
    if expected.is_some() {
        let count = |want: SyncStatus| {
            machines
                .iter()
                .filter(|m| m.sync_status(expected.as_deref()) == want)
                .count()
        };
        println!(
            "{} machine(s): {} current, {} STALE, {} with no policy record.",
            machines.len(),
            count(SyncStatus::Current),
            count(SyncStatus::Stale),
            count(SyncStatus::NoRecord),
        );
    } else {
        println!(
            "{} machine(s) (no expected policy given; pass --master or --expect-sha256 to compare).",
            machines.len()
        );
    }
    if total_unreadable + total_unknown > 0 {
        println!(
            "Skipped lines across all logs: {total_unreadable} unreadable, {total_unknown} unknown-format (counted above, never silently dropped)."
        );
    }

    let attention = machines.iter().any(|m| {
        matches!(m.chain, ChainCheck::Broken { .. })
            || (expected.is_some()
                && matches!(
                    m.sync_status(expected.as_deref()),
                    SyncStatus::Stale | SyncStatus::NoRecord
                ))
    });
    if attention {
        return Err("one or more machines need attention (see the table above)".into());
    }
    Ok(())
}

fn cmd_fetch_policy(
    policy_path: PathBuf,
    source: String,
    log_path: PathBuf,
    policy_helper: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = now_unix();
    let fetcher = fetcher_for_source(&source, policy_helper);
    let label = fetcher.label();
    // The audit log is best-effort here, as in `unmute`: the outcome
    // is always printed, and recorded when the log can be opened.
    let mut log = AuditLog::open(&log_path).ok();
    let note = |kind: EventKind, detail: serde_json::Value, log: &mut Option<AuditLog>| {
        if let Some(l) = log.as_mut() {
            let _ = l.append(&Event {
                ts_unix: now,
                kind,
                detail,
            });
        }
    };
    match refresh_policy(fetcher.as_ref(), &policy_path) {
        Ok(RefreshOutcome::Unchanged) => {
            println!("Policy already up to date (source: {label}).");
            Ok(())
        }
        Ok(RefreshOutcome::Applied { policy, sha256 }) => {
            note(
                EventKind::PolicyUpdated,
                serde_json::json!({
                    "source": label,
                    "sha256": sha256,
                    "enforce": policy.enforce,
                    "allow_unmute": policy.allow_unmute,
                    "max_unmute_minutes": policy.max_unmute_minutes,
                    "schedule_windows": policy.schedule.len(),
                    "pin_set": policy.pin.is_some(),
                }),
                &mut log,
            );
            println!(
                "Policy updated from {label} (sha256 {sha256}); wrote {}",
                policy_path.display()
            );
            Ok(())
        }
        Err(e) => {
            let kind = if matches!(e, muten_audio::Error::Backend(_)) {
                EventKind::PolicyFetchFailed
            } else {
                EventKind::PolicyError
            };
            note(
                kind,
                serde_json::json!({
                    "what": "policy_source",
                    "source": label,
                    "error": e.to_string(),
                }),
                &mut log,
            );
            Err(format!(
                "policy NOT updated ({} left untouched): {e}",
                policy_path.display()
            )
            .into())
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Init { policy } => cmd_init(policy),
        Command::SetPin { policy } => cmd_set_pin(policy),
        Command::Unmute {
            policy,
            grant,
            log,
            minutes,
        } => cmd_unmute(policy, grant, log, minutes),
        Command::Status { policy, grant, log } => cmd_status(policy, grant, log),
        Command::VerifyLog { log } => cmd_verify_log(log),
        Command::Watch {
            policy,
            grant,
            log,
            helper,
            once,
            policy_source,
            policy_source_interval,
            policy_helper,
        } => cmd_watch(
            policy,
            grant,
            log,
            helper,
            once,
            policy_source,
            policy_source_interval,
            policy_helper,
        ),
        Command::FleetStatus {
            logs,
            master,
            expect_sha256,
        } => cmd_fleet_status(logs, master, expect_sha256),
        Command::FetchPolicy {
            policy,
            source,
            log,
            policy_helper,
        } => cmd_fetch_policy(policy, source, log, policy_helper),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("muten-audio: error: {e}");
            ExitCode::FAILURE
        }
    }
}
