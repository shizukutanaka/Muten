//! muten-audio command line.
//!
//! Exit codes: 0 = success, 1 = error (message on stderr),
//! 2 = unmute denied (wrong PIN / not permitted / no PIN set).

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use muten_audio::audit::{verify_chain, AuditLog, Event, EventKind};
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

fn cmd_watch(
    policy_path: PathBuf,
    grant_path: PathBuf,
    log_path: PathBuf,
    helper: PathBuf,
    once: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = Policy::load(&policy_path)?;
    let paths = WatchPaths {
        policy: policy_path,
        grant: grant_path,
        log: log_path,
    };
    let backend = HelperBackend::new(helper);
    let mut watch = Watch::new(policy, paths, backend)?;
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
        } => cmd_watch(policy, grant, log, helper, once),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("muten-audio: error: {e}");
            ExitCode::FAILURE
        }
    }
}
