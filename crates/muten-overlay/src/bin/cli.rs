//! `muten-overlay` CLI. Subcommands:
//! - `classify` / `scareware` — dry-run a single decision (no action).
//! - `rules` — summarize a blocklist file.
//! - `enforce` — run the full enumerate→classify→dismiss loop over a
//!   JSON window list using the NullController (a dry-run controller
//!   that records dismiss requests instead of touching real windows).
//!   On a real host the daemon swaps in an OS controller; the loop
//!   logic is identical.
//! - `monitor` — run N sweeps over a JSON window list, writing a
//!   tamper-evident chained audit log to disk and printing a summary.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use muten_overlay::{
    classify, enforce, verify_chain, ChainedFileSink, Decision, EnumeratedWindow, MemorySink,
    Monitor, NullController, OverlayWindow, Ruleset, RunConfig,
};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "muten-overlay",
    version,
    about = "muten — overlay classifier (dry-run)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Classify one observed window described by a JSON file (or stdin
    /// with `-`). Exit code: 0 Allow, 5 Suspicious, 6 Block, 1 error.
    Classify {
        /// Path to the OverlayWindow JSON, or `-` for stdin.
        window: String,
        /// Optional blocklist file.
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Emit the full verdict as machine-readable JSON (for SIEM /
        /// scripting) instead of the human-readable summary. Exit codes
        /// are unchanged.
        #[arg(long)]
        json: bool,
    },
    /// Show a summary of a blocklist file (counts + sanity check).
    Rules { file: PathBuf },
    /// Assess whether a process + repeat count looks like scareware /
    /// rogue antivirus. Exit code: 0 benign, 7 scareware, 1 error.
    Scareware {
        /// Repeat count: how many times this overlay signature has
        /// appeared in the detection window.
        #[arg(long, default_value_t = 1)]
        repeats: u32,
        /// Owning process name, if known (e.g. "PCProtectorPlus.exe").
        #[arg(long)]
        process: Option<String>,
        /// Blocklist file with `process:` rules.
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Emit the verdict as machine-readable JSON. Exit codes
        /// unchanged.
        #[arg(long)]
        json: bool,
    },
    /// Dry-run the full enforce loop over a JSON array of windows
    /// (each an OverlayWindow with an extra "id" field), using the
    /// NullController. Reports per-window decision and which would be
    /// dismissed. Exit: 0 if nothing blocked, 6 if any window blocked.
    Enforce {
        /// JSON file with an array of {id, ...OverlayWindow} objects,
        /// or `-` for stdin.
        windows: String,
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Run N sweeps over a JSON window list, writing a tamper-evident
    /// chained audit log and printing an event summary. Demonstrates
    /// the full daemon loop. Exit: 0 ok, 1 error.
    Monitor {
        /// JSON file with an array of {id, ...OverlayWindow} objects.
        windows: String,
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Number of sweeps to run.
        #[arg(long, default_value_t = 1)]
        sweeps: u64,
        /// Write the chained audit log here. If omitted, an in-memory
        /// sink is used and the log is not persisted.
        #[arg(long)]
        audit_log: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.cmd {
        Cmd::Classify {
            window,
            rules,
            json,
        } => cmd_classify(&window, rules.as_deref(), json),
        Cmd::Rules { file } => cmd_rules(&file),
        Cmd::Scareware {
            repeats,
            process,
            rules,
            json,
        } => cmd_scareware(repeats, process.as_deref(), rules.as_deref(), json),
        Cmd::Enforce { windows, rules } => cmd_enforce(&windows, rules.as_deref()),
        Cmd::Monitor {
            windows,
            rules,
            sweeps,
            audit_log,
        } => cmd_monitor(&windows, rules.as_deref(), sweeps, audit_log.as_deref()),
    }
}

fn load_rules(path: Option<&std::path::Path>) -> Result<Ruleset, String> {
    match path {
        None => Ok(Ruleset::default()),
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .map_err(|e| format!("reading rules {}: {e}", p.display()))?;
            Ok(Ruleset::parse(&text))
        }
    }
}

fn cmd_classify(
    window: &str,
    rules: Option<&std::path::Path>,
    json: bool,
) -> Result<ExitCode, String> {
    let input = if window == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("reading stdin: {e}"))?;
        s
    } else {
        std::fs::read_to_string(window).map_err(|e| format!("reading {window}: {e}"))?
    };
    let w: OverlayWindow =
        serde_json::from_str(&input).map_err(|e| format!("parsing window JSON: {e}"))?;
    let rs = load_rules(rules)?;
    let v = classify(&w, &rs);

    if json {
        // Serialize the verdict and splice in the natural-language
        // explanation, so a SIEM gets the structured fields *and* the
        // human sentence in one object.
        let mut val = serde_json::to_value(&v).map_err(|e| format!("serializing verdict: {e}"))?;
        if let Some(obj) = val.as_object_mut() {
            obj.insert("explanation".into(), serde_json::Value::String(v.explain()));
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&val).map_err(|e| format!("encoding json: {e}"))?
        );
    } else {
        println!("decision: {:?}", v.decision);
        println!("score:    {}", v.score);
        println!("signals:  {}", v.signals.join(", "));
        if !v.categories.is_empty() {
            let cats: Vec<&str> = v.categories.iter().map(|c| c.as_str()).collect();
            println!("dark_patterns: {}", cats.join(", "));
        }
        if let Some(rule) = &v.matched_rule {
            println!("matched:  {rule}");
        }
        println!("why:      {}", v.explain());
    }

    use muten_overlay::Decision::*;
    Ok(match v.decision {
        Allow => ExitCode::from(0),
        Suspicious => ExitCode::from(5),
        Block => ExitCode::from(6),
    })
}

fn cmd_rules(file: &std::path::Path) -> Result<ExitCode, String> {
    let text =
        std::fs::read_to_string(file).map_err(|e| format!("reading {}: {e}", file.display()))?;
    let rs = Ruleset::parse(&text);
    println!("blocklist: {}", file.display());
    println!("  hosts:     {}", rs.host_count());
    println!("  titles:    {}", rs.title_count());
    println!("  processes: {}", rs.process_count());
    Ok(ExitCode::from(0))
}

fn cmd_scareware(
    repeats: u32,
    process: Option<&str>,
    rules: Option<&std::path::Path>,
    json: bool,
) -> Result<ExitCode, String> {
    let rs = load_rules(rules)?;
    let v = muten_overlay::assess(repeats, process, &rs);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| format!("encoding json: {e}"))?
        );
    } else {
        println!("decision:        {:?}", v.decision);
        println!("repeat_count:    {}", v.repeat_count);
        println!("signals:         {}", v.signals.join(", "));
        if let Some(p) = &v.matched_process {
            println!("matched_process: {p}");
        }
    }
    use muten_overlay::ScarewareDecision::*;
    Ok(match v.decision {
        Benign => ExitCode::from(0),
        Scareware => ExitCode::from(7),
    })
}

/// Input row for `enforce`: an OverlayWindow plus an id. We read into
/// a serde_json::Value array and split id from the rest so we don't
/// need a flatten wrapper struct (which complicates the public type).
/// Read a JSON array of `{id, ...OverlayWindow}` from a file path or
/// `-` (stdin) into `EnumeratedWindow`s. Shared by `enforce` and
/// `monitor`.
fn parse_windows(windows: &str) -> Result<Vec<EnumeratedWindow>, String> {
    let json = if windows == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("reading stdin: {e}"))?;
        s
    } else {
        std::fs::read_to_string(windows).map_err(|e| format!("reading {windows}: {e}"))?
    };

    let arr: Vec<serde_json::Value> = serde_json::from_str(&json)
        .map_err(|e| format!("expected a JSON array of windows: {e}"))?;

    let mut enumerated = Vec::with_capacity(arr.len());
    for (i, mut v) in arr.into_iter().enumerate() {
        let obj = v
            .as_object_mut()
            .ok_or_else(|| format!("window {i} is not an object"))?;
        let id = obj
            .remove("id")
            .and_then(|x| x.as_str().map(String::from))
            .unwrap_or_else(|| format!("window-{i}"));
        let window: OverlayWindow =
            serde_json::from_value(v).map_err(|e| format!("parsing window {i}: {e}"))?;
        enumerated.push(EnumeratedWindow { id, window });
    }
    Ok(enumerated)
}

fn cmd_enforce(windows: &str, rules: Option<&std::path::Path>) -> Result<ExitCode, String> {
    let enumerated = parse_windows(windows)?;

    let rs = load_rules(rules)?;
    let ctrl = NullController::with_windows(enumerated);
    let outcomes = enforce(&ctrl, &rs).map_err(|e| format!("enforce: {e}"))?;

    let mut any_block = false;
    for o in &outcomes {
        if o.decision == Decision::Block {
            any_block = true;
        }
        println!(
            "{:10} {:?} score={} dismissed={} signals=[{}]{}",
            o.window_id,
            o.decision,
            o.score,
            o.dismissed,
            o.signals.join(", "),
            o.matched_rule
                .as_ref()
                .map(|r| format!(" matched={r}"))
                .unwrap_or_default(),
        );
    }
    let dismissed = ctrl.dismissed();
    eprintln!(
        "{} window(s) assessed, {} dismissed",
        outcomes.len(),
        dismissed.len()
    );
    Ok(if any_block {
        ExitCode::from(6)
    } else {
        ExitCode::from(0)
    })
}

fn cmd_monitor(
    windows: &str,
    rules: Option<&std::path::Path>,
    sweeps: u64,
    audit_log: Option<&std::path::Path>,
) -> Result<ExitCode, String> {
    let enumerated = parse_windows(windows)?;
    let rs = load_rules(rules)?;
    let ctrl = NullController::with_windows(enumerated);
    let mut mon = Monitor::new(rs);

    // Logical clock: 1s per sweep, so repeat detection sees distinct
    // timestamps within the window.
    let t = std::cell::Cell::new(0u64);
    let clock = || {
        let v = t.get();
        t.set(v + 1_000);
        v
    };
    let cfg = RunConfig {
        interval_ms: 0, // no real sleep in the CLI demo
        max_sweeps: Some(sweeps),
    };
    let no_proc = |_: &str| None;

    // Pick the sink: persistent chained log, or in-memory.
    let total;
    let summary_head;
    if let Some(path) = audit_log {
        let sink = ChainedFileSink::open(path).map_err(|e| format!("opening audit log: {e}"))?;
        total = mon.run(&ctrl, &sink, &cfg, clock, no_proc, || false);
        summary_head = Some(sink.head());
        // Verify what we just wrote.
        let text = std::fs::read_to_string(path).map_err(|e| format!("reading log: {e}"))?;
        match verify_chain(&text) {
            Ok((count, head)) => {
                eprintln!("audit log: {count} event(s), head={head}, verified OK");
            }
            Err(e) => return Err(format!("written log failed verification: {e}")),
        }
    } else {
        let sink = MemorySink::new();
        total = mon.run(&ctrl, &sink, &cfg, clock, no_proc, || false);
        for ev in sink.events() {
            println!(
                "t={:<8} {:20} {:10} {}",
                ev.timestamp_ms,
                ev.kind,
                ev.window_id,
                serde_json::to_string(&ev.detail).unwrap_or_default()
            );
        }
        summary_head = None;
    }

    eprintln!(
        "{sweeps} sweep(s), {total} dismissal(s){}",
        summary_head
            .map(|h| format!(", head={h}"))
            .unwrap_or_default()
    );
    Ok(ExitCode::from(0))
}
