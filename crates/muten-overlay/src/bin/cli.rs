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
use muten_overlay::sink::merkle_root_of_log;
use muten_overlay::{
    classify, enforce, verify_chain, ChainedFileSink, Decision, EnumeratedWindow, MemorySink,
    Monitor, NullController, OverlayWindow, Ruleset, RunConfig,
};
use std::path::PathBuf;
use std::process::ExitCode;

/// Stable exit codes, documented in `--help` (see SPECIFICATION.md §10).
const EXIT_CODES: &str = "\
Exit codes:
  0  Allow / benign / OK
  5  Suspicious (classify: window flagged for review, not dismissed)
  6  Block (classify, or enforce: at least one window blocked)
  7  Scareware (scareware: rogue-AV / repeat-flood detected)
  1  error (bad input, I/O, or a broken audit log)";

// ── Colored output (NO_COLOR-compliant) ──────────────────────────
//
// Human-readable decisions are tinted (Block=red, Suspicious=yellow,
// Allow=green) so an operator scanning a terminal spots a Block at a
// glance. We follow the https://no-color.org convention: color is
// emitted only when stdout is a real terminal AND `$NO_COLOR` is unset
// (or empty). Piping to a file or a SIEM, or setting `NO_COLOR=1`, gives
// plain text — so machine consumers and `--json` are never affected.

const C_RED: &str = "\x1b[31m";
const C_YELLOW: &str = "\x1b[33m";
const C_GREEN: &str = "\x1b[32m";
const C_RESET: &str = "\x1b[0m";

/// Decide whether to emit ANSI color. Pure (env + tty passed in) so the
/// NO_COLOR precedence is unit-testable without a real terminal.
fn should_colorize(no_color_set: bool, is_tty: bool) -> bool {
    is_tty && !no_color_set
}

/// True if color should be used for the current process' stdout.
fn color_enabled() -> bool {
    use std::io::IsTerminal;
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    should_colorize(no_color, std::io::stdout().is_terminal())
}

/// ANSI code for a decision, or "" when color is disabled.
fn decision_color(d: Decision, on: bool) -> &'static str {
    if !on {
        return "";
    }
    match d {
        Decision::Allow => C_GREEN,
        Decision::Suspicious => C_YELLOW,
        Decision::Block => C_RED,
    }
}

/// Wrap `text` in `code`/reset when `on`, else return it plain.
fn paint(text: &str, code: &str, on: bool) -> String {
    if on && !code.is_empty() {
        format!("{code}{text}{C_RESET}")
    } else {
        text.to_string()
    }
}

#[derive(Parser)]
#[command(
    name = "muten-overlay",
    version,
    about = "muten — overlay classifier (dry-run)",
    after_help = EXIT_CODES
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
        /// Emit a JSON array of per-window outcomes instead of the
        /// human-readable table. Exit code unchanged.
        #[arg(long)]
        json: bool,
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
        /// Emit a JSON document on stdout (the audit events, or a
        /// summary when `--audit-log` is set) instead of the text table.
        #[arg(long)]
        json: bool,
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
        Cmd::Enforce {
            windows,
            rules,
            json,
        } => cmd_enforce(&windows, rules.as_deref(), json),
        Cmd::Monitor {
            windows,
            rules,
            sweeps,
            audit_log,
            json,
        } => cmd_monitor(
            &windows,
            rules.as_deref(),
            sweeps,
            audit_log.as_deref(),
            json,
        ),
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
        let on = color_enabled();
        let decision = paint(
            &format!("{:?}", v.decision),
            decision_color(v.decision, on),
            on,
        );
        println!("decision: {decision}");
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

fn cmd_enforce(
    windows: &str,
    rules: Option<&std::path::Path>,
    json: bool,
) -> Result<ExitCode, String> {
    let enumerated = parse_windows(windows)?;

    let rs = load_rules(rules)?;
    let ctrl = NullController::with_windows(enumerated);
    let outcomes = enforce(&ctrl, &rs).map_err(|e| format!("enforce: {e}"))?;

    let any_block = outcomes.iter().any(|o| o.decision == Decision::Block);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&outcomes).map_err(|e| format!("encoding json: {e}"))?
        );
    } else {
        let on = color_enabled();
        for o in &outcomes {
            let decision = paint(
                &format!("{:?}", o.decision),
                decision_color(o.decision, on),
                on,
            );
            println!(
                "{:10} {decision} score={} dismissed={} signals=[{}]{}",
                o.window_id,
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
    }
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
    json: bool,
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
        let head = sink.head();
        summary_head = Some(head.clone());
        // Verify what we just wrote.
        let text = std::fs::read_to_string(path).map_err(|e| format!("reading log: {e}"))?;
        let count = match verify_chain(&text) {
            Ok((count, head)) => {
                if !json {
                    eprintln!("audit log: {count} event(s), head={head}, verified OK");
                }
                count
            }
            Err(e) => return Err(format!("written log failed verification: {e}")),
        };
        // RFC 6962 Merkle root: a single commitment over every event,
        // publishable/signable out-of-band as an external anchor.
        let merkle_root =
            merkle_root_of_log(&text).map_err(|e| format!("computing merkle root: {e}"))?;
        if !json {
            eprintln!("audit log: merkle_root={merkle_root}");
        }
        if json {
            // With a persisted chain we don't hold events in memory;
            // emit a verifiable summary object instead.
            let summary = serde_json::json!({
                "sweeps": sweeps,
                "dismissals": total,
                "event_count": count,
                "head": head,
                "merkle_root": merkle_root,
                "verified": true,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&summary)
                    .map_err(|e| format!("encoding json: {e}"))?
            );
        }
    } else {
        let sink = MemorySink::new();
        total = mon.run(&ctrl, &sink, &cfg, clock, no_proc, || false);
        let events = sink.events();
        if json {
            let doc = serde_json::json!({
                "sweeps": sweeps,
                "dismissals": total,
                "events": events,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&doc).map_err(|e| format!("encoding json: {e}"))?
            );
        } else {
            for ev in &events {
                println!(
                    "t={:<8} {:20} {:10} {}",
                    ev.timestamp_ms,
                    ev.kind,
                    ev.window_id,
                    serde_json::to_string(&ev.detail).unwrap_or_default()
                );
            }
        }
        summary_head = None;
    }

    if !json {
        eprintln!(
            "{sweeps} sweep(s), {total} dismissal(s){}",
            summary_head
                .map(|h| format!(", head={h}"))
                .unwrap_or_default()
        );
    }
    Ok(ExitCode::from(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_precedence() {
        // Color only when a TTY AND NO_COLOR unset.
        assert!(should_colorize(false, true));
        // NO_COLOR set wins even on a TTY (https://no-color.org).
        assert!(!should_colorize(true, true));
        // Not a TTY (piped/redirected) → never color, regardless of env.
        assert!(!should_colorize(false, false));
        assert!(!should_colorize(true, false));
    }

    #[test]
    fn decision_color_maps_severity() {
        assert_eq!(decision_color(Decision::Block, true), C_RED);
        assert_eq!(decision_color(Decision::Suspicious, true), C_YELLOW);
        assert_eq!(decision_color(Decision::Allow, true), C_GREEN);
        // Color off → empty code for every decision.
        assert_eq!(decision_color(Decision::Block, false), "");
    }

    #[test]
    fn paint_wraps_only_when_enabled() {
        assert_eq!(
            paint("Block", C_RED, true),
            format!("{C_RED}Block{C_RESET}")
        );
        // Disabled → plain text, no escape codes.
        assert_eq!(paint("Block", C_RED, false), "Block");
        // Empty code (color-off path) → plain text even when on.
        assert_eq!(paint("Block", "", true), "Block");
    }
}
