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
//! - `verify` — verify the tamper-evident hash chain of an audit log.
//! - `signals` — list every built-in detection signal with metadata.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use muten_overlay::confusables::sanitize_for_display;
use muten_overlay::sink::merkle_root_of_log;
use muten_overlay::{
    all_signals, classify, enforce, verify_chain, ChainedFileSink, Decision, EnumeratedWindow,
    MemorySink, Monitor, NullController, OverlayWindow, Ruleset, RunConfig,
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
    long_version = concat!(
        env!("CARGO_PKG_VERSION"),
        " (commit ",
        env!("MUTEN_GIT_COMMIT"),
        ")"
    ),
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
        /// NDJSON streaming mode: read one JSON OverlayWindow per line
        /// from the window argument (use `-` for stdin). Each line
        /// produces one JSON verdict line on stdout. Exit code is the
        /// worst verdict seen (0 all-Allow, 5 any-Suspicious, 6 any-Block).
        /// Empty lines are skipped. Implies JSON output.
        #[arg(long)]
        stream: bool,
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
    /// Verify the tamper-evident integrity of an audit log produced by
    /// the `monitor` subcommand. Replays the hash chain and reports the
    /// event count and final Merkle root. Exit: 0 if the log is intact,
    /// 1 if tampered, truncated, or structurally invalid.
    Verify {
        /// Path to the NDJSON audit log file to verify.
        log: PathBuf,
        /// Emit the result as JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// List every built-in detection signal with its default weight,
    /// dark-pattern category, MITRE ATT&CK technique IDs, and
    /// plain-language description. Useful for MDM operators building
    /// blocklist templates, SIEM lookup tables, or documentation.
    /// Exit: 0 always.
    Signals {
        /// Emit the catalog as a JSON array instead of a plain text table.
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
        /// Write Prometheus textfile metrics to this path after all sweeps
        /// (compatible with node_exporter --collector.textfile). Metrics:
        /// muten_sweeps_total, muten_dismissals_total, muten_blocks_total,
        /// muten_suspicious_total, muten_scareware_total.
        #[arg(long)]
        metrics: Option<PathBuf>,
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
            stream,
        } => {
            if stream {
                cmd_classify_stream(&window, rules.as_deref())
            } else {
                cmd_classify(&window, rules.as_deref(), json)
            }
        }
        Cmd::Rules { file } => cmd_rules(&file),
        Cmd::Verify { log, json } => cmd_verify(&log, json),
        Cmd::Signals { json } => cmd_signals(json),
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
            metrics,
        } => cmd_monitor(
            &windows,
            rules.as_deref(),
            sweeps,
            audit_log.as_deref(),
            json,
            metrics.as_deref(),
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
        // Serialize the verdict and splice in computed fields that aren't
        // in the struct (explanation, confidence, score_breakdown) so a
        // SIEM gets structured fields AND the human sentence in one object.
        let mut val = serde_json::to_value(&v).map_err(|e| format!("serializing verdict: {e}"))?;
        if let Some(obj) = val.as_object_mut() {
            obj.insert("explanation".into(), serde_json::Value::String(v.explain()));
            obj.insert(
                "confidence".into(),
                serde_json::to_value(v.confidence())
                    .map_err(|e| format!("serializing confidence: {e}"))?,
            );
            let breakdown: Vec<serde_json::Value> = v
                .score_breakdown()
                .into_iter()
                .map(|(sig, w)| serde_json::json!({"signal": sig, "weight": w}))
                .collect();
            obj.insert(
                "score_breakdown".into(),
                serde_json::Value::Array(breakdown),
            );
            let actions: Vec<serde_json::Value> = v
                .recommended_action()
                .into_iter()
                .map(|a| serde_json::Value::String(a.to_string()))
                .collect();
            obj.insert(
                "recommended_action".into(),
                serde_json::Value::Array(actions),
            );
            let principles: Vec<serde_json::Value> = v
                .persuasion_principles()
                .into_iter()
                .map(|p| serde_json::Value::String(p.as_str().to_string()))
                .collect();
            obj.insert(
                "persuasion_principles".into(),
                serde_json::Value::Array(principles),
            );
            let vectors: Vec<serde_json::Value> = v
                .extraction_vectors()
                .into_iter()
                .map(|x| serde_json::Value::String(x.as_str().to_string()))
                .collect();
            obj.insert(
                "extraction_vectors".into(),
                serde_json::Value::Array(vectors),
            );
            if let Some(r) = v.worst_recoverability() {
                obj.insert(
                    "worst_recoverability".into(),
                    serde_json::Value::String(r.as_str().to_string()),
                );
            }
            let stages: Vec<serde_json::Value> = v
                .scam_stages()
                .into_iter()
                .map(|s| serde_json::Value::String(s.as_str().to_string()))
                .collect();
            obj.insert("scam_stages".into(), serde_json::Value::Array(stages));
            if let Some(h) = v.highest_stage() {
                obj.insert(
                    "highest_stage".into(),
                    serde_json::Value::String(h.as_str().to_string()),
                );
            }
            let profiles: Vec<serde_json::Value> = v
                .victim_profiles()
                .into_iter()
                .map(|p| serde_json::Value::String(p.as_str().to_string()))
                .collect();
            obj.insert("victim_profiles".into(), serde_json::Value::Array(profiles));
            obj.insert(
                "is_targeted_attack".into(),
                serde_json::Value::Bool(v.is_targeted_attack()),
            );
            let mags: Vec<serde_json::Value> = v
                .loss_magnitudes()
                .into_iter()
                .map(|m| serde_json::Value::String(m.as_str().to_string()))
                .collect();
            obj.insert("loss_magnitudes".into(), serde_json::Value::Array(mags));
            if let Some(h) = v.highest_magnitude() {
                obj.insert(
                    "highest_magnitude".into(),
                    serde_json::json!({
                        "band": h.as_str(),
                        "range": h.range_label(),
                    }),
                );
            }
            obj.insert(
                "signal_fingerprint".into(),
                serde_json::Value::String(v.signal_fingerprint()),
            );
            obj.insert(
                "campaign_bucket".into(),
                serde_json::Value::String(v.campaign_bucket()),
            );
            obj.insert(
                "response_priority".into(),
                serde_json::json!({
                    "level": v.response_priority().as_str(),
                    "p_label": v.response_priority().p_label(),
                    "score": v.priority_score(),
                }),
            );
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
        if !v.mitre_techniques.is_empty() {
            println!("mitre:    {}", v.mitre_techniques.join(", "));
        }
        let principles = v.persuasion_principles();
        if !principles.is_empty() {
            let names: Vec<&str> = principles.iter().map(|p| p.as_str()).collect();
            println!("persuasion: {}", names.join(", "));
        }
        let vectors = v.extraction_vectors();
        if !vectors.is_empty() {
            let names: Vec<&str> = vectors.iter().map(|x| x.as_str()).collect();
            print!("extraction: {}", names.join(", "));
            if let Some(r) = v.worst_recoverability() {
                print!(" (recoverability: {})", r.as_str());
            }
            println!();
        }
        let stages = v.scam_stages();
        if !stages.is_empty() {
            let names: Vec<&str> = stages.iter().map(|s| s.as_str()).collect();
            print!("kill_chain: {}", names.join(", "));
            if let Some(h) = v.highest_stage() {
                print!(" (highest: {})", h.as_str());
            }
            println!();
        }
        let profiles = v.victim_profiles();
        if !profiles.is_empty() {
            let names: Vec<&str> = profiles.iter().map(|p| p.as_str()).collect();
            print!("targets:   {}", names.join(", "));
            if v.is_targeted_attack() {
                print!(" [targeted]");
            }
            println!();
        }
        if let Some(h) = v.highest_magnitude() {
            println!("exposure:  {} ({})", h.as_str(), h.range_label());
        }
        let fp = v.signal_fingerprint();
        if !fp.is_empty() {
            println!("fingerprint: {fp}");
        }
        println!("campaign:  {}", v.campaign_bucket());
        let prio = v.response_priority();
        println!(
            "priority:  {} ({}, score {})",
            prio.as_str(),
            prio.p_label(),
            v.priority_score()
        );
        if let Some(rule) = &v.matched_rule {
            println!("matched:  {rule}");
        }
        println!("why:      {}", v.explain());
        let actions = v.recommended_action();
        if !actions.is_empty() {
            println!("action:");
            for a in actions {
                println!("  - {a}");
            }
        }
    }

    use muten_overlay::Decision::*;
    Ok(match v.decision {
        Allow => ExitCode::from(0),
        Suspicious => ExitCode::from(5),
        Block => ExitCode::from(6),
    })
}

/// NDJSON streaming variant: read one OverlayWindow JSON per line,
/// emit one verdict JSON per line. Exit code is worst verdict seen.
fn cmd_classify_stream(window: &str, rules: Option<&std::path::Path>) -> Result<ExitCode, String> {
    use std::io::{BufRead, BufReader};

    let rs = load_rules(rules)?;

    let reader: Box<dyn BufRead> = if window == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        let f = std::fs::File::open(window).map_err(|e| format!("opening {window}: {e}"))?;
        Box::new(BufReader::new(f))
    };

    let mut worst_code: u8 = 0;
    for (lineno, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("line {lineno}: read error: {e}"))?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let w: OverlayWindow = serde_json::from_str(line)
            .map_err(|e| format!("line {lineno}: parsing window JSON: {e}"))?;
        let v = classify(&w, &rs);
        let code = match v.decision {
            Decision::Allow => 0u8,
            Decision::Suspicious => 5,
            Decision::Block => 6,
        };
        if code > worst_code {
            worst_code = code;
        }
        let mut val =
            serde_json::to_value(&v).map_err(|e| format!("line {lineno}: serializing: {e}"))?;
        if let Some(obj) = val.as_object_mut() {
            obj.insert("explanation".into(), serde_json::Value::String(v.explain()));
            obj.insert(
                "confidence".into(),
                serde_json::to_value(v.confidence())
                    .map_err(|e| format!("line {lineno}: serializing confidence: {e}"))?,
            );
            let breakdown: Vec<serde_json::Value> = v
                .score_breakdown()
                .into_iter()
                .map(|(sig, w)| serde_json::json!({"signal": sig, "weight": w}))
                .collect();
            obj.insert(
                "score_breakdown".into(),
                serde_json::Value::Array(breakdown),
            );
            let actions: Vec<serde_json::Value> = v
                .recommended_action()
                .into_iter()
                .map(|a| serde_json::Value::String(a.to_string()))
                .collect();
            obj.insert(
                "recommended_action".into(),
                serde_json::Value::Array(actions),
            );
            let principles: Vec<serde_json::Value> = v
                .persuasion_principles()
                .into_iter()
                .map(|p| serde_json::Value::String(p.as_str().to_string()))
                .collect();
            obj.insert(
                "persuasion_principles".into(),
                serde_json::Value::Array(principles),
            );
            let vectors: Vec<serde_json::Value> = v
                .extraction_vectors()
                .into_iter()
                .map(|x| serde_json::Value::String(x.as_str().to_string()))
                .collect();
            obj.insert(
                "extraction_vectors".into(),
                serde_json::Value::Array(vectors),
            );
            if let Some(r) = v.worst_recoverability() {
                obj.insert(
                    "worst_recoverability".into(),
                    serde_json::Value::String(r.as_str().to_string()),
                );
            }
            let stages: Vec<serde_json::Value> = v
                .scam_stages()
                .into_iter()
                .map(|s| serde_json::Value::String(s.as_str().to_string()))
                .collect();
            obj.insert("scam_stages".into(), serde_json::Value::Array(stages));
            if let Some(h) = v.highest_stage() {
                obj.insert(
                    "highest_stage".into(),
                    serde_json::Value::String(h.as_str().to_string()),
                );
            }
            let profiles: Vec<serde_json::Value> = v
                .victim_profiles()
                .into_iter()
                .map(|p| serde_json::Value::String(p.as_str().to_string()))
                .collect();
            obj.insert("victim_profiles".into(), serde_json::Value::Array(profiles));
            obj.insert(
                "is_targeted_attack".into(),
                serde_json::Value::Bool(v.is_targeted_attack()),
            );
            let mags: Vec<serde_json::Value> = v
                .loss_magnitudes()
                .into_iter()
                .map(|m| serde_json::Value::String(m.as_str().to_string()))
                .collect();
            obj.insert("loss_magnitudes".into(), serde_json::Value::Array(mags));
            if let Some(h) = v.highest_magnitude() {
                obj.insert(
                    "highest_magnitude".into(),
                    serde_json::json!({
                        "band": h.as_str(),
                        "range": h.range_label(),
                    }),
                );
            }
            obj.insert(
                "signal_fingerprint".into(),
                serde_json::Value::String(v.signal_fingerprint()),
            );
            obj.insert(
                "campaign_bucket".into(),
                serde_json::Value::String(v.campaign_bucket()),
            );
            obj.insert(
                "response_priority".into(),
                serde_json::json!({
                    "level": v.response_priority().as_str(),
                    "p_label": v.response_priority().p_label(),
                    "score": v.priority_score(),
                }),
            );
        }
        println!(
            "{}",
            serde_json::to_string(&val)
                .map_err(|e| format!("line {lineno}: encoding json: {e}"))?
        );
    }
    Ok(ExitCode::from(worst_code))
}

fn cmd_rules(file: &std::path::Path) -> Result<ExitCode, String> {
    use muten_overlay::rules::CompositeCondition;
    use muten_overlay::BLOCK_THRESHOLD;

    let text =
        std::fs::read_to_string(file).map_err(|e| format!("reading {}: {e}", file.display()))?;
    let rs = Ruleset::parse(&text);
    println!("blocklist: {}", file.display());
    println!("  hosts:       {}", rs.host_count());
    println!("  titles:      {}", rs.title_count());
    println!("  globs:       {}", rs.glob_count());
    println!("  phones:      {}", rs.phone_count());
    println!("  processes:   {}", rs.process_count());
    println!("  composites:  {}", rs.composite_count());
    println!("  weight overrides: {}", rs.weight_override_count());

    // Bounded-weight guard: warn when a composite rule covers only
    // geometry/origin conditions (no content tell) but its weight alone
    // could push a bare-shape window past BLOCK_THRESHOLD. Such a rule
    // risks auto-blocking kiosk/lockdown shells. See SPECIFICATION §5.1.
    let content_tells = [
        CompositeCondition::HasBlocklistTitle,
        CompositeCondition::HasPhoneNumber,
        CompositeCondition::HasBlocklistPhone,
    ];
    let mut warnings = 0usize;
    for rule in rs.composite_rules() {
        let has_content_tell = rule.conditions.iter().any(|c| content_tells.contains(c));
        if !has_content_tell && rule.weight >= BLOCK_THRESHOLD {
            eprintln!(
                "WARNING: composite rule '{}' has weight {} ≥ BLOCK_THRESHOLD ({}) \
                 with no content-tell condition — a geometry-only window could \
                 be auto-blocked, violating the observe-first FP-aversion guarantee. \
                 Consider adding has_blocklist_title, has_phone_number, or \
                 has_blocklist_phone, or reducing weight.",
                rule.name, rule.weight, BLOCK_THRESHOLD
            );
            warnings += 1;
        }
    }
    if warnings > 0 {
        eprintln!("{warnings} bounded-weight warning(s) — see SPECIFICATION.md §5.1");
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::from(0))
}

fn cmd_verify(log: &std::path::Path, json: bool) -> Result<ExitCode, String> {
    let text =
        std::fs::read_to_string(log).map_err(|e| format!("reading {}: {e}", log.display()))?;
    match verify_chain(&text) {
        Ok((count, head)) => {
            if json {
                let root = merkle_root_of_log(&text).ok();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "ok",
                        "event_count": count,
                        "chain_head": head,
                        "merkle_root": root,
                        "log": log.display().to_string(),
                    }))
                    .map_err(|e| format!("serializing: {e}"))?
                );
            } else {
                let on = color_enabled();
                println!("chain: {}", paint("OK", C_GREEN, on));
                println!("events:     {count}");
                println!("chain_head: {head}");
                if let Ok(root) = merkle_root_of_log(&text) {
                    println!("merkle_root: {root}");
                }
                println!("log:        {}", log.display());
            }
            Ok(ExitCode::from(0))
        }
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "tampered",
                        "error": e.to_string(),
                        "log": log.display().to_string(),
                    }))
                    .map_err(|e2| format!("serializing: {e2}"))?
                );
            } else {
                let on = color_enabled();
                eprintln!("chain: {} — {e}", paint("TAMPERED", C_RED, on));
            }
            Ok(ExitCode::from(1))
        }
    }
}

fn cmd_signals(json: bool) -> Result<ExitCode, String> {
    let signals = all_signals();
    if json {
        let val = serde_json::to_string_pretty(&signals)
            .map_err(|e| format!("serializing signals: {e}"))?;
        println!("{val}");
    } else {
        println!(
            "{:<36} {:>7}  {:<22}  {:<12}  DESCRIPTION",
            "SIGNAL", "WEIGHT", "CATEGORY", "MITRE"
        );
        println!("{}", "-".repeat(120));
        for s in &signals {
            let weight = match s.default_weight {
                Some(w) => format!("{w:+}"),
                None => "n/a".to_string(),
            };
            let cat = s
                .category
                .map(|c| c.as_str().to_string())
                .unwrap_or_default();
            let mitre = if s.mitre_techniques.is_empty() {
                String::new()
            } else {
                s.mitre_techniques.join(",")
            };
            let desc = {
                let mut chars = s.description.chars();
                let truncated: String = chars.by_ref().take(59).collect();
                if chars.next().is_some() {
                    format!("{truncated}…")
                } else {
                    truncated
                }
            };
            println!(
                "{:<36} {:>7}  {:<22}  {:<12}  {}",
                s.name, weight, cat, mitre, desc
            );
        }
        println!();
        println!("{} built-in signals", signals.len());
    }
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
                sanitize_for_display(&o.window_id),
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

/// Write a Prometheus textfile (node_exporter --collector.textfile format).
/// Gauges/counters for the completed monitor run; compatible with Alertmanager.
fn write_prometheus_metrics(
    path: &std::path::Path,
    sweeps: u64,
    dismissals: u64,
    blocks: u64,
    suspicious: u64,
    scareware: u64,
) -> Result<(), String> {
    let content = format!(
        "# HELP muten_sweeps_total Total overlay-sweep iterations completed.\n\
         # TYPE muten_sweeps_total counter\n\
         muten_sweeps_total {sweeps}\n\
         # HELP muten_dismissals_total Total windows dismissed (Block decision).\n\
         # TYPE muten_dismissals_total counter\n\
         muten_dismissals_total {dismissals}\n\
         # HELP muten_blocks_total Total overlay_blocked audit events emitted.\n\
         # TYPE muten_blocks_total counter\n\
         muten_blocks_total {blocks}\n\
         # HELP muten_suspicious_total Total overlay_suspicious audit events emitted.\n\
         # TYPE muten_suspicious_total counter\n\
         muten_suspicious_total {suspicious}\n\
         # HELP muten_scareware_total Total scareware_detected audit events emitted.\n\
         # TYPE muten_scareware_total counter\n\
         muten_scareware_total {scareware}\n"
    );
    std::fs::write(path, content).map_err(|e| format!("writing metrics {}: {e}", path.display()))
}

fn cmd_monitor(
    windows: &str,
    rules: Option<&std::path::Path>,
    sweeps: u64,
    audit_log: Option<&std::path::Path>,
    json: bool,
    metrics: Option<&std::path::Path>,
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
        ..RunConfig::default()
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
                    sanitize_for_display(&ev.window_id),
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

    // Prometheus textfile metrics (L4): count event kinds from the in-memory
    // sink (already populated) or by re-reading the audit log line-by-line.
    if let Some(metrics_path) = metrics {
        let (blocks, suspicious_count, scareware_count) = count_audit_kinds(audit_log)?;
        write_prometheus_metrics(
            metrics_path,
            sweeps,
            total,
            blocks,
            suspicious_count,
            scareware_count,
        )?;
        if !json {
            eprintln!("metrics: {}", metrics_path.display());
        }
    }
    Ok(ExitCode::from(0))
}

/// Count overlay_blocked / overlay_suspicious / scareware_detected events
/// from the audit log. When no log path is provided returns (0,0,0).
fn count_audit_kinds(audit_log: Option<&std::path::Path>) -> Result<(u64, u64, u64), String> {
    let Some(path) = audit_log else {
        return Ok((0, 0, 0));
    };
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading log: {e}"))?;
    let (mut blocks, mut suspicious, mut scareware) = (0u64, 0u64, 0u64);
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        match v["kind"].as_str() {
            Some("overlay_blocked") => blocks += 1,
            Some("overlay_suspicious") => suspicious += 1,
            Some("scareware_detected") => scareware += 1,
            _ => {}
        }
    }
    Ok((blocks, suspicious, scareware))
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
