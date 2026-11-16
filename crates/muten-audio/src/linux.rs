//! Linux audio backend: the "hands" for Linux machines, behind the
//! same [`AudioBackend`] trait the Windows PowerShell helper
//! implements, so policy, [`crate::decide`], grants and the audit log
//! behave identically on both platforms.
//!
//! All OS contact is delegated to the desktop's own command-line
//! tools — this crate gains no audio dependency and keeps
//! `#![forbid(unsafe_code)]`:
//!
//! - `wpctl` (PipeWire / WirePlumber) is preferred:
//!   `wpctl get-volume @DEFAULT_AUDIO_SINK@` reports
//!   `Volume: 0.42` or `Volume: 0.42 [MUTED]`, and
//!   `wpctl set-mute @DEFAULT_AUDIO_SINK@ 1|0` sets the mute.
//! - `pactl` (PulseAudio) is the fallback:
//!   `pactl get-sink-mute @DEFAULT_SINK@` reports `Mute: yes|no`,
//!   `pactl get-sink-volume @DEFAULT_SINK@` reports per-channel
//!   percentages, and `pactl set-sink-mute @DEFAULT_SINK@ 1|0` sets
//!   the mute.
//!
//! Scope matches the Windows helper: the **default playback device
//! only** (`@DEFAULT_AUDIO_SINK@` / `@DEFAULT_SINK@`).
//!
//! If neither tool is usable, [`LinuxBackend::new`] fails with an
//! error naming both tools and why each failed; the CLI prints that
//! reason and exits before any enforcement starts — the agent stops
//! loudly and changes nothing, never silently.
//!
//! Command execution goes through the [`CommandRunner`] trait so the
//! whole backend — tool selection, output parsing, the mute command
//! sequence — is unit-tested against a scripted fake machine, with
//! no audio device involved.

use std::process::Command;

use crate::agent::AudioBackend;
use crate::decide::Observed;
use crate::{Error, Result};

/// The captured result of one external command invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Whether the command exited with status 0.
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Runs external commands on behalf of the Linux backend.
/// [`SystemRunner`] is the production implementation; tests use a
/// scripted fake.
pub trait CommandRunner {
    /// Run `program` with `args`. An `Err` means the command could
    /// not be launched at all (e.g. the tool is not installed); a
    /// command that ran and failed returns `Ok` with
    /// `success == false`.
    fn run(&mut self, program: &str, args: &[&str]) -> Result<CommandOutput>;
}

/// Production [`CommandRunner`]: a thin wrapper over
/// [`std::process::Command`].
#[derive(Debug, Default)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<CommandOutput> {
        let out = Command::new(program)
            .args(args)
            .output()
            .map_err(|e| Error::Backend(format!("failed to launch {program}: {e}")))?;
        Ok(CommandOutput {
            success: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        })
    }
}

/// A Linux audio tool the backend can drive, in preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxTool {
    /// `wpctl` — PipeWire / WirePlumber.
    Wpctl,
    /// `pactl` — PulseAudio.
    Pactl,
}

impl LinuxTool {
    /// The executable name.
    pub fn program(self) -> &'static str {
        match self {
            LinuxTool::Wpctl => "wpctl",
            LinuxTool::Pactl => "pactl",
        }
    }

    /// Human-readable name for messages and logs.
    pub fn describe(self) -> &'static str {
        match self {
            LinuxTool::Wpctl => "wpctl (PipeWire/WirePlumber)",
            LinuxTool::Pactl => "pactl (PulseAudio)",
        }
    }

    /// The state query used both as the availability probe and (for
    /// wpctl) as the state read itself.
    fn probe_args(self) -> &'static [&'static str] {
        match self {
            LinuxTool::Wpctl => &["get-volume", "@DEFAULT_AUDIO_SINK@"],
            LinuxTool::Pactl => &["get-sink-mute", "@DEFAULT_SINK@"],
        }
    }
}

/// Try one tool: run its state query and require a clean exit.
fn probe(runner: &mut dyn CommandRunner, tool: LinuxTool) -> std::result::Result<(), String> {
    match runner.run(tool.program(), tool.probe_args()) {
        Ok(out) if out.success => Ok(()),
        Ok(out) => Err(format!(
            "state query failed: {}",
            if out.stderr.is_empty() {
                "exit status non-zero".to_string()
            } else {
                out.stderr.clone()
            }
        )),
        // Unwrap the Backend variant so the combined message does
        // not repeat its "audio backend error:" prefix per tool.
        Err(Error::Backend(msg)) => Err(msg),
        Err(e) => Err(e.to_string()),
    }
}

/// Pick the tool to drive: `wpctl` first, then `pactl`. When neither
/// is usable the error names both tools and the reason each failed,
/// so the operator knows exactly what to install or fix.
pub fn detect_tool(runner: &mut dyn CommandRunner) -> Result<LinuxTool> {
    let mut failures: Vec<String> = Vec::new();
    for tool in [LinuxTool::Wpctl, LinuxTool::Pactl] {
        match probe(runner, tool) {
            Ok(()) => return Ok(tool),
            Err(reason) => failures.push(format!("{} — {reason}", tool.describe())),
        }
    }
    Err(Error::Backend(format!(
        "no usable Linux audio tool found ({}); install PipeWire/WirePlumber \
         or PulseAudio, or run inside a desktop session where one of them \
         is available — the agent stops here and changes nothing",
        failures.join("; ")
    )))
}

/// Parse `wpctl get-volume` output: `Volume: 0.42` or
/// `Volume: 0.42 [MUTED]`.
pub fn parse_wpctl_state(text: &str) -> Result<Observed> {
    let err = || Error::Backend(format!("unparseable wpctl volume output {text:?}"));
    let rest = text.trim().strip_prefix("Volume:").ok_or_else(err)?;
    let mut tokens = rest.split_whitespace();
    let fraction: f64 = tokens.next().ok_or_else(err)?.parse().map_err(|_| err())?;
    let muted = tokens.any(|t| t == "[MUTED]");
    Ok(Observed {
        muted,
        volume_percent: Some((fraction.clamp(0.0, 1.0) * 100.0).round() as u8),
    })
}

/// Parse `pactl get-sink-mute` output: `Mute: yes` or `Mute: no`.
pub fn parse_pactl_mute(text: &str) -> Result<bool> {
    let err = || Error::Backend(format!("unparseable pactl mute output {text:?}"));
    match text.trim().strip_prefix("Mute:").ok_or_else(err)?.trim() {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err(err()),
    }
}

/// Parse the first channel percentage out of `pactl get-sink-volume`
/// output (`Volume: front-left: 27525 /  42% / -22.61 dB, …`).
/// Informational only — muting is the enforcement — so an output
/// without a percentage yields `None`, not an error.
pub fn parse_pactl_volume(text: &str) -> Option<u8> {
    let bytes = text.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b != b'%' {
            continue;
        }
        let mut start = i;
        while start > 0 && bytes[start - 1].is_ascii_digit() {
            start -= 1;
        }
        if start == i {
            continue;
        }
        if let Ok(v) = text[start..i].parse::<u32>() {
            return Some(v.min(100) as u8);
        }
    }
    None
}

/// [`AudioBackend`] for Linux, driving `wpctl` or `pactl` through a
/// [`CommandRunner`].
pub struct LinuxBackend<R: CommandRunner = SystemRunner> {
    tool: LinuxTool,
    runner: R,
}

impl LinuxBackend<SystemRunner> {
    /// Detect the machine's audio tool and build the backend.
    /// Fails — with the reason, naming both tools — when neither
    /// `wpctl` nor `pactl` is usable; the caller stops there.
    pub fn new() -> Result<LinuxBackend<SystemRunner>> {
        LinuxBackend::with_runner(SystemRunner)
    }
}

impl<R: CommandRunner> LinuxBackend<R> {
    /// Build the backend over a specific runner, detecting the tool
    /// by probing it. Used by tests with a scripted fake machine.
    pub fn with_runner(mut runner: R) -> Result<LinuxBackend<R>> {
        let tool = detect_tool(&mut runner)?;
        Ok(LinuxBackend { tool, runner })
    }

    /// The tool this backend drives.
    pub fn tool(&self) -> LinuxTool {
        self.tool
    }

    /// Run one command for this backend's tool and require success;
    /// failures carry the tool's stderr so the audit log (via the
    /// watchdog's helper-error record) shows what actually happened.
    fn run_checked(&mut self, args: &[&str]) -> Result<CommandOutput> {
        let out = self.runner.run(self.tool.program(), args)?;
        if !out.success {
            return Err(Error::Backend(format!(
                "{} {} failed: {}",
                self.tool.program(),
                args.join(" "),
                if out.stderr.is_empty() {
                    "exit status non-zero".to_string()
                } else {
                    out.stderr.clone()
                }
            )));
        }
        Ok(out)
    }
}

impl<R: CommandRunner> AudioBackend for LinuxBackend<R> {
    fn get_state(&mut self) -> Result<Observed> {
        match self.tool {
            LinuxTool::Wpctl => {
                let out = self.run_checked(&["get-volume", "@DEFAULT_AUDIO_SINK@"])?;
                parse_wpctl_state(&out.stdout)
            }
            LinuxTool::Pactl => {
                let mute_out = self.run_checked(&["get-sink-mute", "@DEFAULT_SINK@"])?;
                let muted = parse_pactl_mute(&mute_out.stdout)?;
                // Volume is informational; a failed volume query
                // must not fail the poll, only leave the field empty.
                let volume_percent = self
                    .runner
                    .run("pactl", &["get-sink-volume", "@DEFAULT_SINK@"])
                    .ok()
                    .filter(|out| out.success)
                    .and_then(|out| parse_pactl_volume(&out.stdout));
                Ok(Observed {
                    muted,
                    volume_percent,
                })
            }
        }
    }

    fn set_mute(&mut self, mute: bool) -> Result<()> {
        let value = if mute { "1" } else { "0" };
        match self.tool {
            LinuxTool::Wpctl => {
                self.run_checked(&["set-mute", "@DEFAULT_AUDIO_SINK@", value])?;
            }
            LinuxTool::Pactl => {
                self.run_checked(&["set-sink-mute", "@DEFAULT_SINK@", value])?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{Watch, WatchPaths};
    use crate::audit::verify_chain;
    use crate::decide::Decision;
    use crate::grant::Grant;
    use crate::policy::Policy;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ToolState {
        /// Not installed: launching fails.
        Missing,
        /// Installed but every command exits non-zero.
        Broken,
        /// Installed and behaving like the real tool.
        Working,
    }

    /// A scripted Linux machine: per-tool availability plus a single
    /// default sink whose mute state the tools report and change,
    /// exactly as the real `wpctl`/`pactl` would observe each other.
    struct FakeMachine {
        wpctl: ToolState,
        pactl: ToolState,
        muted: bool,
        volume_percent: u8,
        calls: Vec<String>,
    }

    impl FakeMachine {
        fn new(wpctl: ToolState, pactl: ToolState) -> FakeMachine {
            FakeMachine {
                wpctl,
                pactl,
                muted: false,
                volume_percent: 55,
                calls: Vec::new(),
            }
        }
    }

    impl CommandRunner for FakeMachine {
        fn run(&mut self, program: &str, args: &[&str]) -> Result<CommandOutput> {
            self.calls.push(format!("{program} {}", args.join(" ")));
            let state = match program {
                "wpctl" => self.wpctl,
                "pactl" => self.pactl,
                other => {
                    return Err(Error::Backend(format!(
                        "failed to launch {other}: No such file or directory (os error 2)"
                    )))
                }
            };
            match state {
                ToolState::Missing => Err(Error::Backend(format!(
                    "failed to launch {program}: No such file or directory (os error 2)"
                ))),
                ToolState::Broken => Ok(CommandOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: "fake tool failure".to_string(),
                }),
                ToolState::Working => Ok(self.serve(program, args)),
            }
        }
    }

    impl FakeMachine {
        fn serve(&mut self, program: &str, args: &[&str]) -> CommandOutput {
            let ok = |stdout: String| CommandOutput {
                success: true,
                stdout,
                stderr: String::new(),
            };
            let fail = |stderr: &str| CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: stderr.to_string(),
            };
            match (program, args) {
                ("wpctl", ["get-volume", "@DEFAULT_AUDIO_SINK@"]) => ok(format!(
                    "Volume: {:.2}{}",
                    f64::from(self.volume_percent) / 100.0,
                    if self.muted { " [MUTED]" } else { "" }
                )),
                ("wpctl", ["set-mute", "@DEFAULT_AUDIO_SINK@", v]) => {
                    self.muted = *v == "1";
                    ok(String::new())
                }
                ("pactl", ["get-sink-mute", "@DEFAULT_SINK@"]) => {
                    ok(if self.muted { "Mute: yes" } else { "Mute: no" }.to_string())
                }
                ("pactl", ["get-sink-volume", "@DEFAULT_SINK@"]) => ok(format!(
                    "Volume: front-left: 36045 /  {}% / -15.57 dB,   \
                     front-right: 36045 /  {}% / -15.57 dB",
                    self.volume_percent, self.volume_percent
                )),
                ("pactl", ["set-sink-mute", "@DEFAULT_SINK@", v]) => {
                    self.muted = *v == "1";
                    ok(String::new())
                }
                _ => fail("unknown fake command"),
            }
        }
    }

    // ---- parsers ----

    #[test]
    fn wpctl_state_parses_volume_and_mute() {
        let o = parse_wpctl_state("Volume: 0.42").unwrap();
        assert!(!o.muted);
        assert_eq!(o.volume_percent, Some(42));

        let o = parse_wpctl_state("Volume: 0.42 [MUTED]").unwrap();
        assert!(o.muted);
        assert_eq!(o.volume_percent, Some(42));

        let o = parse_wpctl_state("Volume: 1.00 [MUTED]").unwrap();
        assert_eq!(o.volume_percent, Some(100));
    }

    #[test]
    fn wpctl_state_rejects_garbage() {
        assert!(parse_wpctl_state("").is_err());
        assert!(parse_wpctl_state("Volume: loud").is_err());
        assert!(parse_wpctl_state("Muted: yes").is_err());
    }

    #[test]
    fn pactl_mute_parses_yes_and_no() {
        assert!(parse_pactl_mute("Mute: yes").unwrap());
        assert!(!parse_pactl_mute("Mute: no").unwrap());
        assert!(parse_pactl_mute("Mute: maybe").is_err());
        assert!(parse_pactl_mute("").is_err());
    }

    #[test]
    fn pactl_volume_takes_the_first_percentage() {
        let text = "Volume: front-left: 27525 /  42% / -22.61 dB,   \
                    front-right: 27525 /  42% / -22.61 dB\n\tbalance 0.00";
        assert_eq!(parse_pactl_volume(text), Some(42));
        assert_eq!(parse_pactl_volume("Volume: 100%"), Some(100));
        assert_eq!(parse_pactl_volume("no numbers here"), None);
    }

    // ---- tool selection ----

    #[test]
    fn detect_prefers_wpctl_when_both_work() {
        let mut machine = FakeMachine::new(ToolState::Working, ToolState::Working);
        assert_eq!(detect_tool(&mut machine).unwrap(), LinuxTool::Wpctl);
    }

    #[test]
    fn detect_falls_back_to_pactl_when_wpctl_is_missing() {
        let mut machine = FakeMachine::new(ToolState::Missing, ToolState::Working);
        assert_eq!(detect_tool(&mut machine).unwrap(), LinuxTool::Pactl);
    }

    #[test]
    fn detect_falls_back_to_pactl_when_wpctl_is_broken() {
        let mut machine = FakeMachine::new(ToolState::Broken, ToolState::Working);
        assert_eq!(detect_tool(&mut machine).unwrap(), LinuxTool::Pactl);
    }

    #[test]
    fn detect_without_any_tool_errors_and_names_both() {
        let mut machine = FakeMachine::new(ToolState::Missing, ToolState::Broken);
        let err = detect_tool(&mut machine).unwrap_err().to_string();
        assert!(err.contains("wpctl"), "error: {err}");
        assert!(err.contains("pactl"), "error: {err}");
        assert!(err.contains("changes nothing"), "error: {err}");
        // Both tools were actually tried, in preference order.
        assert!(
            machine.calls[0].starts_with("wpctl"),
            "calls: {:?}",
            machine.calls
        );
        assert!(
            machine.calls[1].starts_with("pactl"),
            "calls: {:?}",
            machine.calls
        );
    }

    // ---- backend operations ----

    #[test]
    fn wpctl_backend_reads_and_sets_mute() {
        let mut backend =
            LinuxBackend::with_runner(FakeMachine::new(ToolState::Working, ToolState::Missing))
                .unwrap();
        assert_eq!(backend.tool(), LinuxTool::Wpctl);

        let state = backend.get_state().unwrap();
        assert!(!state.muted);
        assert_eq!(state.volume_percent, Some(55));

        backend.set_mute(true).unwrap();
        assert!(backend.get_state().unwrap().muted);
        backend.set_mute(false).unwrap();
        assert!(!backend.get_state().unwrap().muted);

        assert!(backend
            .runner
            .calls
            .iter()
            .any(|c| c == "wpctl set-mute @DEFAULT_AUDIO_SINK@ 1"));
        assert!(backend
            .runner
            .calls
            .iter()
            .any(|c| c == "wpctl set-mute @DEFAULT_AUDIO_SINK@ 0"));
    }

    #[test]
    fn pactl_backend_reads_and_sets_mute() {
        let mut backend =
            LinuxBackend::with_runner(FakeMachine::new(ToolState::Missing, ToolState::Working))
                .unwrap();
        assert_eq!(backend.tool(), LinuxTool::Pactl);

        let state = backend.get_state().unwrap();
        assert!(!state.muted);
        assert_eq!(state.volume_percent, Some(55));

        backend.set_mute(true).unwrap();
        let state = backend.get_state().unwrap();
        assert!(state.muted);
        assert!(backend
            .runner
            .calls
            .iter()
            .any(|c| c == "pactl set-sink-mute @DEFAULT_SINK@ 1"));
    }

    #[test]
    fn set_mute_failure_is_an_error_with_the_tools_stderr() {
        // wpctl works for the probe but the machine breaks before
        // set-mute runs.
        let mut backend =
            LinuxBackend::with_runner(FakeMachine::new(ToolState::Working, ToolState::Missing))
                .unwrap();
        backend.runner.wpctl = ToolState::Broken;
        let err = backend.set_mute(true).unwrap_err().to_string();
        assert!(err.contains("set-mute"), "error: {err}");
        assert!(err.contains("fake tool failure"), "error: {err}");
    }

    // ---- the watchdog over the Linux backend ----

    struct Rig {
        _dir: tempfile::TempDir,
        paths: WatchPaths,
    }

    fn rig_with(machine: FakeMachine) -> (Rig, Watch<LinuxBackend<FakeMachine>>) {
        let dir = tempfile::tempdir().unwrap();
        let paths = WatchPaths {
            policy: dir.path().join("policy.json"),
            grant: dir.path().join("grant.json"),
            log: dir.path().join("audit.log"),
        };
        let backend = LinuxBackend::with_runner(machine).unwrap();
        let watch = Watch::new(Policy::starter(), paths.clone(), backend).unwrap();
        (Rig { _dir: dir, paths }, watch)
    }

    // 2026-11-16 10:00 JST (Monday) = 01:00 UTC.
    const T0: i64 = 1_794_790_800;

    #[test]
    fn linux_watch_enforces_the_same_policy_end_to_end() {
        let machine = FakeMachine::new(ToolState::Working, ToolState::Missing);
        let (rig, mut w) = rig_with(machine);

        // Startup poll: the unmuted sink is muted via wpctl.
        assert_eq!(w.step(T0).unwrap(), Decision::MuteNow);
        assert!(w.backend().runner.muted);
        assert_eq!(w.step(T0 + 1).unwrap(), Decision::LeaveMuted);

        // A raise behind the agent's back is re-muted on the next poll.
        w.backend_mut().runner.muted = false;
        assert_eq!(w.step(T0 + 5).unwrap(), Decision::MuteNow);
        assert!(w.backend().runner.muted);

        // A PIN grant (written by the platform-independent CLI)
        // unmutes, and its expiry re-mutes — same as on Windows.
        Grant::new(T0 + 10, 30).save(&rig.paths.grant).unwrap();
        assert_eq!(
            w.step(T0 + 10).unwrap(),
            Decision::UnmuteForGrant {
                remaining_secs: 30 * 60
            }
        );
        assert!(!w.backend().runner.muted);
        assert_eq!(w.step(T0 + 10 + 30 * 60).unwrap(), Decision::MuteNow);
        assert!(w.backend().runner.muted);

        // The audit log is the same hash-chained format, intact.
        let text = std::fs::read_to_string(&rig.paths.log).unwrap();
        let status = verify_chain(&text).unwrap();
        assert!(status.events >= 5);
        assert!(text.contains("volume_raised_detected"));
        assert!(text.contains("unmuted_for_grant"));
        assert!(text.contains("grant_expired"));
    }

    #[test]
    fn linux_watch_on_a_pactl_machine_mutes_at_startup() {
        let machine = FakeMachine::new(ToolState::Missing, ToolState::Working);
        let (_rig, mut w) = rig_with(machine);
        assert_eq!(w.backend().tool(), LinuxTool::Pactl);
        assert_eq!(w.step(T0).unwrap(), Decision::MuteNow);
        assert!(w.backend().runner.muted);
        assert!(w
            .backend()
            .runner
            .calls
            .iter()
            .any(|c| c == "pactl set-sink-mute @DEFAULT_SINK@ 1"));
    }
}
