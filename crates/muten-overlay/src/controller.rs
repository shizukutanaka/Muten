//! OS abstraction for observing and dismissing overlay windows.
//!
//! This is the overlay-side analogue of `muten-audio`'s `AudioBackend`
//! trait: the pure classifier ([`crate::classify`], [`crate::assess`])
//! decides *what* to do; an [`OverlayController`] is *how* — it
//! enumerates the windows currently on screen and, when policy says
//! `Block`, dismisses one. The real implementations (a Win32 / macOS /
//! X11-Wayland enumerator+dismisser) live behind this trait so the
//! domain logic stays testable without a desktop, exactly like the
//! audio backends.
//!
//! ## Default posture: dry-run
//!
//! [`NullController`] enumerates nothing and "dismisses" by recording
//! the request in memory. The daemon uses it on CI and in
//! `observe`-style rollouts; it lets the whole detect→decide→act loop
//! run and be audited without touching a single real window.
//!
//! ## Why dismissing is gated, not automatic (CLAUDE.md I9)
//!
//! Dismissing a window is a destructive-ish action (the user loses
//! whatever was on screen). muten only calls [`OverlayController::dismiss`]
//! for a `Block` verdict — a confirmed blocklist hit or an
//! unmistakable heuristic score — never for `Suspicious`. Everything
//! else is audited and left alone. The controller is also free to
//! implement `dismiss` as "log and notify" rather than "force-close"
//! where forcibly closing a window would be too aggressive for the
//! deployment.

use crate::OverlayWindow;
use serde::{Deserialize, Serialize};

/// Errors a controller can surface. Kept small; the daemon logs these
/// as `BackendError`-style audit events and retries next tick rather
/// than crashing — a transient window-manager hiccup is not fatal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ControllerError {
    /// The helper's `enumerate` verb failed; payload is the error description.
    Enumerate(String),
    /// The helper's `dismiss` verb failed; payload is the error description.
    Dismiss(String),
    /// This controller is not supported on the current host.
    Unsupported,
    /// The helper process did not exit within the configured timeout and
    /// was killed. Distinct from `Enumerate`/`Dismiss` because a hang (a
    /// broken window-manager IPC call, a stuck modal dialog blocking
    /// AppleScript, a frozen COM call) is a different failure mode than a
    /// clean non-zero exit or unparseable output, and an operator
    /// triaging the audit log benefits from telling them apart.
    Timeout(String),
}

impl std::fmt::Display for ControllerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enumerate(s) => write!(f, "enumerate failed: {s}"),
            Self::Dismiss(s) => write!(f, "dismiss failed: {s}"),
            Self::Unsupported => write!(f, "controller unsupported on this host"),
            Self::Timeout(s) => write!(f, "helper timed out: {s}"),
        }
    }
}

impl std::error::Error for ControllerError {}

/// A stable handle the controller uses to refer to one window across
/// calls. Opaque to the domain layer; the OS impl chooses the encoding
/// (HWND, CGWindowID, X11 window id, …).
pub type WindowId = String;

/// One enumerated window plus the controller's handle for it, so the
/// daemon can pass the handle back to [`OverlayController::dismiss`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumeratedWindow {
    /// The controller's opaque, stable handle for this window.
    pub id: WindowId,
    /// Owning process / application name, if the helper can attribute one
    /// cheaply (best-effort; `None` = unknown). Matched against blocklist
    /// `process:` rules via `Ruleset::match_process`'s squash semantics
    /// (case-, space-, and separator-insensitive substring), so a Wayland
    /// app-id like `org.mozilla.firefox` still matches a rule written as
    /// `firefox`. `#[serde(default)]` keeps helpers that predate this
    /// field (and omit it) parsing unchanged.
    #[serde(default)]
    pub process: Option<String>,
    /// The observed window metadata.
    pub window: OverlayWindow,
}

/// Abstracts over OS window-management backends (Win32, macOS, X11/Wayland).
/// Both `enumerate` and `dismiss` are allowed to fail transiently — the
/// caller logs the error and retries next sweep rather than aborting.
pub trait OverlayController: Send + Sync {
    /// Human-readable name for diagnostics, e.g. "null", "win32".
    fn name(&self) -> &'static str;

    /// Is this controller usable on the current host?
    fn available(&self) -> bool;

    /// Snapshot the windows currently on screen.
    fn enumerate(&self) -> Result<Vec<EnumeratedWindow>, ControllerError>;

    /// Dismiss the window with the given id. Implementations may
    /// force-close, minimize, or merely log+notify depending on how
    /// aggressive the deployment wants to be. Returns Ok(true) if the
    /// window was actually acted upon, Ok(false) if it was already
    /// gone, Err on failure.
    fn dismiss(&self, id: &WindowId) -> Result<bool, ControllerError>;
}

/// Dry-run controller: sees nothing, and "dismisses" by recording the
/// request. The default for CI, tests, and observe-mode rollouts.
#[derive(Debug, Default)]
pub struct NullController {
    /// Windows to hand back from `enumerate`, for tests.
    seed: Vec<EnumeratedWindow>,
    /// Dismiss requests recorded here, newest last.
    dismissed: std::sync::Mutex<Vec<WindowId>>,
}

impl NullController {
    /// Create an empty dry-run controller (enumerates nothing).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a controller that will return `windows` from `enumerate`.
    #[must_use]
    pub fn with_windows(windows: Vec<EnumeratedWindow>) -> Self {
        Self {
            seed: windows,
            dismissed: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Ids that `dismiss` was called with, in order.
    #[must_use]
    pub fn dismissed(&self) -> Vec<WindowId> {
        self.dismissed.lock().unwrap().clone()
    }
}

impl OverlayController for NullController {
    fn name(&self) -> &'static str {
        "null"
    }
    fn available(&self) -> bool {
        true
    }
    fn enumerate(&self) -> Result<Vec<EnumeratedWindow>, ControllerError> {
        Ok(self.seed.clone())
    }
    fn dismiss(&self, id: &WindowId) -> Result<bool, ControllerError> {
        self.dismissed.lock().unwrap().push(id.clone());
        Ok(true)
    }
}

/// Real-host controller that shells out to a per-OS helper command,
/// the same pattern as `muten-audio`'s pactl backend.
///
/// The helper is a small platform-specific program (a PowerShell
/// script on Windows, a `swift`/`osascript` helper on macOS, a
/// `wmctrl`/`xdotool` wrapper on X11) that muten ships in
/// `installer/`. The protocol is deliberately tiny so the helper can
/// be audited at a glance and reimplemented per platform:
///
/// - **enumerate**: muten runs `<helper> enumerate`. The helper prints
///   a JSON array of `{id, window}` objects (one `EnumeratedWindow`
///   each) to stdout and exits 0.
/// - **dismiss**: muten runs `<helper> dismiss <id>`. Exit 0 = acted,
///   exit 2 = window already gone, any other = failure.
///
/// muten itself never links a window-manager API, so this crate keeps
/// `#![forbid(unsafe_code)]`; all the `unsafe` FFI lives in the
/// separate, swappable helper. The cost is one process spawn per
/// sweep, well within the daemon's tick budget (same trade-off the
/// audio backend documents).
///
/// Every call is bounded by [`Self::timeout`] (default 5s): a helper that
/// hangs — a broken window-manager IPC call, a stuck modal blocking
/// AppleScript, a frozen COM call — is killed rather than blocking the
/// daemon loop forever. Without this, a single hung helper invocation
/// would freeze not just that sweep but the daemon's entire graceful-stop
/// mechanism, since the stop-flag is only checked *between* sweeps.
pub struct SubprocessController {
    helper: String,
    timeout: std::time::Duration,
}

/// Default per-call timeout: generous for a single `wmctrl`/`osascript`/
/// PowerShell invocation (which normally completes in well under a
/// second) while still bounding a genuine hang to a few seconds rather
/// than forever.
const DEFAULT_HELPER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How often the timeout-bounded waiter polls the child for exit. Short
/// enough that the timeout deadline is honored promptly, long enough to
/// avoid busy-spinning the CPU while waiting on a normal sub-second call.
const HELPER_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

impl SubprocessController {
    /// `helper` is the path/name of the platform helper. Override via
    /// `$MUTEN_OVERLAY_HELPER` for testing or non-PATH installs. Uses
    /// [`DEFAULT_HELPER_TIMEOUT`]; call [`Self::with_timeout`] to override.
    #[must_use]
    pub fn new(helper: impl Into<String>) -> Self {
        Self::with_timeout(helper, DEFAULT_HELPER_TIMEOUT)
    }

    /// Like [`Self::new`], with an explicit per-call timeout.
    #[must_use]
    pub fn with_timeout(helper: impl Into<String>, timeout: std::time::Duration) -> Self {
        let h = std::env::var("MUTEN_OVERLAY_HELPER").unwrap_or_else(|_| helper.into());
        Self { helper: h, timeout }
    }

    /// Run the helper with `args`, killing it and returning
    /// `ControllerError::Timeout` if it does not exit within `self.timeout`.
    ///
    /// Spawns (rather than using the simpler `Command::output()`) so the
    /// child can be polled and killed; stdout/stderr are drained on
    /// separate threads *while* polling, not after, so a helper that
    /// writes more than the OS pipe buffer before exiting can't deadlock
    /// this call (it would otherwise block on `write()` waiting for us to
    /// read, while we block waiting for it to exit).
    fn run(&self, args: &[&str]) -> Result<std::process::Output, ControllerError> {
        let mut child = std::process::Command::new(&self.helper)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| ControllerError::Enumerate(e.to_string()))?;

        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        let drain = |mut pipe: Option<std::process::ChildStdout>| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                if let Some(p) = pipe.as_mut() {
                    use std::io::Read;
                    let _ = p.read_to_end(&mut buf);
                }
                buf
            })
        };
        let drain_err = |mut pipe: Option<std::process::ChildStderr>| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                if let Some(p) = pipe.as_mut() {
                    use std::io::Read;
                    let _ = p.read_to_end(&mut buf);
                }
                buf
            })
        };
        let stdout_handle = drain(stdout_pipe);
        let stderr_handle = drain_err(stderr_pipe);

        let start = std::time::Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if start.elapsed() >= self.timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(ControllerError::Timeout(format!(
                            "{:?} did not exit within {:?}",
                            self.helper, self.timeout
                        )));
                    }
                    std::thread::sleep(HELPER_POLL_INTERVAL);
                }
                Err(e) => return Err(ControllerError::Enumerate(e.to_string())),
            }
        };
        let stdout = stdout_handle.join().unwrap_or_default();
        let stderr = stderr_handle.join().unwrap_or_default();
        Ok(std::process::Output {
            status,
            stdout,
            stderr,
        })
    }
}

impl OverlayController for SubprocessController {
    fn name(&self) -> &'static str {
        "subprocess"
    }

    fn available(&self) -> bool {
        // The helper must run and answer `--probe` with exit 0 within the
        // timeout. We don't trust PATH alone since a same-named non-helper
        // could shadow it. Routed through the same timeout-bounded `run`
        // as enumerate/dismiss so a hung helper fails the startup probe
        // instead of hanging it.
        self.run(&["--probe"])
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn enumerate(&self) -> Result<Vec<EnumeratedWindow>, ControllerError> {
        let out = self.run(&["enumerate"])?;
        if !out.status.success() {
            return Err(ControllerError::Enumerate(
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        if text.trim().is_empty() {
            return Ok(Vec::new());
        }
        serde_json::from_str::<Vec<EnumeratedWindow>>(&text)
            .map_err(|e| ControllerError::Enumerate(format!("bad helper JSON: {e}")))
    }

    fn dismiss(&self, id: &WindowId) -> Result<bool, ControllerError> {
        let out = self.run(&["dismiss", id])?;
        match out.status.code() {
            Some(0) => Ok(true),  // acted
            Some(2) => Ok(false), // already gone
            _ => Err(ControllerError::Dismiss(
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Origin;

    // Serialize all SubprocessController tests within this binary.
    // The Linux kernel can return ETXTBSY when multiple threads concurrently
    // create + exec shell scripts, even in distinct temp directories (a kernel
    // inode-refcount quirk under high parallelism). Running them under one
    // mutex costs nothing in wall-clock time (each test is a single exec).
    #[cfg(unix)]
    static SUBPROCESS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn win(id: &str, title: &str) -> EnumeratedWindow {
        EnumeratedWindow {
            process: None,
            id: id.into(),
            window: OverlayWindow {
                title: title.into(),
                url: None,
                coverage_percent: 100,
                topmost: true,
                has_close_button: false,
                blocks_input: true,
                origin: Origin::Unsolicited,
                age_ms: 200,
            },
        }
    }

    #[test]
    fn null_controller_is_available_and_named() {
        let c = NullController::new();
        assert!(c.available());
        assert_eq!(c.name(), "null");
    }

    #[test]
    fn null_enumerate_returns_seed() {
        let c = NullController::with_windows(vec![win("1", "a"), win("2", "b")]);
        let got = c.enumerate().unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].id, "1");
    }

    #[test]
    fn null_dismiss_records_requests_in_order() {
        let c = NullController::new();
        assert!(c.dismiss(&"7".to_string()).unwrap());
        assert!(c.dismiss(&"9".to_string()).unwrap());
        assert_eq!(c.dismissed(), vec!["7".to_string(), "9".to_string()]);
    }

    #[test]
    fn empty_enumerate_by_default() {
        let c = NullController::new();
        assert!(c.enumerate().unwrap().is_empty());
    }

    #[test]
    fn controller_error_display() {
        assert_eq!(
            ControllerError::Enumerate("x".into()).to_string(),
            "enumerate failed: x"
        );
        assert_eq!(
            ControllerError::Dismiss("y".into()).to_string(),
            "dismiss failed: y"
        );
        assert_eq!(
            ControllerError::Unsupported.to_string(),
            "controller unsupported on this host"
        );
        assert_eq!(
            ControllerError::Timeout("z".into()).to_string(),
            "helper timed out: z"
        );
    }

    // ── SubprocessController (fake helper) ───────────────────────

    /// Write an executable fake helper script and return its path.
    /// The script answers --probe (exit 0), enumerate (prints JSON),
    /// and dismiss <id> (exit 0 for "win", exit 2 for "gone", exit 1
    /// otherwise) — exercising every branch of the protocol.
    #[cfg(unix)]
    fn fake_helper(dir: &std::path::Path) -> String {
        use std::io::Write;
        let path = dir.join("helper.sh");
        let json = r#"[{"id":"w1","process":"PC Protector Plus","window":{"title":"your computer is infected","url":"http://scam.example/x","coverage_percent":100,"topmost":true,"has_close_button":false,"blocks_input":true,"origin":"unsolicited","age_ms":200}}]"#;
        let script = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
             --probe) exit 0 ;;\n\
             enumerate) echo '{json}' ;;\n\
             dismiss) case \"$2\" in win) exit 0 ;; gone) exit 2 ;; *) echo 'boom' 1>&2; exit 1 ;; esac ;;\n\
             *) exit 1 ;;\n\
             esac\n"
        );
        {
            use std::os::unix::fs::PermissionsExt;
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(script.as_bytes()).unwrap();
            // fsync before chmod: guarantees the kernel sees a fully written,
            // closed inode before exec — prevents ETXTBSY under parallel tests.
            f.sync_all().unwrap();
            let mut perms = f.metadata().unwrap().permissions();
            perms.set_mode(0o755);
            // Close first, then chmod via path — file is closed before exec.
            drop(f);
            std::fs::set_permissions(&path, perms).unwrap();
        }
        path.to_string_lossy().into_owned()
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_available_when_helper_probes_ok() {
        let _guard = SUBPROCESS_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let helper = fake_helper(dir.path());
        let c = SubprocessController::new(helper);
        assert!(c.available());
        assert_eq!(c.name(), "subprocess");
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_unavailable_when_helper_missing() {
        let c = SubprocessController::new("/nonexistent/muten-helper-xyz");
        assert!(!c.available());
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_enumerate_parses_helper_json() {
        let _guard = SUBPROCESS_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let helper = fake_helper(dir.path());
        let c = SubprocessController::new(helper);
        let windows = c.enumerate().unwrap();
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].id, "w1");
        assert_eq!(windows[0].process.as_deref(), Some("PC Protector Plus"));
        assert_eq!(windows[0].window.title, "your computer is infected");
        assert!(windows[0].window.blocks_input);
    }

    /// Backwards compatibility: a helper that predates the `process` field
    /// (and therefore omits it) must keep parsing — the field is
    /// `#[serde(default)]`, so it simply comes back as `None`.
    #[test]
    fn enumerated_window_parses_without_process_field() {
        let old_format = r#"{"id":"w1","window":{"title":"t","coverage_percent":10,"topmost":false,"has_close_button":true,"blocks_input":false,"origin":"unknown","age_ms":0}}"#;
        let ew: EnumeratedWindow = serde_json::from_str(old_format)
            .expect("pre-process-field helper JSON must keep parsing");
        assert_eq!(ew.process, None);
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_dismiss_maps_exit_codes() {
        let _guard = SUBPROCESS_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let helper = fake_helper(dir.path());
        let c = SubprocessController::new(helper);
        // exit 0 → acted
        assert!(c.dismiss(&"win".to_string()).unwrap());
        // exit 2 → already gone
        assert!(!c.dismiss(&"gone".to_string()).unwrap());
        // exit 1 → error
        assert!(c.dismiss(&"other".to_string()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_enforce_end_to_end_dismisses_scam() {
        let _guard = SUBPROCESS_LOCK.lock().unwrap();
        use crate::{enforce, Decision, Ruleset};
        let dir = tempfile::tempdir().unwrap();
        let helper = fake_helper(dir.path());
        let c = SubprocessController::new(helper);
        // helper's window id is "w1" but dismiss only succeeds for "win";
        // use a host blocklist so the window classifies as Block, then
        // verify enforce attempts dismiss (helper returns exit 1 for w1
        // → dismissed=false, but the decision is still Block).
        let rules = Ruleset::from_lines(&["host: scam.example"]);
        let outcomes = enforce(&c, &rules).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].decision, Decision::Block);
        // w1 is not "win"/"gone" → helper exit 1 → dismiss errored →
        // folded to dismissed=false (sweep didn't abort).
        assert!(!outcomes[0].dismissed);
    }

    /// A helper that hangs forever on every verb — models a broken
    /// window-manager IPC call, a stuck modal blocking AppleScript, or a
    /// frozen COM call. Used to prove the timeout actually bounds the
    /// wait rather than blocking indefinitely.
    #[cfg(unix)]
    fn hanging_helper(dir: &std::path::Path) -> String {
        use std::io::Write;
        let path = dir.join("hang.sh");
        // `sleep infinity` isn't portable to all /bin/sh; a very long
        // fixed sleep behaves identically for this test's purposes (the
        // timeout will kill it long before it would ever complete).
        let script = "#!/bin/sh\nsleep 3600\n";
        {
            use std::os::unix::fs::PermissionsExt;
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(script.as_bytes()).unwrap();
            f.sync_all().unwrap();
            let mut perms = f.metadata().unwrap().permissions();
            perms.set_mode(0o755);
            drop(f);
            std::fs::set_permissions(&path, perms).unwrap();
        }
        path.to_string_lossy().into_owned()
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_available_returns_false_on_hung_helper_within_timeout() {
        let _guard = SUBPROCESS_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let helper = hanging_helper(dir.path());
        let c = SubprocessController::with_timeout(helper, std::time::Duration::from_millis(200));
        let start = std::time::Instant::now();
        assert!(
            !c.available(),
            "a hung --probe must be treated as unavailable, not block forever"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "available() must return promptly once the timeout elapses, took {:?}",
            start.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_enumerate_times_out_on_hung_helper() {
        let _guard = SUBPROCESS_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let helper = hanging_helper(dir.path());
        let c = SubprocessController::with_timeout(helper, std::time::Duration::from_millis(200));
        let start = std::time::Instant::now();
        let err = c.enumerate().expect_err("hung helper must error, not hang");
        assert!(
            matches!(err, ControllerError::Timeout(_)),
            "expected Timeout, got {err:?}"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "enumerate() must return promptly once the timeout elapses, took {:?}",
            start.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_dismiss_times_out_on_hung_helper() {
        let _guard = SUBPROCESS_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let helper = hanging_helper(dir.path());
        let c = SubprocessController::with_timeout(helper, std::time::Duration::from_millis(200));
        let err = c
            .dismiss(&"w1".to_string())
            .expect_err("hung helper must error, not hang");
        assert!(matches!(err, ControllerError::Timeout(_)));
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_default_timeout_does_not_affect_well_behaved_helper() {
        // A regression guard: adding the timeout mechanism must not slow
        // down or break a normal, fast-responding helper.
        let _guard = SUBPROCESS_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let helper = fake_helper(dir.path());
        let c = SubprocessController::new(helper);
        let start = std::time::Instant::now();
        assert!(c.available());
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "a fast helper must not be slowed down by the timeout machinery"
        );
    }
}
