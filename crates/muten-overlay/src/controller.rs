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
    Enumerate(String),
    Dismiss(String),
    Unsupported,
}

impl std::fmt::Display for ControllerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enumerate(s) => write!(f, "enumerate failed: {s}"),
            Self::Dismiss(s) => write!(f, "dismiss failed: {s}"),
            Self::Unsupported => write!(f, "controller unsupported on this host"),
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
    pub id: WindowId,
    pub window: OverlayWindow,
}

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
pub struct SubprocessController {
    helper: String,
}

impl SubprocessController {
    /// `helper` is the path/name of the platform helper. Override via
    /// `$MUTEN_OVERLAY_HELPER` for testing or non-PATH installs.
    #[must_use]
    pub fn new(helper: impl Into<String>) -> Self {
        let h = std::env::var("MUTEN_OVERLAY_HELPER").unwrap_or_else(|_| helper.into());
        Self { helper: h }
    }

    fn run(&self, args: &[&str]) -> Result<std::process::Output, ControllerError> {
        std::process::Command::new(&self.helper)
            .args(args)
            .output()
            .map_err(|e| ControllerError::Enumerate(e.to_string()))
    }
}

impl OverlayController for SubprocessController {
    fn name(&self) -> &'static str {
        "subprocess"
    }

    fn available(&self) -> bool {
        // The helper must run and answer `--probe` with exit 0. We
        // don't trust PATH alone since a same-named non-helper could
        // shadow it.
        std::process::Command::new(&self.helper)
            .arg("--probe")
            .output()
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

    fn win(id: &str, title: &str) -> EnumeratedWindow {
        EnumeratedWindow {
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
            ControllerError::Unsupported.to_string(),
            "controller unsupported on this host"
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
        let json = r#"[{"id":"w1","window":{"title":"your computer is infected","url":"http://scam.example/x","coverage_percent":100,"topmost":true,"has_close_button":false,"blocks_input":true,"origin":"unsolicited","age_ms":200}}]"#;
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
        let dir = tempfile::tempdir().unwrap();
        let helper = fake_helper(dir.path());
        let c = SubprocessController::new(helper);
        let windows = c.enumerate().unwrap();
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].id, "w1");
        assert_eq!(windows[0].window.title, "your computer is infected");
        assert!(windows[0].window.blocks_input);
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_dismiss_maps_exit_codes() {
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
}
