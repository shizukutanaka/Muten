//! The resident watchdog: poll → decide → act → log.
//!
//! [`Watch::step`] performs exactly one poll and is the unit under
//! test; [`Watch::run`] is the thin loop around it (call `step`, sleep
//! `poll_interval_ms`, repeat). All OS contact goes through
//! [`AudioBackend`], so tests drive the full enforcement behaviour —
//! startup mute, re-mute after a volume raise, grant honoured, grant
//! expiry re-mute — against a fake backend.

use std::path::PathBuf;
use std::process::Command;

use crate::audit::{AuditLog, Event, EventKind};
use crate::decide::{decide, Decision, Observed};
use crate::grant::Grant;
use crate::policy::Policy;
use crate::time::local_from_unix;
use crate::{Error, Result};

/// OS audio operations. Implemented by [`HelperBackend`] in production
/// and by fakes in tests.
pub trait AudioBackend {
    /// Current state of the default playback endpoint.
    fn get_state(&mut self) -> Result<Observed>;
    /// Set the endpoint mute. `true` = muted.
    fn set_mute(&mut self, mute: bool) -> Result<()>;
}

/// Backend that delegates to the PowerShell helper script
/// (`agent/audio-helper.ps1`). Protocol:
///
/// ```text
/// powershell -NoProfile -ExecutionPolicy Bypass -File audio-helper.ps1 get
///     -> stdout: {"muted":true,"volume":0.42}   (volume is 0.0..=1.0)
/// powershell ... audio-helper.ps1 mute    (exit 0 on success)
/// powershell ... audio-helper.ps1 unmute  (exit 0 on success)
/// ```
pub struct HelperBackend {
    pub powershell: String,
    pub script: PathBuf,
}

impl HelperBackend {
    pub fn new(script: PathBuf) -> HelperBackend {
        HelperBackend {
            powershell: "powershell".to_string(),
            script,
        }
    }

    fn invoke(&mut self, action: &str) -> Result<String> {
        let out = Command::new(&self.powershell)
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                &self.script.to_string_lossy(),
                action,
            ])
            .output()
            .map_err(|e| Error::Backend(format!("failed to launch helper: {e}")))?;
        if !out.status.success() {
            return Err(Error::Backend(format!(
                "helper action {action:?} exited with {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

impl AudioBackend for HelperBackend {
    fn get_state(&mut self) -> Result<Observed> {
        let text = self.invoke("get")?;
        #[derive(serde::Deserialize)]
        struct HelperState {
            muted: bool,
            volume: Option<f64>,
        }
        let state: HelperState = serde_json::from_str(&text).map_err(|e| {
            Error::Backend(format!("helper returned unparseable state {text:?}: {e}"))
        })?;
        Ok(Observed {
            muted: state.muted,
            volume_percent: state
                .volume
                .map(|v| (v.clamp(0.0, 1.0) * 100.0).round() as u8),
        })
    }

    fn set_mute(&mut self, mute: bool) -> Result<()> {
        self.invoke(if mute { "mute" } else { "unmute" })?;
        Ok(())
    }
}

/// File locations the watchdog works with.
#[derive(Debug, Clone)]
pub struct WatchPaths {
    pub policy: PathBuf,
    pub grant: PathBuf,
    pub log: PathBuf,
}

/// The watchdog state machine.
pub struct Watch<B: AudioBackend> {
    policy: Policy,
    paths: WatchPaths,
    backend: B,
    log: AuditLog,
    /// Whether we have already recorded the current grant's expiry.
    expired_grant_seen: Option<i64>,
}

impl<B: AudioBackend> Watch<B> {
    pub fn new(policy: Policy, paths: WatchPaths, backend: B) -> Result<Watch<B>> {
        let log = AuditLog::open(&paths.log)?;
        Ok(Watch {
            policy,
            paths,
            backend,
            log,
            expired_grant_seen: None,
        })
    }

    fn record(&mut self, now_unix: i64, kind: EventKind, detail: serde_json::Value) {
        // A failed audit write must not kill enforcement, but it must
        // not be silent either: report it on stderr (the launcher
        // console) every time it happens.
        let event = Event {
            ts_unix: now_unix,
            kind,
            detail,
        };
        if let Err(e) = self.log.append(&event) {
            eprintln!("muten-audio: WARNING: audit log write failed: {e}");
        }
    }

    /// One poll: observe, decide, act, log transitions.
    pub fn step(&mut self, now_unix: i64) -> Result<Decision> {
        let grant = match Grant::load(&self.paths.grant) {
            Ok(g) => g,
            Err(e) => {
                // A corrupt grant file must never become a grant, and
                // must never pass silently either.
                self.record(
                    now_unix,
                    EventKind::HelperError,
                    serde_json::json!({"what": "grant_load", "error": e.to_string()}),
                );
                None
            }
        };

        let observed = match self.backend.get_state() {
            Ok(o) => o,
            Err(e) => {
                self.record(
                    now_unix,
                    EventKind::HelperError,
                    serde_json::json!({"what": "get_state", "error": e.to_string()}),
                );
                return Err(e);
            }
        };

        let local = local_from_unix(now_unix, self.policy.utc_offset_minutes);
        let decision = decide(&self.policy, local, observed, grant.as_ref(), now_unix);

        // Record an expired grant exactly once per grant.
        if let Some(g) = grant {
            if !g.is_active(now_unix)
                && now_unix >= g.granted_at_unix
                && self.expired_grant_seen != Some(g.granted_at_unix)
                && self.policy.is_enforced_at(local)
            {
                self.expired_grant_seen = Some(g.granted_at_unix);
                self.record(
                    now_unix,
                    EventKind::GrantExpired,
                    serde_json::json!({"granted_at_unix": g.granted_at_unix}),
                );
            }
        }

        match decision {
            Decision::MuteNow => {
                // A raise is logged before the re-mute so the audit
                // trail shows *why* the endpoint went quiet again.
                self.record(
                    now_unix,
                    EventKind::VolumeRaisedDetected,
                    serde_json::json!({"volume_percent": observed.volume_percent}),
                );
                self.backend.set_mute(true)?;
                self.record(
                    now_unix,
                    EventKind::Muted,
                    serde_json::json!({"reason": "unmuted_without_grant"}),
                );
            }
            Decision::UnmuteForGrant { remaining_secs } => {
                self.backend.set_mute(false)?;
                self.record(
                    now_unix,
                    EventKind::UnmutedForGrant,
                    serde_json::json!({"remaining_secs": remaining_secs}),
                );
            }
            Decision::LeaveMuted | Decision::LeaveUnmuted | Decision::Standby => {
                // No action and nothing new to log: AgentStarted /
                // PolicyLoaded already cover the steady state.
            }
        }
        Ok(decision)
    }

    /// The resident loop: log start, then step forever.
    pub fn run(&mut self, now_fn: impl Fn() -> i64) -> Result<()> {
        let now = now_fn();
        self.record(
            now,
            EventKind::AgentStarted,
            serde_json::json!({"version": env!("CARGO_PKG_VERSION")}),
        );
        self.record(
            now,
            EventKind::PolicyLoaded,
            serde_json::json!({
                "enforce": self.policy.enforce,
                "allow_unmute": self.policy.allow_unmute,
                "max_unmute_minutes": self.policy.max_unmute_minutes,
                "schedule_windows": self.policy.schedule.len(),
            }),
        );
        loop {
            self.step(now_fn())?;
            std::thread::sleep(std::time::Duration::from_millis(
                self.policy.poll_interval_ms,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[derive(Default)]
    struct FakeBackend {
        muted: bool,
        volume_percent: Option<u8>,
        mute_calls: Vec<bool>,
    }

    impl AudioBackend for FakeBackend {
        fn get_state(&mut self) -> Result<Observed> {
            Ok(Observed {
                muted: self.muted,
                volume_percent: self.volume_percent,
            })
        }
        fn set_mute(&mut self, mute: bool) -> Result<()> {
            self.muted = mute;
            self.mute_calls.push(mute);
            Ok(())
        }
    }

    struct Rig {
        _dir: tempfile::TempDir,
        paths: WatchPaths,
    }

    fn rig() -> (Rig, Watch<FakeBackend>) {
        let dir = tempfile::tempdir().unwrap();
        let paths = WatchPaths {
            policy: dir.path().join("policy.json"),
            grant: dir.path().join("grant.json"),
            log: dir.path().join("audit.log"),
        };
        let backend = FakeBackend {
            muted: false,
            volume_percent: Some(55),
            ..Default::default()
        };
        let watch = Watch::new(Policy::starter(), paths.clone(), backend).unwrap();
        (Rig { _dir: dir, paths }, watch)
    }

    // 2026-11-16 10:00 JST (Monday) = 01:00 UTC.
    const T0: i64 = 1_794_790_800;

    #[test]
    fn startup_poll_mutes_an_unmuted_endpoint() {
        let (_rig, mut w) = rig();
        assert_eq!(w.step(T0).unwrap(), Decision::MuteNow);
        assert!(w.backend.muted);
        assert_eq!(w.backend.mute_calls, vec![true]);
        // Next poll: already muted, no further action.
        assert_eq!(w.step(T0 + 1).unwrap(), Decision::LeaveMuted);
        assert_eq!(w.backend.mute_calls, vec![true]);
    }

    #[test]
    fn volume_raise_is_detected_and_remuted() {
        let (_rig, mut w) = rig();
        w.step(T0).unwrap();
        // The user raises the volume / unmutes behind our back.
        w.backend.muted = false;
        assert_eq!(w.step(T0 + 5).unwrap(), Decision::MuteNow);
        assert!(w.backend.muted);
    }

    #[test]
    fn grant_unmutes_then_expiry_remutes() {
        let (rig, mut w) = rig();
        w.step(T0).unwrap();
        assert!(w.backend.muted);

        // Admin grants 30 minutes starting at T0+10.
        Grant::new(T0 + 10, 30).save(&rig.paths.grant).unwrap();
        assert_eq!(
            w.step(T0 + 10).unwrap(),
            Decision::UnmuteForGrant {
                remaining_secs: 30 * 60
            }
        );
        assert!(!w.backend.muted);
        assert_eq!(w.step(T0 + 20).unwrap(), Decision::LeaveUnmuted);

        // Grant expires at T0+10+1800: the endpoint is re-muted.
        assert_eq!(w.step(T0 + 10 + 30 * 60).unwrap(), Decision::MuteNow);
        assert!(w.backend.muted);

        // The whole story is in the audit log, chain intact.
        let text = std::fs::read_to_string(&rig.paths.log).unwrap();
        let status = crate::audit::verify_chain(&text).unwrap();
        assert!(status.events >= 5);
        assert!(text.contains("volume_raised_detected"));
        assert!(text.contains("unmuted_for_grant"));
        assert!(text.contains("grant_expired"));
    }

    #[test]
    fn corrupt_grant_file_never_unmutes() {
        let (rig, mut w) = rig();
        w.step(T0).unwrap();
        std::fs::write(&rig.paths.grant, "{tampered").unwrap();
        w.backend.muted = false;
        // Corruption is treated as "no grant" (and logged), never as
        // permission: the endpoint is muted again.
        assert_eq!(w.step(T0 + 5).unwrap(), Decision::MuteNow);
        assert!(w.backend.muted);
    }
}
