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
use crate::distribute::{refresh_policy, PolicyFetcher, RefreshOutcome};
use crate::grant::Grant;
use crate::policy::Policy;
use crate::time::local_from_unix;
use crate::{Error, Result};

/// OS audio operations. Implemented by [`HelperBackend`] (Windows)
/// and [`crate::LinuxBackend`] (Linux) in production, and by fakes in
/// tests.
pub trait AudioBackend {
    /// Current state of the default playback endpoint.
    fn get_state(&mut self) -> Result<Observed>;
    /// Set the endpoint mute. `true` = muted.
    fn set_mute(&mut self, mute: bool) -> Result<()>;
}

/// Forwarding impl so the CLI can pick the backend at runtime
/// (helper vs. Linux) and hand the watchdog a single boxed backend.
impl AudioBackend for Box<dyn AudioBackend> {
    fn get_state(&mut self) -> Result<Observed> {
        (**self).get_state()
    }

    fn set_mute(&mut self, mute: bool) -> Result<()> {
        (**self).set_mute(mute)
    }
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

/// Central-distribution state attached to a [`Watch`]: where the
/// policy is pulled from, and how often.
struct PolicySource {
    fetcher: Box<dyn PolicyFetcher>,
    label: String,
    interval_secs: i64,
    last_check_unix: Option<i64>,
}

/// The watchdog state machine.
pub struct Watch<B: AudioBackend> {
    policy: Policy,
    paths: WatchPaths,
    backend: B,
    log: AuditLog,
    /// Whether we have already recorded the current grant's expiry.
    expired_grant_seen: Option<i64>,
    /// Central policy distribution, when configured.
    source: Option<PolicySource>,
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
            source: None,
        })
    }

    /// Attach a central policy source: the watchdog pulls it every
    /// `interval_secs` (and once on the first poll) and applies
    /// whatever validates. See [`crate::distribute`] for the rules —
    /// a failed or invalid pull is logged and never disturbs
    /// enforcement.
    pub fn with_policy_source(
        mut self,
        fetcher: Box<dyn PolicyFetcher>,
        interval_secs: i64,
    ) -> Watch<B> {
        let label = fetcher.label();
        self.source = Some(PolicySource {
            fetcher,
            label,
            interval_secs: interval_secs.max(1),
            last_check_unix: None,
        });
        self
    }

    /// The policy currently in force (after any distributed refresh).
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The backend the watchdog drives.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Mutable access to the backend (tests substitute machine
    /// states behind the watchdog's back, e.g. a volume raise).
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Pull the central source when due and apply a valid new policy.
    /// Runs at the top of a poll; the poll itself then decides with
    /// the freshest policy. Failures are recorded and swallowed —
    /// enforcement continues with the policy already in force.
    fn maybe_refresh_policy(&mut self, now_unix: i64) {
        let (label, result) = {
            let Some(source) = &mut self.source else {
                return;
            };
            if let Some(last) = source.last_check_unix {
                if now_unix - last < source.interval_secs {
                    return;
                }
            }
            source.last_check_unix = Some(now_unix);
            let label = source.label.clone();
            let result = refresh_policy(source.fetcher.as_ref(), &self.paths.policy);
            (label, result)
        };
        match result {
            Ok(RefreshOutcome::Unchanged) => {
                // Steady state: nothing to record (PolicyLoaded /
                // PolicyUpdated already tell the story).
            }
            Ok(RefreshOutcome::Applied { policy, sha256 }) => {
                self.policy = policy;
                self.record(
                    now_unix,
                    EventKind::PolicyUpdated,
                    serde_json::json!({
                        "source": label,
                        "sha256": sha256,
                        "enforce": self.policy.enforce,
                        "allow_unmute": self.policy.allow_unmute,
                        "max_unmute_minutes": self.policy.max_unmute_minutes,
                        "schedule_windows": self.policy.schedule.len(),
                        "pin_set": self.policy.pin.is_some(),
                    }),
                );
            }
            Err(e) => {
                // "Could not fetch it" and "fetched it but it is not
                // a valid policy" are different operational problems;
                // the log says which one happened.
                let kind = if matches!(e, Error::Backend(_)) {
                    EventKind::PolicyFetchFailed
                } else {
                    EventKind::PolicyError
                };
                self.record(
                    now_unix,
                    kind,
                    serde_json::json!({
                        "what": "policy_source",
                        "source": label,
                        "error": e.to_string(),
                    }),
                );
            }
        }
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
        // A due policy refresh happens first, so this poll already
        // decides with the freshest valid policy.
        self.maybe_refresh_policy(now_unix);

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
            if let Err(e) = self.step(now_fn()) {
                // The loop is about to end and enforcement with it:
                // say so in the log, so a collected log (fleet-status)
                // does not keep reporting this machine as running.
                self.record(
                    now_fn(),
                    EventKind::AgentStopped,
                    serde_json::json!({"reason": "error", "error": e.to_string()}),
                );
                return Err(e);
            }
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
        fail_set_mute: bool,
    }

    impl AudioBackend for FakeBackend {
        fn get_state(&mut self) -> Result<Observed> {
            Ok(Observed {
                muted: self.muted,
                volume_percent: self.volume_percent,
            })
        }
        fn set_mute(&mut self, mute: bool) -> Result<()> {
            if self.fail_set_mute {
                return Err(crate::Error::Backend("set_mute failed".into()));
            }
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
    fn run_records_agent_stopped_when_it_exits_on_an_error() {
        let (rig, mut w) = rig();
        w.backend.fail_set_mute = true;
        assert!(w.run(|| T0).is_err());
        let text = std::fs::read_to_string(&rig.paths.log).unwrap();
        crate::audit::verify_chain(&text).unwrap();
        let last = text.lines().last().unwrap();
        assert!(last.contains("\"agent_stopped\""), "{last}");
        assert!(last.contains("set_mute failed"), "{last}");
    }

    // ---- central policy distribution (intake) ----

    use crate::distribute::PolicyFetcher;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// A fetcher whose responses the test scripts in advance; the
    /// clone the test keeps shares the queue with the one the
    /// watchdog owns, so responses can be added between polls.
    #[derive(Clone, Default)]
    struct ScriptedFetcher {
        responses: Arc<Mutex<VecDeque<crate::Result<Vec<u8>>>>>,
        calls: Arc<Mutex<usize>>,
    }

    impl PolicyFetcher for ScriptedFetcher {
        fn fetch(&self) -> crate::Result<Vec<u8>> {
            *self.calls.lock().unwrap() += 1;
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("no scripted response left")
        }

        fn label(&self) -> String {
            "scripted://source".to_string()
        }
    }

    fn policy_json(enforce: bool) -> Vec<u8> {
        let mut p = Policy::starter();
        p.enforce = enforce;
        p.to_json().unwrap().into_bytes()
    }

    fn rig_with_source(interval_secs: i64) -> (Rig, Watch<FakeBackend>, ScriptedFetcher) {
        let (rig, watch) = rig();
        let fetcher = ScriptedFetcher::default();
        let watch = watch.with_policy_source(Box::new(fetcher.clone()), interval_secs);
        (rig, watch, fetcher)
    }

    fn serve(fetcher: &ScriptedFetcher, response: crate::Result<Vec<u8>>) {
        fetcher.responses.lock().unwrap().push_back(response);
    }

    #[test]
    fn distributed_policy_is_applied_on_the_first_poll() {
        let (rig, mut w, fetcher) = rig_with_source(300);
        let bytes = policy_json(false); // central says: enforcement off
        serve(&fetcher, Ok(bytes.clone()));

        // The starter policy would mute; the distributed one stands by.
        assert_eq!(w.step(T0).unwrap(), Decision::Standby);
        assert!(!w.backend.muted);
        assert!(!w.policy().enforce);

        // The application is in the audit log, identified by hash.
        let text = std::fs::read_to_string(&rig.paths.log).unwrap();
        assert!(text.contains("policy_updated"), "log: {text}");
        assert!(text.contains(&crate::distribute::policy_sha256(&bytes)));
    }

    #[test]
    fn invalid_distributed_policy_keeps_enforcement_and_is_logged() {
        let (rig, mut w, fetcher) = rig_with_source(300);
        serve(&fetcher, Ok(b"{tampered".to_vec()));

        assert_eq!(w.step(T0).unwrap(), Decision::MuteNow);
        assert!(w.backend.muted);
        assert!(w.policy().enforce);
        let text = std::fs::read_to_string(&rig.paths.log).unwrap();
        assert!(text.contains("policy_error"), "log: {text}");
    }

    #[test]
    fn unreachable_source_keeps_enforcement_and_is_logged() {
        let (rig, mut w, fetcher) = rig_with_source(300);
        serve(
            &fetcher,
            Err(crate::Error::Backend("share unreachable".into())),
        );

        assert_eq!(w.step(T0).unwrap(), Decision::MuteNow);
        assert!(w.backend.muted);
        let text = std::fs::read_to_string(&rig.paths.log).unwrap();
        assert!(text.contains("policy_fetch_failed"), "log: {text}");
    }

    #[test]
    fn refreshes_are_rate_limited_by_the_interval() {
        let (_rig, mut w, fetcher) = rig_with_source(3600);
        serve(&fetcher, Ok(policy_json(false)));
        assert_eq!(w.step(T0).unwrap(), Decision::Standby);

        // A new central policy exists, but the interval has not
        // elapsed: no second fetch, and the applied policy still rules.
        serve(&fetcher, Ok(policy_json(true)));
        assert_eq!(w.step(T0 + 10).unwrap(), Decision::Standby);
        assert_eq!(*fetcher.calls.lock().unwrap(), 1);

        // After the interval, the new policy is pulled and applied.
        assert_eq!(w.step(T0 + 3600).unwrap(), Decision::MuteNow);
        assert_eq!(*fetcher.calls.lock().unwrap(), 2);
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
