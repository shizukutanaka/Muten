//! Central policy distribution: the intake side.
//!
//! Until now `policy.json` was placed on each machine by hand, which
//! does not survive contact with a fleet. This module is the smallest
//! intake that fixes that: the watchdog (or the one-shot
//! `fetch-policy` command) periodically pulls a policy from one
//! administrator-controlled location — a file path (a shared folder,
//! including a UNC path, or a local file) or an http(s) URL — and
//! applies it **only** if it parses and validates exactly like a
//! hand-placed policy ([`Policy::load`]'s rules: unknown fields are
//! rejected, structural invariants are checked). Anything else —
//! source unreachable, content invalid — leaves the current policy
//! byte-for-byte untouched, and the caller records the failure in the
//! audit log: the intake must never become a way for enforcement to
//! quietly fall off.
//!
//! Trust model, stated plainly (also in the README): there is **no
//! signature scheme and no home-grown cryptography** here. Whoever
//! can write to the distribution location controls the policy of
//! every machine that pulls from it — protect that location like an
//! administrator credential (share ACLs, TLS on the server, …). What
//! the intake does provide is an identity trail: every applied
//! policy is recorded in the audit log together with the SHA-256 of
//! its exact bytes, so an administrator can verify after the fact
//! which policy each machine actually took.
//!
//! Like the audio backend, all OS contact is delegated: a file source
//! is a plain read, and a URL source is downloaded by the PowerShell
//! helper (`agent/policy-fetch.ps1`). This crate does no network I/O
//! itself and gains no network dependency.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::policy::Policy;
use crate::{Error, Result};

/// A place a policy can be pulled from.
pub trait PolicyFetcher {
    /// Fetch the raw policy bytes. Any failure is an `Err`; the
    /// caller keeps the current policy.
    fn fetch(&self) -> Result<Vec<u8>>;
    /// Human-readable source description for the audit log. Must not
    /// contain credentials (see [`sanitize_source_label`]).
    fn label(&self) -> String;
}

/// Fetches from a file path — a shared folder (including a UNC path
/// such as `\\fileserver\muten\policy.json`), or a local file.
pub struct FileFetcher {
    pub path: PathBuf,
}

impl PolicyFetcher for FileFetcher {
    fn fetch(&self) -> Result<Vec<u8>> {
        std::fs::read(&self.path).map_err(|e| {
            Error::Backend(format!(
                "failed to read policy source {}: {e}",
                self.path.display()
            ))
        })
    }

    fn label(&self) -> String {
        self.path.display().to_string()
    }
}

/// Fetches from an http(s) URL by delegating the download to the
/// PowerShell helper (`agent/policy-fetch.ps1`), exactly like the
/// audio backend delegates Core Audio to its helper script.
pub struct HelperFetcher {
    pub powershell: String,
    pub script: PathBuf,
    pub url: String,
}

impl HelperFetcher {
    pub fn new(script: PathBuf, url: String) -> HelperFetcher {
        HelperFetcher {
            powershell: "powershell".to_string(),
            script,
            url,
        }
    }
}

impl PolicyFetcher for HelperFetcher {
    fn fetch(&self) -> Result<Vec<u8>> {
        // The helper downloads to a file we name; PowerShell's stdout
        // is not a safe channel for arbitrary bytes.
        let tmp = std::env::temp_dir().join(format!(
            "muten-policy-fetch-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let result = (|| {
            let out = Command::new(&self.powershell)
                .args([
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    &self.script.to_string_lossy(),
                    &self.url,
                    &tmp.to_string_lossy(),
                ])
                .output()
                .map_err(|e| {
                    Error::Backend(format!("failed to launch policy fetch helper: {e}"))
                })?;
            if !out.status.success() {
                return Err(Error::Backend(format!(
                    "policy fetch helper exited with {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
            std::fs::read(&tmp)
                .map_err(|e| Error::Backend(format!("policy fetch helper produced no file: {e}")))
        })();
        let _ = std::fs::remove_file(&tmp);
        result
    }

    fn label(&self) -> String {
        sanitize_source_label(&self.url)
    }
}

/// Build the fetcher for a `--policy-source` value: an `http://` /
/// `https://` URL goes through the helper script; anything else is
/// treated as a file path.
pub fn fetcher_for_source(source: &str, fetch_helper: PathBuf) -> Box<dyn PolicyFetcher> {
    if source.starts_with("http://") || source.starts_with("https://") {
        Box::new(HelperFetcher::new(fetch_helper, source.to_string()))
    } else {
        Box::new(FileFetcher {
            path: PathBuf::from(source),
        })
    }
}

/// Strip any `user:password@` userinfo from a URL so audit-log labels
/// never record credentials. Non-URL labels pass through unchanged.
pub fn sanitize_source_label(source: &str) -> String {
    let Some(scheme_end) = source.find("://") else {
        return source.to_string();
    };
    let rest = &source[scheme_end + 3..];
    let authority_end = rest.find('/').unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => format!("{}{}", &source[..scheme_end + 3], &rest[at + 1..]),
        None => source.to_string(),
    }
}

/// SHA-256 (hex) of raw policy bytes — the identity under which an
/// applied policy is recorded in the audit log.
pub fn policy_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// What one refresh attempt did.
#[derive(Debug)]
pub enum RefreshOutcome {
    /// The source serves exactly what is already in place.
    Unchanged,
    /// A new policy was validated and written to the target file.
    Applied {
        /// The parsed policy (the same value the target now holds).
        policy: Policy,
        /// SHA-256 (hex) of the applied bytes.
        sha256: String,
    },
}

/// One refresh attempt against `target` (the local `policy.json`).
///
/// The fetched bytes must parse as a policy (unknown fields rejected,
/// exactly as for a hand-placed file) and pass [`Policy::validate`];
/// only then is the target replaced — atomically, via a sibling temp
/// file and rename. On any failure the target is left untouched.
pub fn refresh_policy(fetcher: &dyn PolicyFetcher, target: &Path) -> Result<RefreshOutcome> {
    let bytes = fetcher.fetch()?;
    let policy: Policy = serde_json::from_slice(&bytes)?;
    policy.validate()?;
    let sha256 = policy_sha256(&bytes);
    if let Ok(current) = std::fs::read(target) {
        if policy_sha256(&current) == sha256 {
            return Ok(RefreshOutcome::Unchanged);
        }
    }
    let tmp = target.with_extension("json.tmp");
    std::fs::write(&tmp, &bytes)?;
    if let Err(e) = std::fs::rename(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(RefreshOutcome::Applied { policy, sha256 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// A fetcher that plays back scripted responses, so tests never
    /// touch a network or a real share.
    struct FakeFetcher {
        label: String,
        responses: Mutex<VecDeque<Result<Vec<u8>>>>,
        calls: Mutex<usize>,
    }

    impl FakeFetcher {
        fn new(responses: Vec<Result<Vec<u8>>>) -> FakeFetcher {
            FakeFetcher {
                label: "fake://source".to_string(),
                responses: Mutex::new(responses.into()),
                calls: Mutex::new(0),
            }
        }
    }

    impl PolicyFetcher for FakeFetcher {
        fn fetch(&self) -> Result<Vec<u8>> {
            *self.calls.lock().unwrap() += 1;
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("no scripted response left")
        }

        fn label(&self) -> String {
            self.label.clone()
        }
    }

    fn policy_bytes(enforce: bool) -> Vec<u8> {
        let mut p = Policy::starter();
        p.enforce = enforce;
        p.to_json().unwrap().into_bytes()
    }

    #[test]
    fn valid_fetched_policy_is_applied_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("policy.json");
        std::fs::write(&target, policy_bytes(true)).unwrap();

        let bytes = policy_bytes(false);
        let fetcher = FakeFetcher::new(vec![Ok(bytes.clone())]);
        let outcome = refresh_policy(&fetcher, &target).unwrap();
        match outcome {
            RefreshOutcome::Applied { policy, sha256 } => {
                assert!(!policy.enforce);
                assert_eq!(sha256, policy_sha256(&bytes));
            }
            RefreshOutcome::Unchanged => panic!("expected Applied"),
        }
        // The target now holds the fetched bytes exactly, so the next
        // refresh recognises them as unchanged.
        assert_eq!(std::fs::read(&target).unwrap(), bytes);
    }

    #[test]
    fn identical_bytes_are_reported_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("policy.json");
        let bytes = policy_bytes(true);
        std::fs::write(&target, &bytes).unwrap();

        let fetcher = FakeFetcher::new(vec![Ok(bytes)]);
        assert!(matches!(
            refresh_policy(&fetcher, &target).unwrap(),
            RefreshOutcome::Unchanged
        ));
    }

    #[test]
    fn unparseable_content_keeps_the_target_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("policy.json");
        let original = policy_bytes(true);
        std::fs::write(&target, &original).unwrap();

        let fetcher = FakeFetcher::new(vec![Ok(b"{tampered".to_vec())]);
        assert!(refresh_policy(&fetcher, &target).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), original);
    }

    #[test]
    fn unknown_fields_in_fetched_policy_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("policy.json");
        let original = policy_bytes(true);
        std::fs::write(&target, &original).unwrap();

        // A typo'd or foreign field must fail loudly, exactly as it
        // does for a hand-placed policy file.
        let bytes = br#"{"version":1,"enforce":false,"surprise":true}"#.to_vec();
        let fetcher = FakeFetcher::new(vec![Ok(bytes)]);
        assert!(refresh_policy(&fetcher, &target).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), original);
    }

    #[test]
    fn invalid_policy_keeps_the_target_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("policy.json");
        let original = policy_bytes(true);
        std::fs::write(&target, &original).unwrap();

        // Parses as JSON and as a Policy, but fails validation.
        let bytes = br#"{"version":2,"enforce":false}"#.to_vec();
        let fetcher = FakeFetcher::new(vec![Ok(bytes)]);
        let err = refresh_policy(&fetcher, &target).unwrap_err();
        assert!(matches!(err, Error::Policy(_)), "error: {err}");
        assert_eq!(std::fs::read(&target).unwrap(), original);
    }

    #[test]
    fn fetch_failure_creates_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("policy.json");

        let fetcher = FakeFetcher::new(vec![Err(Error::Backend("share unreachable".into()))]);
        assert!(refresh_policy(&fetcher, &target).is_err());
        assert!(!target.exists());
    }

    #[test]
    fn file_fetcher_reads_a_path_and_reports_a_missing_one() {
        let dir = tempfile::tempdir().unwrap();
        let share = dir.path().join("policy.json");
        std::fs::write(&share, b"{}").unwrap();
        let fetcher = FileFetcher { path: share };
        assert_eq!(fetcher.fetch().unwrap(), b"{}");

        let missing = FileFetcher {
            path: dir.path().join("nope.json"),
        };
        assert!(missing.fetch().is_err());
    }

    #[test]
    fn source_kind_is_chosen_by_prefix() {
        let url = fetcher_for_source(
            "https://admin:secret@files.example.com/muten/policy.json",
            PathBuf::from("policy-fetch.ps1"),
        );
        // The label never carries the credentials from the URL.
        assert_eq!(url.label(), "https://files.example.com/muten/policy.json");

        let path = fetcher_for_source(
            r"\\fileserver\muten\policy.json",
            PathBuf::from("policy-fetch.ps1"),
        );
        assert_eq!(path.label(), r"\\fileserver\muten\policy.json");
    }

    #[test]
    fn labels_without_credentials_pass_through() {
        assert_eq!(
            sanitize_source_label("https://example.com/policy.json"),
            "https://example.com/policy.json"
        );
        assert_eq!(
            sanitize_source_label("/srv/muten/policy.json"),
            "/srv/muten/policy.json"
        );
        // An '@' in the path part is not userinfo.
        assert_eq!(
            sanitize_source_label("https://example.com/a@b/policy.json"),
            "https://example.com/a@b/policy.json"
        );
    }
}
