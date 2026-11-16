//! muten-audio — the "audio" half of muten: forced-mute enforcement for
//! managed Windows PCs (company PCs, libraries, schools, kiosks).
//!
//! This crate is the *brain*: policy, schedule evaluation, the admin-PIN
//! gate, temporary-unmute grants, the watchdog decision function, and a
//! tamper-evident audit log. It performs **no OS audio calls itself** —
//! all Core Audio work lives in a small PowerShell helper
//! (`agent/audio-helper.ps1`) behind the [`AudioBackend`] trait, exactly
//! like muten-overlay keeps Win32 in its helper scripts. That split is
//! what makes the enforcement logic fully testable without a Windows
//! machine or a sound device.
//!
//! Honest scope (also stated in the README): this is a user-mode agent.
//! It deters casual unmuting and records what happened; it cannot stop a
//! user who holds local administrator rights on the box. Hard
//! enforcement needs a service running under a separate admin account,
//! ACL-protected files, or Group Policy / MDM — see the root README.

#![forbid(unsafe_code)]

pub mod agent;
pub mod audit;
pub mod decide;
pub mod distribute;
pub mod fleet;
pub mod grant;
pub mod pin;
pub mod policy;
pub mod time;

pub use agent::{AudioBackend, HelperBackend, Watch, WatchPaths};
pub use audit::{verify_chain, AuditLog, ChainStatus, Event, EventKind};
pub use decide::{decide, Decision, Observed};
pub use distribute::{
    fetcher_for_source, refresh_policy, FileFetcher, HelperFetcher, PolicyFetcher, RefreshOutcome,
};
pub use fleet::{
    analyze_log, collect_log_paths, format_unix_utc, machine_label, short_hash, AppliedPolicy,
    ChainCheck, MachineStatus, PolicyFailure, SyncStatus,
};
pub use grant::Grant;
pub use pin::PinRecord;
pub use policy::{Policy, Weekday, Window};

/// Errors surfaced by the library (the CLI maps them to exit codes).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("policy error: {0}")]
    Policy(#[from] policy::PolicyError),
    #[error("audit log error: {0}")]
    Audit(#[from] audit::AuditError),
    #[error("audio backend error: {0}")]
    Backend(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
