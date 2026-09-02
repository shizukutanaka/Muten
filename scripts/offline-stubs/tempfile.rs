//! Minimal stand-in for the `tempfile` crate: `tempdir()` and
//! `TempDir::new()`, which is all the product's tests use.
//!
//! Directories are removed on drop, as upstream does. Uniqueness comes
//! from pid + clock + a process-local counter, so two directories created
//! inside the same nanosecond still differ - without the counter, tests
//! that create several temp dirs in quick succession could share a path
//! and see each other's files.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

pub struct TempDir {
    p: PathBuf,
}
impl TempDir {
    pub fn new() -> std::io::Result<TempDir> {
        tempdir()
    }
    pub fn path(&self) -> &Path {
        &self.p
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.p);
    }
}
pub fn tempdir() -> std::io::Result<TempDir> {
    let mut p = std::env::temp_dir();
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    p.push(format!("muten-stub-{}-{}-{}", std::process::id(), n, seq));
    std::fs::create_dir_all(&p)?;
    Ok(TempDir { p })
}
