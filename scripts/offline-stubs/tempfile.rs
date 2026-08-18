//! Minimal stand-in for the `tempfile` crate: only `tempdir()` is used.
use std::path::{Path, PathBuf};
pub struct TempDir { p: PathBuf }
impl TempDir {
    pub fn path(&self) -> &Path { &self.p }
}
impl Drop for TempDir {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.p); }
}
pub fn tempdir() -> std::io::Result<TempDir> {
    let mut p = std::env::temp_dir();
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    p.push(format!("muten-stub-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&p)?;
    Ok(TempDir { p })
}
