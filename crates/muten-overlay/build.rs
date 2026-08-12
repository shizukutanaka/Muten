fn main() {
    // Embed git commit hash in the binary for --version display.
    let git_hash = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=MUTEN_GIT_COMMIT={git_hash}");
    // .git lives at the repo root, two levels above this crate's Cargo.toml.
    // Relative paths are resolved from the manifest dir (CARGO_MANIFEST_DIR),
    // so these point to the correct .git/ even in a workspace layout.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads/");
}
