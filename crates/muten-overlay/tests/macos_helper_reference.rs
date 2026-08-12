//! End-to-end test for the real macOS reference helper script
//! (`installer/overlay-helper/muten-overlay-helper-macos.sh`), not just
//! the wire-format fixtures in `helper_contract.rs`. Stubs `osascript`
//! on `PATH` with a fake script that emits realistic System
//! Events output, then runs the *actual* shipped shell script and
//! inspects its JSON output — the same "drive the real artifact, not
//! just a fixture" discipline used elsewhere in this test suite (see
//! `linux_helper_reference.rs`).

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

fn write_executable(dir: &std::path::Path, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

/// Fake `osascript` modeling two windows: a borderless scam alert whose
/// `button 1` (the close button `dismiss()` clicks) does not exist, and
/// an ordinary window that has one.
fn write_fake_osascript(dir: &std::path::Path) {
    write_executable(
        dir,
        "osascript",
        "#!/bin/sh\n\
         if [ \"$1\" = \"-e\" ]; then\n\
         case \"$2\" in\n\
         *\"bounds of window of desktop\"*) echo \"0, 0, 1920, 1080\" ;;\n\
         *) echo \"true\" ;;\n\
         esac\n\
         exit 0\n\
         fi\n\
         printf 'ScamAlert\\tYour Computer Is Infected\\t1920\\t1080\\tfalse\\n'\n\
         printf 'TextEdit\\tuntitled\\t800\\t600\\ttrue\\n'\n",
    );
}

/// Regression guard for the `has_close_button` slice of audit DR-2 on
/// macOS: the helper used to hard-code `has_close_button: true`
/// unconditionally, silently suppressing the `no_close_button` (+25)
/// signal — the strongest behavioral tell of a scam overlay — for a
/// genuinely borderless/frameless scam window on macOS.
#[test]
fn enumerate_reports_has_close_button_from_button_1_existence() {
    let dir = tempfile::tempdir().unwrap();
    write_fake_osascript(dir.path());

    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../installer/overlay-helper/muten-overlay-helper-macos.sh"
    );
    let path_with_fakes = format!(
        "{}:{}",
        dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("sh")
        .arg(script)
        .arg("enumerate")
        .env("PATH", path_with_fakes)
        .stdin(Stdio::null())
        .output()
        .expect("run the real macos helper script");
    assert!(
        output.status.success(),
        "helper enumerate must exit 0: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let windows: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("enumerate did not print valid JSON ({e}): {stdout}"));
    let windows = windows.as_array().expect("enumerate prints a JSON array");
    assert_eq!(windows.len(), 2, "both fake windows must be enumerated");

    let scam = windows
        .iter()
        .find(|w| w["id"] == "ScamAlert::Your Computer Is Infected")
        .expect("scam alert window present");
    assert_eq!(
        scam["window"]["has_close_button"], false,
        "a window without button 1 must report has_close_button:false: {scam}"
    );

    let ordinary = windows
        .iter()
        .find(|w| w["id"] == "TextEdit::untitled")
        .expect("ordinary window present");
    assert_eq!(
        ordinary["window"]["has_close_button"], true,
        "a window with button 1 must report has_close_button:true: {ordinary}"
    );
}

/// Fake `osascript` modeling two windows: a modal scam dialog whose
/// accessibility `subrole` is `AXDialog` (no close button either — a
/// realistic borderless "Verify Your Identity" alert), and an ordinary
/// standard window with neither trait.
fn write_fake_osascript_modal(dir: &std::path::Path) {
    write_executable(
        dir,
        "osascript",
        "#!/bin/sh\n\
         if [ \"$1\" = \"-e\" ]; then\n\
         case \"$2\" in\n\
         *\"bounds of window of desktop\"*) echo \"0, 0, 1920, 1080\" ;;\n\
         *) echo \"true\" ;;\n\
         esac\n\
         exit 0\n\
         fi\n\
         printf 'ScamAlertApp\\tVerify Your Identity\\t400\\t300\\tfalse\\ttrue\\n'\n\
         printf 'TextEdit\\tuntitled\\t800\\t600\\ttrue\\tfalse\\n'\n",
    );
}

/// Regression guard for the `blocks_input` slice of audit DR-2 on macOS:
/// the helper used to hard-code `blocks_input: false` unconditionally,
/// silently suppressing the classifier's `blocks_input` (+20) signal for
/// a genuinely modal scam dialog. `AXDialog`/`AXSystemDialog` is the
/// standard macOS Accessibility API subrole for a modal dialog window.
#[test]
fn enumerate_reports_blocks_input_from_axdialog_subrole() {
    let dir = tempfile::tempdir().unwrap();
    write_fake_osascript_modal(dir.path());

    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../installer/overlay-helper/muten-overlay-helper-macos.sh"
    );
    let path_with_fakes = format!(
        "{}:{}",
        dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("sh")
        .arg(script)
        .arg("enumerate")
        .env("PATH", path_with_fakes)
        .stdin(Stdio::null())
        .output()
        .expect("run the real macos helper script");
    assert!(
        output.status.success(),
        "helper enumerate must exit 0: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let windows: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("enumerate did not print valid JSON ({e}): {stdout}"));
    let windows = windows.as_array().expect("enumerate prints a JSON array");
    assert_eq!(windows.len(), 2, "both fake windows must be enumerated");

    let modal = windows
        .iter()
        .find(|w| w["id"] == "ScamAlertApp::Verify Your Identity")
        .expect("modal scam dialog window present");
    assert_eq!(
        modal["window"]["blocks_input"], true,
        "a window whose subrole is AXDialog must report blocks_input:true: {modal}"
    );

    let ordinary = windows
        .iter()
        .find(|w| w["id"] == "TextEdit::untitled")
        .expect("ordinary window present");
    assert_eq!(
        ordinary["window"]["blocks_input"], false,
        "a window with a standard (non-dialog) subrole must report blocks_input:false: {ordinary}"
    );
}
