//! End-to-end test for the real X11 reference helper script
//! (`installer/overlay-helper/muten-overlay-helper-linux.sh`), not just
//! the wire-format fixtures in `helper_contract.rs`. Stubs `xprop`,
//! `wmctrl`, and `xdotool` on `PATH` with fake scripts that emit
//! realistic EWMH property text, then runs the *actual* shipped shell
//! script and inspects its JSON output — the same "drive the real
//! artifact, not just a fixture" discipline used for the compiled
//! `daemon` binary elsewhere in this test suite.

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

/// Fake `xprop`, `wmctrl`, `xdotool` modeling two windows: one a modal
/// dialog (`_NET_WM_STATE_MODAL` + `_NET_WM_STATE_ABOVE`) impersonating a
/// scam alert, one an ordinary window with no `_NET_WM_STATE` at all
/// (xprop's real "property not found" behavior).
fn write_fake_x11_tools(dir: &std::path::Path) {
    write_executable(
        dir,
        "wmctrl",
        "#!/bin/sh\n\
         if [ \"$1\" = \"-lG\" ]; then\n\
         printf '0x01000001 0 0 0 1920 1080 host.local  modal-scam-alert\\n'\n\
         printf '0x01000002 0 0 0 800 600 host.local  ordinary-notepad\\n'\n\
         elif [ \"$1\" = \"-l\" ]; then\n\
         printf '0x01000001 0 host.local  modal-scam-alert\\n'\n\
         printf '0x01000002 0 host.local  ordinary-notepad\\n'\n\
         fi\n",
    );
    write_executable(
        dir,
        "xprop",
        "#!/bin/sh\n\
         id=\"$2\"\n\
         prop=\"$3\"\n\
         case \"$prop\" in\n\
         _NET_WM_STATE)\n\
         if [ \"$id\" = \"0x01000001\" ]; then\n\
         echo '_NET_WM_STATE(ATOM) = _NET_WM_STATE_MODAL, _NET_WM_STATE_ABOVE'\n\
         else\n\
         echo '_NET_WM_STATE:  not found.'\n\
         fi\n\
         ;;\n\
         _NET_WM_ALLOWED_ACTIONS)\n\
         echo '_NET_WM_ALLOWED_ACTIONS(ATOM) = _NET_WM_ACTION_CLOSE, _NET_WM_ACTION_MOVE'\n\
         ;;\n\
         _NET_WM_PID)\n\
         echo '_NET_WM_PID(CARDINAL) = 4242'\n\
         ;;\n\
         esac\n",
    );
    write_executable(dir, "xdotool", "#!/bin/sh\necho \"1920 1080\"\n");
}

/// Regression guard for the `blocks_input` slice of audit DR-2 (helper
/// geometry-field fidelity): the X11 reference helper used to hard-code
/// `blocks_input: false` unconditionally, even though `_NET_WM_STATE`
/// (already fetched for `topmost`) carries a genuine EWMH signal for it —
/// `_NET_WM_STATE_MODAL`. Without this, a modal scam dialog reported
/// `blocks_input: false`, silently losing the `blocks_input` (+20)
/// signal the classifier is designed to use, on every real X11 host.
#[test]
fn enumerate_reports_blocks_input_from_net_wm_state_modal() {
    let dir = tempfile::tempdir().unwrap();
    write_fake_x11_tools(dir.path());

    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../installer/overlay-helper/muten-overlay-helper-linux.sh"
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
        .env("DISPLAY", ":0")
        .stdin(Stdio::null())
        .output()
        .expect("run the real linux helper script");
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
        .find(|w| w["id"] == "0x01000001")
        .expect("modal-scam-alert window present");
    assert_eq!(
        modal["window"]["blocks_input"], true,
        "a window with _NET_WM_STATE_MODAL must report blocks_input:true: {modal}"
    );
    assert_eq!(
        modal["window"]["topmost"], true,
        "_NET_WM_STATE_ABOVE must still independently drive topmost: {modal}"
    );

    let ordinary = windows
        .iter()
        .find(|w| w["id"] == "0x01000002")
        .expect("ordinary-notepad window present");
    assert_eq!(
        ordinary["window"]["blocks_input"], false,
        "a window with no _NET_WM_STATE property must report blocks_input:false: {ordinary}"
    );
}
