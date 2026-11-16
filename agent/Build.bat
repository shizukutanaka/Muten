@echo off
rem ============================================================
rem  Build muten-audio.exe from source and copy it next to the
rem  agent scripts. Requires a Rust toolchain (rustup) on PATH.
rem  Run this once on any Windows machine; the resulting folder
rem  (exe + scripts + policy) is portable - copy it anywhere.
rem ============================================================
setlocal
cd /d %~dp0

where cargo >nul 2>nul
if errorlevel 1 (
    echo [muten] ERROR: cargo not found. Install Rust from
    echo [muten] https://rustup.rs and run Build.bat again.
    pause
    exit /b 1
)

pushd ..\crates\muten-audio
cargo build --release
if errorlevel 1 (
    echo [muten] ERROR: build failed - see the messages above.
    popd
    pause
    exit /b 1
)
popd

copy /y ..\crates\muten-audio\target\release\muten-audio.exe .\muten-audio.exe >nul
if errorlevel 1 (
    echo [muten] ERROR: could not copy muten-audio.exe here.
    pause
    exit /b 1
)

echo [muten] Done: muten-audio.exe is in this folder.
echo [muten] Next: run Set-Pin.bat, then Start-Muten.bat.
pause
