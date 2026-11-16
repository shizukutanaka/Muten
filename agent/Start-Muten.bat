@echo off
rem ============================================================
rem  muten-audio launcher (resident watchdog)
rem  Keep this window open while enforcement is active.
rem  Closing the window (or Ctrl+C) stops the agent - that is
rem  intentional and visible, never silent.
rem ============================================================
setlocal
cd /d %~dp0

if not exist muten-audio.exe (
    echo [muten] ERROR: muten-audio.exe not found in this folder.
    echo [muten] Build it once with Build.bat, or copy a built
    echo [muten] muten-audio.exe next to this file.
    pause
    exit /b 1
)
if not exist policy.json (
    echo [muten] ERROR: policy.json not found.
    echo [muten] Run Set-Pin.bat first - it creates policy.json
    echo [muten] and asks you to set the admin PIN.
    pause
    exit /b 1
)
if not exist audio-helper.ps1 (
    echo [muten] ERROR: audio-helper.ps1 not found in this folder.
    pause
    exit /b 1
)

echo [muten] Starting the forced-mute agent...
echo [muten] Policy: policy.json   Log: audit.log
echo [muten] Close this window or press Ctrl+C to stop.
echo.

muten-audio.exe watch --policy policy.json --grant grant.json --log audit.log --helper audio-helper.ps1

echo.
echo [muten] Agent stopped with exit code %errorlevel%.
echo [muten] If that was not intentional, read the messages above
echo [muten] and check audit.log in this folder.
pause
