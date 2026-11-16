@echo off
rem ============================================================
rem  muten-audio: create policy.json (first run) or change the
rem  admin PIN. The PIN is stored only as a salted hash.
rem  Run this in a private console - the PIN you type is echoed.
rem ============================================================
setlocal
cd /d %~dp0

if not exist muten-audio.exe (
    echo [muten] ERROR: muten-audio.exe not found in this folder.
    echo [muten] Build it once with Build.bat first.
    pause
    exit /b 1
)

if exist policy.json (
    echo [muten] policy.json exists - changing the admin PIN.
    muten-audio.exe set-pin --policy policy.json
) else (
    echo [muten] No policy.json yet - creating one and setting the PIN.
    muten-audio.exe init --policy policy.json
)

echo.
echo [muten] Finished with exit code %errorlevel%.
pause
