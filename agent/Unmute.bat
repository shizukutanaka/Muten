@echo off
rem ============================================================
rem  muten-audio: grant a temporary unmute (admin PIN required).
rem  Sound comes back on the agent's next poll and is muted
rem  again automatically when the grant expires.
rem ============================================================
setlocal
cd /d %~dp0

if not exist muten-audio.exe (
    echo [muten] ERROR: muten-audio.exe not found in this folder.
    pause
    exit /b 1
)
if not exist policy.json (
    echo [muten] ERROR: policy.json not found. Run Set-Pin.bat first.
    pause
    exit /b 1
)

set "MINUTES="
set /p MINUTES=How many minutes of sound? (policy cap applies):
if "%MINUTES%"=="" set "MINUTES=15"

muten-audio.exe unmute --policy policy.json --grant grant.json --log audit.log --minutes %MINUTES%

echo.
echo [muten] Finished with exit code %errorlevel%.
pause
