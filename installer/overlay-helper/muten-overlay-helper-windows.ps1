<#
  muten overlay helper - Windows reference implementation.

  Protocol (see docs/OVERLAY_BLOCKING.md). muten-overlay's
  SubprocessController invokes this with one of:

    helper.ps1 --probe        exit 0 if usable
    helper.ps1 enumerate      print JSON array of {id, window} to stdout
    helper.ps1 dismiss <id>   exit 0 acted / 2 already-gone / other failure

  This reference uses only built-in .NET / Win32 P/Invoke available in
  Windows PowerShell 5.1+ (shipped with Windows 10/11), so no extra
  install is needed. All the unsafe Win32 interop lives HERE, not in
  muten itself, which stays forbid(unsafe_code).

  It closes windows with WM_CLOSE (graceful) and never kills the
  owning process - process/registry cleanup is the EDR's job
  (CLAUDE.md I9).

  Fields X11/Win32 can't cheaply determine (unsolicited vs
  user-initiated) default conservatively so the classifier biases
  toward Suspicious (review) over Block (dismiss).
#>

param(
    [Parameter(Position = 0)][string]$Cmd = "",
    [Parameter(Position = 1)][string]$Id  = ""
)

$ErrorActionPreference = "Stop"

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class MutenWin {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr p);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr h);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr h, int i);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageTimeout(IntPtr h, uint msg, IntPtr wp, IntPtr lp, uint flags, uint timeout, out IntPtr res);
    [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    public struct RECT { public int Left, Top, Right, Bottom; }
    public const int GWL_EXSTYLE = -20;
    public const int GWL_STYLE = -16;
    public const int WS_EX_TOPMOST = 0x00000008;
    public const int WS_SYSMENU = 0x00080000;
    public const uint WM_CLOSE = 0x0010;
}
"@

function Json-Escape([string]$s) {
    if ($null -eq $s) { return "" }
    $s = $s -replace '\\', '\\'
    $s = $s -replace '"', '\"'
    $s = $s -replace "`t", " "
    $s = $s -replace "`r", ""
    $s = $s -replace "`n", " "
    return $s
}

function Do-Probe {
    # If the Add-Type compiled and we're on Windows, we're usable.
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { exit 0 }
    exit 1
}

function Do-Enumerate {
    $screenW = [System.Windows.Forms.SystemInformation]::VirtualScreen.Width
    $screenH = [System.Windows.Forms.SystemInformation]::VirtualScreen.Height
    if ($screenW -le 0) { $screenW = 1920 }
    if ($screenH -le 0) { $screenH = 1080 }
    $fg = [MutenWin]::GetForegroundWindow()

    $items = New-Object System.Collections.ArrayList
    $cb = [MutenWin+EnumWindowsProc]{
        param($h, $lp)
        if (-not [MutenWin]::IsWindowVisible($h)) { return $true }
        $len = [MutenWin]::GetWindowTextLength($h)
        if ($len -le 0) { return $true }
        $sb = New-Object System.Text.StringBuilder ($len + 1)
        [void][MutenWin]::GetWindowText($h, $sb, $sb.Capacity)
        $title = $sb.ToString()
        if ([string]::IsNullOrWhiteSpace($title)) { return $true }

        $r = New-Object MutenWin+RECT
        [void][MutenWin]::GetWindowRect($h, [ref]$r)
        $w = $r.Right - $r.Left
        $hgt = $r.Bottom - $r.Top
        if ($w -le 0 -or $hgt -le 0) { return $true }
        $cov = [int](($w * $hgt * 100) / ($screenW * $screenH))
        if ($cov -gt 100) { $cov = 100 }

        $ex = [MutenWin]::GetWindowLong($h, [MutenWin]::GWL_EXSTYLE)
        $topmost = (($ex -band [MutenWin]::WS_EX_TOPMOST) -ne 0)

        # Close button: a window with WS_SYSMENU has the standard title-
        # bar close control. Scam overlays frequently drop it (borderless
        # full-screen) to trap the user. This is a real signal, so we
        # report it rather than defaulting to true.
        $style = [MutenWin]::GetWindowLong($h, [MutenWin]::GWL_STYLE)
        $hasClose = (($style -band [MutenWin]::WS_SYSMENU) -ne 0)

        # Owning process name (best-effort): HWND -> PID -> ProcessName.
        # Lets muten's `process:` blocklist rules and the rogue_av_process
        # signal work on Windows. Get-Process can race a just-exited PID,
        # so failures simply omit the field (the daemon treats a missing
        # value as "unknown").
        $procName = ""
        $procId = [uint32]0
        [void][MutenWin]::GetWindowThreadProcessId($h, [ref]$procId)
        if ($procId -gt 0) {
            $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if ($null -ne $p) { $procName = $p.ProcessName }
        }

        $et = Json-Escape $title
        $procPart = ""
        if (-not [string]::IsNullOrWhiteSpace($procName)) {
            $procPart = '"process":"' + (Json-Escape $procName) + '",'
        }
        $obj = '{"id":"' + ([int64]$h) + '",' + $procPart + '"window":{"title":"' + $et + '","url":null,"coverage_percent":' + $cov + ',"topmost":' + ($topmost.ToString().ToLower()) + ',"has_close_button":' + ($hasClose.ToString().ToLower()) + ',"blocks_input":false,"origin":"unknown","age_ms":0}}'
        [void]$items.Add($obj)
        return $true
    }
    [void][MutenWin]::EnumWindows($cb, [IntPtr]::Zero)
    "[" + ($items -join ",") + "]"
}

function Do-Dismiss([string]$winId) {
    if ([string]::IsNullOrWhiteSpace($winId)) { [Console]::Error.WriteLine("dismiss: missing id"); exit 1 }
    $h = [IntPtr][int64]$winId
    if (-not [MutenWin]::IsWindow($h)) { exit 2 }   # already gone
    $res = [IntPtr]::Zero
    # WM_CLOSE via SendMessageTimeout (2s) so a hung window can't block us.
    [void][MutenWin]::SendMessageTimeout($h, [MutenWin]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero, 0, 2000, [ref]$res)
    if (-not [MutenWin]::IsWindow($h)) { exit 0 }   # closed
    # Still there after WM_CLOSE: report acted-but-uncertain as success
    # (we sent the close); muten will re-evaluate next sweep.
    exit 0
}

Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue

switch ($Cmd) {
    "--probe"   { Do-Probe }
    "enumerate" { Do-Enumerate }
    "dismiss"   { Do-Dismiss $Id }
    default     { [Console]::Error.WriteLine("usage: helper.ps1 {--probe|enumerate|dismiss <id>}"); exit 1 }
}
