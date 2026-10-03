<#
RAWRXD_IDE_LAUNCH_PROBE_001

Measures whether RawrXD-Win32IDE.exe actually starts and creates a window. The IDE target
LINKS (verified: 22,361,600 bytes, Subsystem=2 WINDOWS_GUI, sha256 93697D40...), but
linking is not running. This is the first runtime evidence for that binary.

Bounded by construction: a single PID is launched, observed for a fixed window, then
terminated. Nothing is killed by image name.

Observations recorded:
  - process survived N seconds
  - exit code if it died
  - top-level windows owned by that PID, with titles and visibility
  - child processes spawned
  - any files created or modified during the probe window
#>

$ErrorActionPreference = 'Continue'
$Exe   = 'F:\~dev\build_ide_probe\bin\RawrXD-Win32IDE.exe'
$Probe = 75          # seconds to observe
$Work  = 'F:\~dev\audit_tombstone_001'

if (-not (Test-Path $Exe)) { Write-Output "ABORT: $Exe missing"; exit 2 }

# Baseline of recently-touched files, so anything the IDE writes is attributable.
$cutoff = (Get-Date).AddMinutes(-2)
$before = @{}
foreach ($d in @("$env:TEMP", "$env:LOCALAPPDATA", "$env:APPDATA", 'F:\~dev', 'F:\~dev\rawrxd')) {
    if (Test-Path $d) {
        Get-ChildItem -Path $d -File -Recurse -Depth 2 -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $cutoff } | ForEach-Object { $before[$_.FullName] = $_.LastWriteTime }
    }
}

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
public class Win {
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr p);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
    delegate bool EnumProc(IntPtr h, IntPtr p);
    public static List<string> ForPid(uint want) {
        var outp = new List<string>();
        EnumWindows((h, p) => {
            uint pid; GetWindowThreadProcessId(h, out pid);
            if (pid == want) {
                var t = new StringBuilder(512); GetWindowTextW(h, t, 512);
                var c = new StringBuilder(256); GetClassNameW(h, c, 256);
                outp.Add(string.Format("class={0} visible={1} title=\"{2}\"", c, IsWindowVisible(h), t));
            }
            return true;
        }, IntPtr.Zero);
        return outp;
    }
}
"@

Write-Output "LAUNCHING=$Exe"
Write-Output "PROBE_SECONDS=$Probe"
$start = Get-Date
$proc = Start-Process -FilePath $Exe -PassThru -WindowStyle Normal
Write-Output "PID=$($proc.Id)"
Write-Output "START_UTC=$($proc.StartTime.ToUniversalTime().ToString('o'))"

$exited = $false
$exitCode = $null
for ($i = 0; $i -lt $Probe; $i++) {
    Start-Sleep -Seconds 1
    if ($proc.HasExited) { $exited = $true; $exitCode = $proc.ExitCode; break }
}

$survivedSec = [int]((Get-Date) - $start).TotalSeconds
Write-Output ''
Write-Output "SURVIVED_SECONDS=$survivedSec"
Write-Output "EXITED_EARLY=$exited"
if ($exited) { Write-Output "EXIT_CODE=$exitCode" }

Write-Output ''
if (-not $exited) {
    Write-Output "WORKING_SET_MB=$([math]::Round($proc.WorkingSet64/1MB,1))"
    Write-Output "THREAD_COUNT=$($proc.Threads.Count)"
    Write-Output "HANDLE_COUNT=$($proc.HandleCount)"
    $wins = [Win]::ForPid([uint32]$proc.Id)
    Write-Output "TOP_LEVEL_WINDOWS=$($wins.Count)"
    $wins | ForEach-Object { Write-Output "  $_" }

    Write-Output ''
    Write-Output '--- children ---'
    $kids = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($proc.Id)" -ErrorAction SilentlyContinue)
    Write-Output "CHILD_PROCESS_COUNT=$($kids.Count)"
    $kids | ForEach-Object { Write-Output "  pid=$($_.ProcessId) name=$($_.Name)" }
}

Write-Output ''
Write-Output '--- files written during the probe ---'
$cutoff2 = $start.AddSeconds(-1)
$after = @()
foreach ($d in @("$env:TEMP", "$env:LOCALAPPDATA", "$env:APPDATA", 'F:\~dev', 'F:\~dev\rawrxd')) {
    if (Test-Path $d) {
        Get-ChildItem -Path $d -File -Recurse -Depth 2 -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $cutoff2 } | ForEach-Object { $after += $_ }
    }
}
Write-Output "FILES_TOUCHED=$($after.Count)"
$after | Select-Object -First 25 | ForEach-Object { Write-Output ("  {0}  {1:u}" -f $_.FullName, $_.LastWriteTime) }

Write-Output ''
Write-Output '--- teardown (this PID only) ---'
if (-not $proc.HasExited) { $proc.Kill(); $proc.WaitForExit(20000) | Out-Null }
Write-Output "STILL_ALIVE_AFTER_KILL=$(if (-not $proc.HasExited) { 'YES' } else { 'NO' })"
Write-Output "IDE_LAUNCHED=$survivedSec"
