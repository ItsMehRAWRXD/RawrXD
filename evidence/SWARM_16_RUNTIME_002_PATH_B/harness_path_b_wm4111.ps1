# SWARM_16_RUNTIME_002_PATH_B - tip GUI WM_COMMAND 4111 after createWindow fix
# PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 FAIL_CLOSED
# Historical tip 6832F439 preserved; this harness targets NEW tip SHA after rebuild.
$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\SWARM_16_RUNTIME_002_PATH_B"
$TipExe = "G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe"
$HistoricalSha = "6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2"
$MapPath = "G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.map"
$IDM_SUBAGENT_SWARM = 4111
$WM_COMMAND = 0x0111
$ClassName = "RawrXD_IDE_MainWindow"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $OutDir "logs") | Out-Null
$Log = Join-Path $OutDir "RUNLOG.txt"
$Stdout = Join-Path $OutDir "tip_gui_stdout.log"
$Stderr = Join-Path $OutDir "tip_gui_stderr.log"
$Summary = Join-Path $OutDir "SUMMARY.txt"
Set-Content -Path $Log -Value ""

function WLog([string]$m) {
  $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"), $m
  Add-Content -Path $Log -Value $line
  Write-Output $line
}

$cs = @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class TipSwarmInvokeB {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindowW(string c, string t);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  public static IntPtr FindMainByPid(uint pid, string className) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var cls = new StringBuilder(256);
      GetClassNameW(h, cls, 256);
      if (cls.ToString() == className) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

WLog "START SWARM_16_RUNTIME_002_PATH_B"
WLog "PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 PATH=B_GUI"
WLog "TIP_EXE=$TipExe"
WLog "HISTORICAL_SHA=$HistoricalSha (preserve)"

if (-not (Test-Path $TipExe)) {
  WLog "FAIL_CLOSED: tip exe missing"
  @"
PATH=B_GUI
TIP_EXE_MISSING=1
INVOKED=0
RUNTIME_PASS=0
PROMOTE=0
"@ | Set-Content $Summary
  exit 2
}

$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Set-Content (Join-Path $OutDir "sha.txt") "TIP_SHA=$sha"
WLog "TIP_SHA_OBSERVED=$sha"
$rebuilt = ($sha -ne $HistoricalSha)
WLog "TIP_REBUILD=$rebuilt"
if (-not $rebuilt) {
  WLog "GATE: tip still historical 6832F439 — SettingsManager fix not in binary; INVOKED not earned"
}

$mapHits = @{
  onSubAgentSwarm = $false
  resolveSwarmModelOrchPlan = $false
  executeSwarm = $false
}
if (Test-Path $MapPath) {
  $map = Get-Content $MapPath -Raw -ErrorAction SilentlyContinue
  if ($map -match "onSubAgentSwarm") { $mapHits.onSubAgentSwarm = $true }
  if ($map -match "resolveSwarmModelOrchPlan") { $mapHits.resolveSwarmModelOrchPlan = $true }
  if ($map -match "executeSwarm") { $mapHits.executeSwarm = $true }
}
WLog ("MAP_LINKED on={0} resolve={1} exec={2}" -f $mapHits.onSubAgentSwarm,$mapHits.resolveSwarmModelOrchPlan,$mapHits.executeSwarm)

Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | ForEach-Object {
  WLog "KILL_PRIOR pid=$($_.Id)"
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

$env:RAWRXD_SWARM_N = "16"
$env:RAWRXD_SWARM_MAX_PARALLEL = "4"
$env:RAWRXD_GUI = "1"
Remove-Item Env:RAWRXD_HEADLESS -ErrorAction SilentlyContinue

WLog "LAUNCH tip GUI"
$p = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
  -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr `
  -PassThru -WindowStyle Normal
WLog "PID=$($p.Id)"

$hwnd = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(45)
while ((Get-Date) -lt $deadline) {
  if ($p.HasExited) {
    WLog ("FAIL_CLOSED: early exit code={0}" -f $p.ExitCode)
    break
  }
  $hwnd = [TipSwarmInvokeB]::FindMainByPid([uint32]$p.Id, $ClassName)
  if ($hwnd -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 250
}

WLog ("MAIN_HWND=0x{0:X}" -f $hwnd.ToInt64())
$invoked = 0
$onHit = "NOT_RUN"; $resolveHit = "NOT_RUN"; $execHit = "NOT_RUN"

if ($hwnd -eq [IntPtr]::Zero) {
  WLog "WINDOW_NOT_FOUND INVOKED=NOT_RUN"
} else {
  $ok = [TipSwarmInvokeB]::PostMessageW($hwnd, [uint32]$WM_COMMAND, [IntPtr]$IDM_SUBAGENT_SWARM, [IntPtr]::Zero)
  WLog ("PostMessageW WM_COMMAND 4111 ok={0}" -f $ok)
  Start-Sleep -Seconds 8
  $errText = ""
  if (Test-Path $Stderr) { $errText = Get-Content $Stderr -Raw -ErrorAction SilentlyContinue }
  $outText = ""
  if (Test-Path $Stdout) { $outText = Get-Content $Stdout -Raw -ErrorAction SilentlyContinue }
  $blob = "$errText`n$outText"
  if ($blob -match "onSubAgentSwarm|IDM_SUBAGENT_SWARM|HexMag Swarm|executeSwarm") {
    $invoked = 1
    if ($blob -match "onSubAgentSwarm") { $onHit = "HIT" }
    if ($blob -match "resolveSwarmModelOrchPlan") { $resolveHit = "HIT" }
    if ($blob -match "executeSwarm") { $execHit = "HIT" }
  }
  # Fail-closed: PostMessage alone != INVOKED without ODS/UI witness
  if ($invoked -eq 0) {
    WLog "PostMessage delivered but no orch witness — INVOKED=0 (fail-closed)"
  }
}

@"
PATH=B_GUI
N=16
HISTORICAL_SHA=$HistoricalSha
TIP_SHA=$sha
TIP_REBUILD=$rebuilt
SOURCE_WIRED=1
LINKED=$(if($mapHits.onSubAgentSwarm -and $mapHits.resolveSwarmModelOrchPlan -and $mapHits.executeSwarm){'1'}else{'0'})
MAIN_HWND=0x$('{0:X}' -f $hwnd.ToInt64())
IDM_SUBAGENT_SWARM=4111
onSubAgentSwarm=$onHit
resolveSwarmModelOrchPlan=$resolveHit
executeSwarm=$execHit
INVOKED=$invoked
RUNTIME_REACHED=$(if($invoked -eq 1){'1'}else{'0'})
RUNTIME_PASS=0
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
"@ | Set-Content $Summary

WLog ("DISPOSITION INVOKED={0} on={1} resolve={2} exec={3}" -f $invoked,$onHit,$resolveHit,$execHit)
WLog "END SWARM_16_RUNTIME_002_PATH_B"
exit 0
