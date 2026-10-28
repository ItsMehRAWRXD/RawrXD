# SWARM_16_RUNTIME_001 - tip EXE GUI WM_COMMAND invoke (NO binary modify)
# IDM_SUBAGENT_SWARM=4111 -> onSubAgentSwarm (Win32IDE_SubAgent.cpp.obj LINKED)
# PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 FAIL_CLOSED
$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\SWARM_16_RUNTIME_001"
$TipExe = "G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe"
$ExpectedSha = "6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2"
$MapPath = "G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.map"
$IDM_SUBAGENT_SWARM = 4111
$WM_COMMAND = 0x0111
$ClassName = "RawrXD_IDE_MainWindow"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Log = Join-Path $OutDir "RUNLOG.txt"
$Stdout = Join-Path $OutDir "tip_gui_stdout.log"
$Stderr = Join-Path $OutDir "tip_gui_stderr.log"
$UiDump = Join-Path $OutDir "ui_text_dump.txt"
$Pre = Join-Path $OutDir "probe_pre.txt"
$Post = Join-Path $OutDir "probe_post.txt"
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
public class TipSwarmInvoke {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindowW(string c, string t);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
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
  public static string DumpUi(IntPtr root, uint pid) {
    var bag = new List<string>();
    EnumProc childCb = (h, l) => {
      var cls = new StringBuilder(128);
      var txt = new StringBuilder(8192);
      GetClassNameW(h, cls, 128);
      GetWindowTextW(h, txt, 8192);
      string t = txt.ToString();
      if (t.Length > 0) {
        if (t.Length > 800) t = t.Substring(0, 800);
        bag.Add(cls.ToString() + "|" + t);
      }
      return true;
    };
    if (root != IntPtr.Zero) EnumChildWindows(root, childCb, IntPtr.Zero);
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var cls = new StringBuilder(128);
      var txt = new StringBuilder(1024);
      GetClassNameW(h, cls, 128);
      GetWindowTextW(h, txt, 1024);
      string t = txt.ToString();
      if (t.Length > 0) bag.Add("TOP:" + cls.ToString() + "|" + t);
      return true;
    }, IntPtr.Zero);
    return string.Join("\n", bag);
  }
}
'@
Add-Type -TypeDefinition $cs -Language CSharp

WLog "START SWARM_16_RUNTIME_001"
WLog "PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 NO_BINARY_MODIFY=1"

if (-not (Test-Path $TipExe)) { WLog "FAIL_CLOSED: EXE missing"; exit 2 }
$obsSha = (Get-FileHash -Path $TipExe -Algorithm SHA256).Hash
$shaMatch = ($obsSha -eq $ExpectedSha)
WLog ("TIP_EXE=" + $TipExe)
WLog ("TIP_SHA_EXPECTED=" + $ExpectedSha)
WLog ("TIP_SHA_OBSERVED=" + $obsSha)
WLog ("TIP_SHA_MATCH=" + $shaMatch)
if (-not $shaMatch) { WLog "FAIL_CLOSED: tip SHA mismatch"; exit 3 }

$mapOn = $false; $mapResolve = $false; $mapExec = $false; $mapEnum = $false
if (Test-Path $MapPath) {
  $mapOn = [bool](Select-String -Path $MapPath -Pattern '\?onSubAgentSwarm@Win32IDE@@QEAAXXZ' | Where-Object { $_.Line -match 'Win32IDE_SubAgent' } | Select-Object -First 1)
  $mapResolve = [bool](Select-String -Path $MapPath -Pattern 'resolveSwarmModelOrchPlan@Win32App' | Select-Object -First 1)
  $mapExec = [bool](Select-String -Path $MapPath -Pattern '\?executeSwarm@SubAgentManager@@' | Select-Object -First 1)
  $mapEnum = [bool](Select-String -Path $MapPath -Pattern 'enumerateSwarmModelCandidates@Win32App' | Select-Object -First 1)
}
$preUtc = (Get-Date).ToUniversalTime().ToString("o")
@(
  ("TIP_PROBE_PRE_UTC=" + $preUtc),
  ("EXE=" + $TipExe),
  ("OBSERVED_SHA=" + $obsSha),
  ("EXPECTED_SHA=" + $ExpectedSha),
  ("SHA_MATCH=" + $shaMatch),
  ("MAP_onSubAgentSwarm_SubAgent=" + $mapOn),
  ("MAP_resolveSwarmModelOrchPlan=" + $mapResolve),
  ("MAP_executeSwarm_SubAgentManager=" + $mapExec),
  ("MAP_enumerateSwarmModelCandidates=" + $mapEnum),
  ("IDM_SUBAGENT_SWARM=" + $IDM_SUBAGENT_SWARM),
  "INVOKE=PostMessageW WM_COMMAND",
  "RAWRXD_SWARM_N=16",
  "RAWRXD_SWARM_MAX_PARALLEL=4",
  "RAWRXD_SWARM_SEQUENTIAL=0",
  "PROMOTE=0"
) -join "`n" | Set-Content $Pre
WLog ("MAP_LINKED on=" + $mapOn + " resolve=" + $mapResolve + " exec=" + $mapExec + " enum=" + $mapEnum)

Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | ForEach-Object {
  WLog ("KILL_PRIOR pid=" + $_.Id)
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

$env:RAWRXD_SWARM_N = "16"
$env:RAWRXD_SWARM_MAX_PARALLEL = "4"
$env:RAWRXD_SWARM_SEQUENTIAL = "0"
Remove-Item Env:LOCAL_ONLY_NO_OLLAMA -ErrorAction SilentlyContinue

WLog "LAUNCH tip GUI"
# Redirect can break GUI CreateProcess on some hosts; launch without redirect, capture UI text instead.
$proc = Start-Process -FilePath $TipExe -WorkingDirectory $OutDir -PassThru -WindowStyle Normal
WLog ("PID=" + $proc.Id)
Set-Content -Path $Stdout -Value "REDIRECT_SKIPPED=1 GUI_MODE=1"
Set-Content -Path $Stderr -Value "REDIRECT_SKIPPED=1 GUI_MODE=1"

$hwnd = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) {
    WLog ("FAIL_CLOSED: early exit code=" + $proc.ExitCode)
    break
  }
  $hwnd = [TipSwarmInvoke]::FindMainByPid([uint32]$proc.Id, $ClassName)
  if ($hwnd -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 500
}
WLog ("HWND=" + $hwnd)
$windowFound = ($hwnd -ne [IntPtr]::Zero -and [TipSwarmInvoke]::IsWindow($hwnd))
$posted = $false
if ($windowFound) {
  Start-Sleep -Seconds 5
  $posted = [TipSwarmInvoke]::PostMessageW($hwnd, [uint32]$WM_COMMAND, [IntPtr]$IDM_SUBAGENT_SWARM, [IntPtr]::Zero)
  WLog ("PostMessageW WM_COMMAND id=" + $IDM_SUBAGENT_SWARM + " result=" + $posted)
} else {
  WLog "WINDOW_NOT_FOUND INVOKED=NOT_RUN"
}

Start-Sleep -Seconds 15

$uiText = ""
if ($windowFound) { $uiText = [TipSwarmInvoke]::DumpUi($hwnd, [uint32]$proc.Id) }
Set-Content -Path $UiDump -Value $uiText -Encoding UTF8

$allEvidence = [string]$uiText
$hitStart = $allEvidence -match "Starting HexMag swarm|HexMag swarm N="
$hitFailInv = $allEvidence -match "FAIL_CLOSED: swarm model inventory empty"
$hitNoEditor = $allEvidence -match "No editor content for swarm input"
$hitBridge = $allEvidence -match "SubAgentManager not initialized|agent bridge unavailable"
$hitComplete = $allEvidence -match "Swarm complete|Swarm FAIL_CLOSED: empty merge"
$hitOnLog = $allEvidence -match "onSubAgentSwarm"

$onInvoked = "NOT_RUN"
$resolveInvoked = "NOT_RUN"
$execInvoked = "NOT_RUN"
$runtimePass = 0

if ($posted -and $windowFound) {
  if ($hitOnLog -or $hitStart -or $hitFailInv -or $hitNoEditor -or $hitBridge -or $hitComplete) {
    $onInvoked = "INVOKED"
  } else {
    $onInvoked = "POSTED_UNWITNESSED"
  }
}
if ($hitFailInv -or $hitStart -or $hitNoEditor) {
  $resolveInvoked = "INVOKED"
  $onInvoked = "INVOKED"
}
if ($hitStart -or $hitComplete) { $execInvoked = "INVOKED" }

$alive = -not $proc.HasExited
$postUtc = (Get-Date).ToUniversalTime().ToString("o")
@(
  ("TIP_PROBE_POST_UTC=" + $postUtc),
  ("PID=" + $proc.Id),
  ("PROCESS_ALIVE=" + $alive),
  ("WINDOW_FOUND=" + $windowFound),
  ("HWND=" + $hwnd),
  ("POSTMESSAGE_OK=" + $posted),
  ("IDM_SUBAGENT_SWARM=" + $IDM_SUBAGENT_SWARM),
  ("HIT_onSubAgentSwarm_LOG=" + $hitOnLog),
  ("HIT_START_BANNER=" + $hitStart),
  ("HIT_FAIL_INVENTORY=" + $hitFailInv),
  ("HIT_NO_EDITOR=" + $hitNoEditor),
  ("HIT_BRIDGE_UNAVAIL=" + $hitBridge),
  ("HIT_COMPLETE_OR_EMPTY=" + $hitComplete),
  ("onSubAgentSwarm=" + $onInvoked),
  ("resolveSwarmModelOrchPlan=" + $resolveInvoked),
  ("executeSwarm=" + $execInvoked),
  ("RUNTIME_PASS=" + $runtimePass),
  "RAWRXD_SWARM_N=16",
  "RAWRXD_SWARM_MAX_PARALLEL=4",
  "NOTE_QUEUED_NE_PARALLEL=maxParallel_cap_4_with_N16_slots__16_slots_neq_16_resident",
  ("SHA_STILL=" + $obsSha),
  "PROMOTE=0"
) -join "`n" | Set-Content $Post

WLog ("DISPOSITION on=" + $onInvoked + " resolve=" + $resolveInvoked + " exec=" + $execInvoked + " RUNTIME_PASS=" + $runtimePass)

if (-not $proc.HasExited) {
  WLog ("STOP tip PID=" + $proc.Id)
  Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 2
}
WLog "END SWARM_16_RUNTIME_001"
exit 0
