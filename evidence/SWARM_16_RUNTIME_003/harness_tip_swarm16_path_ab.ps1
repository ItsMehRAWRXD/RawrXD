# SWARM_16_RUNTIME_003 — tip 748B Path A (/api/swarm/orch) + Path B (GUI WM_COMMAND 4111)
# PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 NO_INVENT_PASS=1 REBUILD=0 GhostText absorb NOT_AUTHORIZED
$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\SWARM_16_RUNTIME_003"
$Logs = Join-Path $OutDir "logs"
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$TipExe = "G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe"
$ExpectSha = "748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145"
$Port = 18961
$Log = Join-Path $OutDir "RUNLOG.txt"
Set-Content $Log ""

function WLog([string]$m) {
  $line = "[{0}] {1}" -f (Get-Date -Format "o"), $m
  Add-Content $Log $line
  Write-Output $line
}

function Wait-PortReady($Proc, [int]$Seconds = 120) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) {
    if ($Proc.HasExited) { return $false }
    if (netstat -ano | Select-String ":$Port\s+.*LISTENING") { return $true }
    Start-Sleep -Milliseconds 400
  }
  return $false
}

function Invoke-Orch([hashtable]$Headers, [hashtable]$Body, [string]$Tag, [int]$TimeoutSec = 600) {
  $json = ($Body | ConvertTo-Json -Compress -Depth 6)
  $uri = "http://127.0.0.1:$Port/api/swarm/orch"
  $code = -1; $respBody = ""
  try {
    $resp = Invoke-WebRequest -Uri $uri -Method POST -Body ([Text.Encoding]::UTF8.GetBytes($json)) `
      -ContentType "application/json; charset=utf-8" -Headers $Headers -TimeoutSec $TimeoutSec -UseBasicParsing
    $code = [int]$resp.StatusCode
    $respBody = [string]$resp.Content
  } catch {
    if ($_.Exception.Response) {
      $code = [int]$_.Exception.Response.StatusCode.value__
      try {
        $reader = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
        $respBody = $reader.ReadToEnd()
      } catch { $respBody = $_.Exception.Message }
    } else { $respBody = $_.Exception.Message }
  }
  $json | Set-Content (Join-Path $Logs ("orch_${Tag}_req.json"))
  $code | Set-Content (Join-Path $Logs ("orch_${Tag}_code.txt"))
  $respBody | Set-Content (Join-Path $Logs ("orch_${Tag}_body.json"))
  return @{ code = $code; body = $respBody }
}

$sha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
$sha | Set-Content (Join-Path $Logs "exe_sha.txt")
WLog "START SWARM_16_RUNTIME_003 TIP_SHA=$sha MATCH=$([int]($sha -eq $ExpectSha))"
if ($sha -ne $ExpectSha) {
  WLog "FAIL_CLOSED: tip SHA mismatch vs freeze authority"
  @"
PATH=A+B
TIP_SHA=$sha
EXPECTED=$ExpectSha
SHA_MATCH=0
RUNTIME_PASS=0
PROMOTE=0
"@ | Set-Content (Join-Path $OutDir "SUMMARY.txt")
  exit 2
}

Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | ForEach-Object {
  WLog "KILL_PRIOR pid=$($_.Id)"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep 2

# ---------- PATH A: headless orch ----------
$key = "swarm16-748b-" + [guid]::NewGuid().ToString("N").Substring(0, 12)
$env:RAWRXD_HOSTED_API_KEY = $key
$env:RAWRXD_HOSTED_API_SCOPES = "read,inference,models,github,admin,*"
$env:RAWRXD_HEADLESS = "1"
$env:LOCAL_ONLY = "1"
$env:RAWRXD_SWARM_N = "16"
$env:RAWRXD_SWARM_MAX_PARALLEL = "4"
$env:RAWRXD_MODELS = "G:\~dev\rawrxd\models"
$env:RAWRXD_SWARM_MODEL_DIR = "G:\~dev\rawrxd\models"
Remove-Item Env:RAWRXD_SWARM_SEQUENTIAL -ErrorAction SilentlyContinue
Remove-Item Env:LOCAL_ONLY_NO_OLLAMA -ErrorAction SilentlyContinue

WLog "PATH_A launch headless port=$Port"
$pA = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
  -ArgumentList @("--headless","--local","--port","$Port","--bind","127.0.0.1","--dir","G:\~dev\rawrxd") `
  -RedirectStandardOutput (Join-Path $Logs "path_a_out.txt") `
  -RedirectStandardError (Join-Path $Logs "path_a_err.txt") `
  -PassThru -WindowStyle Hidden
$ready = Wait-PortReady $pA 120
WLog "PATH_A READY=$ready PID=$($pA.Id) EXITED=$($pA.HasExited)"
"PID=$($pA.Id) READY=$ready EXITED=$($pA.HasExited)" | Set-Content (Join-Path $Logs "path_a_meta.txt")

$auth = @{ "X-Api-Key" = $key; "Origin" = "http://127.0.0.1:$Port" }
$pathA_parallel = @{ code = -1; body = "" }
$pathA_seq = @{ code = -1; body = "" }
$pathA_cancel = @{ code = -1; body = "" }

if ($ready) {
  $snippet = "int main(){ /* swarm16 orch probe */ return 0; }`n"
  WLog "PATH_A POST parallel n=16 maxParallel via env"
  $pathA_parallel = Invoke-Orch $auth @{ n = 16; input = $snippet; cleanup = $true } "parallel" 900
  WLog ("PATH_A parallel HTTP={0} bytes={1}" -f $pathA_parallel.code, $pathA_parallel.body.Length)

  # sequential chain
  $env:RAWRXD_SWARM_SEQUENTIAL = "1"
  # note: process already running — sequential must be requested via body if supported; re-post with n=4
  # Tip resolveSwarmModelOrchPlan reads env of the server process; restart for sequential.
  if (-not $pA.HasExited) { Stop-Process -Id $pA.Id -Force -ErrorAction SilentlyContinue }
  Start-Sleep 2
  $pA = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
    -ArgumentList @("--headless","--local","--port","$Port","--bind","127.0.0.1","--dir","G:\~dev\rawrxd") `
    -RedirectStandardOutput (Join-Path $Logs "path_a_seq_out.txt") `
    -RedirectStandardError (Join-Path $Logs "path_a_seq_err.txt") `
    -PassThru -WindowStyle Hidden
  $ready = Wait-PortReady $pA 120
  WLog "PATH_A_SEQ READY=$ready"
  if ($ready) {
    $pathA_seq = Invoke-Orch $auth @{ n = 4; input = $snippet; cleanup = $true } "sequential" 900
    WLog ("PATH_A sequential HTTP={0} bytes={1}" -f $pathA_seq.code, $pathA_seq.body.Length)
    $pathA_cancel = Invoke-Orch $auth @{ n = 4; input = $snippet; cleanup = $true; cancelAfterMs = 50 } "cancel" 120
    WLog ("PATH_A cancel HTTP={0} bytes={1}" -f $pathA_cancel.code, $pathA_cancel.body.Length)
  }
} else {
  WLog "PATH_A FAIL_CLOSED: port not ready"
}

if ($null -ne $pA -and -not $pA.HasExited) { Stop-Process -Id $pA.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep 2
Remove-Item Env:RAWRXD_SWARM_SEQUENTIAL -ErrorAction SilentlyContinue

# Parse Path A parallel disposition
$paPass = 0; $paReached = 0; $paModels = @(); $paDisp = "NOT_RUN"
try {
  $j = $pathA_parallel.body | ConvertFrom-Json
  if ($j.RUNTIME_PASS -eq $true) { $paPass = 1 }
  if ($j.RUNTIME_REACHED -eq $true) { $paReached = 1 }
  if ($j.models) { $paModels = @($j.models) }
  if ($j.disposition) { $paDisp = [string]$j.disposition }
} catch { $paDisp = "PARSE_FAIL" }

$seqPass = 0; $seqReached = 0; $seqModels = @(); $seqDisp = "NOT_RUN"
try {
  $j2 = $pathA_seq.body | ConvertFrom-Json
  if ($j2.RUNTIME_PASS -eq $true) { $seqPass = 1 }
  if ($j2.RUNTIME_REACHED -eq $true) { $seqReached = 1 }
  if ($j2.models) { $seqModels = @($j2.models) }
  if ($j2.disposition) { $seqDisp = [string]$j2.disposition }
} catch { if ($pathA_seq.code -gt 0) { $seqDisp = "PARSE_FAIL" } }

# ---------- PATH B: GUI + ODS + editor seed ----------
WLog "PATH_B GUI launch"
Remove-Item Env:RAWRXD_HEADLESS -ErrorAction SilentlyContinue
$env:RAWRXD_GUI = "1"
$env:RAWRXD_SWARM_N = "16"
$env:RAWRXD_SWARM_MAX_PARALLEL = "4"
$env:RAWRXD_MODELS = "G:\~dev\rawrxd\models"

$cs = @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class Swarm16TipB {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool EnumChildWindows(IntPtr p, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var cls = new StringBuilder(256);
      GetClassNameW(h, cls, 256);
      if (cls.ToString() == "RawrXD_IDE_MainWindow") { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static List<string> DumpChildren(IntPtr main) {
    var lines = new List<string>();
    EnumChildWindows(main, (h, l) => {
      var cls = new StringBuilder(256); GetClassNameW(h, cls, 256);
      var txt = new StringBuilder(4096); GetWindowTextW(h, txt, 4096);
      string t = txt.ToString();
      if (t.Length > 0 || cls.ToString().IndexOf("Edit", StringComparison.OrdinalIgnoreCase) >= 0
          || cls.ToString().IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) >= 0) {
        if (t.Length > 200) t = t.Substring(0, 200);
        lines.Add(cls.ToString() + "|" + t.Replace("\r"," ").Replace("\n"," "));
      }
      // seed any large rich edit / edit that looks like editor
      string c = cls.ToString();
      if (c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) >= 0 || c == "Edit") {
        int len = GetWindowTextW(h, new StringBuilder(8), 8);
        if (len < 8) SetWindowTextW(h, "int main(){ /* swarm16 path B seed */ return 0; }\n");
      }
      return true;
    }, IntPtr.Zero);
    return lines;
  }
  public static string ScrapeText(IntPtr main) {
    var sb = new StringBuilder();
    EnumChildWindows(main, (h, l) => {
      var txt = new StringBuilder(8192);
      GetWindowTextW(h, txt, 8192);
      if (txt.Length > 0) { sb.AppendLine(txt.ToString()); }
      return true;
    }, IntPtr.Zero);
    return sb.ToString();
  }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

$pB = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
  -RedirectStandardOutput (Join-Path $Logs "path_b_out.txt") `
  -RedirectStandardError (Join-Path $Logs "path_b_err.txt") `
  -PassThru -WindowStyle Normal
WLog "PATH_B PID=$($pB.Id)"
$hwnd = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
  if ($pB.HasExited) { WLog ("PATH_B early exit={0}" -f $pB.ExitCode); break }
  $hwnd = [Swarm16TipB]::FindMain([uint32]$pB.Id)
  if ($hwnd -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 250
}
WLog ("PATH_B MAIN_HWND=0x{0:X}" -f $hwnd.ToInt64())

$pbPost = 0; $pbInvoked = 0; $pbUiHit = "NOT_OBSERVED"
if ($hwnd -ne [IntPtr]::Zero) {
  $kids = [Swarm16TipB]::DumpChildren($hwnd)
  $kids | Set-Content (Join-Path $Logs "path_b_children_pre.txt")
  Start-Sleep 1
  $ok = [Swarm16TipB]::PostMessageW($hwnd, [uint32]0x0111, [IntPtr]4111, [IntPtr]::Zero)
  $pbPost = [int]$ok
  WLog "PATH_B PostMessage 4111 ok=$ok"
  Start-Sleep 12
  $ui = [Swarm16TipB]::ScrapeText($hwnd)
  $ui | Set-Content (Join-Path $Logs "path_b_ui_scrape.txt")
  $err = ""; if (Test-Path (Join-Path $Logs "path_b_err.txt")) { $err = Get-Content (Join-Path $Logs "path_b_err.txt") -Raw }
  $out = ""; if (Test-Path (Join-Path $Logs "path_b_out.txt")) { $out = Get-Content (Join-Path $Logs "path_b_out.txt") -Raw }
  $blob = "$ui`n$err`n$out"
  if ($blob -match "onSubAgentSwarm|HexMag swarm|FAIL_CLOSED: swarm model|No editor content|SubAgentManager not initialized|SubAgent Swarm") {
    $pbInvoked = 1
    $pbUiHit = "HIT"
  }
}
if (-not $pB.HasExited) { Stop-Process -Id $pB.Id -Force -ErrorAction SilentlyContinue }

# ---------- Seal summary ----------
$modelsList = ($paModels + $seqModels | Select-Object -Unique) -join ","
$orchPass = [int](($paPass -eq 1) -or ($seqPass -eq 1))
# Fail-closed: product RUNTIME_PASS requires Path A orch JSON RUNTIME_PASS or honest Path B orch UI+execute.
# Path B PostMessage alone never invents PASS.
$runtimePass = $orchPass
$disposition = if ($runtimePass -eq 1) { "RUNTIME_PASS" } elseif ($paReached -eq 1 -or $seqReached -eq 1) { "RUNTIME_REACHED_PARTIAL" } elseif ($pathA_parallel.code -gt 0 -or $pbPost -eq 1) { "FAIL_CLOSED_INVOKED_NO_PASS" } else { "FAIL_CLOSED_NOT_REACHED" }

@"
GATE=SWARM_16_RUNTIME_003
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))
TIP_EXE=$TipExe
TIP_SHA=$sha
SHA_MATCH=1
GHOSTTEXT_ABSORB=NOT_AUTHORIZED
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
PATH_A_HTTP_PARALLEL=$($pathA_parallel.code)
PATH_A_DISP_PARALLEL=$paDisp
PATH_A_RUNTIME_REACHED_PARALLEL=$paReached
PATH_A_RUNTIME_PASS_PARALLEL=$paPass
PATH_A_HTTP_SEQUENTIAL=$($pathA_seq.code)
PATH_A_DISP_SEQUENTIAL=$seqDisp
PATH_A_RUNTIME_REACHED_SEQUENTIAL=$seqReached
PATH_A_RUNTIME_PASS_SEQUENTIAL=$seqPass
PATH_A_MODELS=$modelsList
PATH_B_MAIN_HWND=0x$('{0:X}' -f $hwnd.ToInt64())
PATH_B_POSTMESSAGE_4111=$pbPost
PATH_B_UI_ORCH_WITNESS=$pbUiHit
PATH_B_INVOKED_OBSERVED=$pbInvoked
ORCH_DISPOSITION=$disposition
RUNTIME_PASS=$runtimePass
MODELS_EXERCISED=$modelsList
NOTE=GhostText B421 absorb NOT_AUTHORIZED; tip authority remains 748B freeze
"@ | Set-Content (Join-Path $OutDir "SUMMARY.txt")

WLog "DISPOSITION=$disposition RUNTIME_PASS=$runtimePass PROMOTE=0"
WLog "END SWARM_16_RUNTIME_003"
exit 0
