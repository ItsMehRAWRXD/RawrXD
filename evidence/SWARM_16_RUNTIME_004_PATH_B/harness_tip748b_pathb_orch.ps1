# SWARM_16_RUNTIME_004_PATH_B — tip 748B PathB orch RUNTIME (GUI WM_COMMAND 4111)
# AUTHORITY: TIP_FREEZE_001\bin only. REBUILD=0. ABSORB=NOT_AUTHORIZED. PROMOTE=0.
# Fail-closed: PostMessage alone != orch RUNTIME_REACHED.
$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\SWARM_16_RUNTIME_004_PATH_B"
$Logs = Join-Path $OutDir "logs"
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$TipExe = "G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe"
$TipDir = Split-Path $TipExe
$ExpectSha = "748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145"
$IDM = 4111
$WM_COMMAND = 0x0111
$Log = Join-Path $OutDir "RUNLOG.txt"
Set-Content $Log ""

function WLog([string]$m) {
  $line = "[{0}] {1}" -f (Get-Date -Format "o"), $m
  Add-Content $Log $line
  Write-Output $line
}

$cs = @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class PathB748 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool EnumChildWindows(IntPtr p, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageTimeoutW(
    IntPtr h, uint Msg, IntPtr wParam, IntPtr lParam, uint flags, uint timeout, out IntPtr result);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr GetPropW(IntPtr h, string name);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  const uint SMTO_ABORTIFHUNG = 0x0002;
  const uint WM_SETTEXT = 0x000C;
  const uint EM_REPLACESEL = 0x00C2;
  const uint EM_SETSEL = 0x00B1;
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
  public static bool MenuReady(IntPtr main) {
    return GetPropW(main, "RawrXD.MainMenuReady") != IntPtr.Zero;
  }
  public static int SeedEditor(IntPtr main, string text) {
    int seeded = 0;
    EnumChildWindows(main, (h, l) => {
      var cls = new StringBuilder(256);
      GetClassNameW(h, cls, 256);
      string c = cls.ToString();
      bool ed = c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) >= 0
             || c.IndexOf("Scintilla", StringComparison.OrdinalIgnoreCase) >= 0
             || c == "Edit"
             || c.IndexOf("RAWRXD_EDITOR", StringComparison.OrdinalIgnoreCase) >= 0;
      if (!ed) return true;
      if (!IsWindowVisible(h)) return true;
      SendMessageW(h, EM_SETSEL, (IntPtr)0, (IntPtr)(-1));
      var bytes = Encoding.Unicode.GetBytes(text + "\0");
      GCHandle gch = GCHandle.Alloc(bytes, GCHandleType.Pinned);
      try {
        SendMessageW(h, EM_REPLACESEL, (IntPtr)1, gch.AddrOfPinnedObject());
      } finally { gch.Free(); }
      SetWindowTextW(h, text);
      seeded++;
      return true;
    }, IntPtr.Zero);
    return seeded;
  }
  public static string Scrape(IntPtr main) {
    var sb = new StringBuilder();
    EnumChildWindows(main, (h, l) => {
      var cls = new StringBuilder(128); GetClassNameW(h, cls, 128);
      var txt = new StringBuilder(4096); GetWindowTextW(h, txt, 4096);
      if (txt.Length > 0) sb.AppendLine(cls + "|" + txt);
      return true;
    }, IntPtr.Zero);
    return sb.ToString();
  }
  public static int Post4111(IntPtr h) {
    return PostMessageW(h, 0x0111, (IntPtr)4111, IntPtr.Zero) ? 1 : 0;
  }
  public static int Send4111(IntPtr h, uint timeoutMs, out long result, out int timedOut) {
    IntPtr r = IntPtr.Zero;
    IntPtr ok = SendMessageTimeoutW(h, 0x0111, (IntPtr)4111, IntPtr.Zero, SMTO_ABORTIFHUNG, timeoutMs, out r);
    result = r.ToInt64();
    timedOut = (ok == IntPtr.Zero) ? 1 : 0;
    return (ok != IntPtr.Zero) ? 1 : 0;
  }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

$sha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
$sha | Set-Content (Join-Path $Logs "exe_sha.txt")
WLog "START SWARM_16_RUNTIME_004_PATH_B TIP_SHA=$sha MATCH=$([int]($sha -eq $ExpectSha))"
if ($sha -ne $ExpectSha) {
  @"
GATE=SWARM_16_RUNTIME_004_PATH_B
SHA_MATCH=0
RUNTIME_REACHED=0
RUNTIME_PASS=0
PROMOTE=0
ROOT_CAUSE=TIP_SHA_MISMATCH
"@ | Set-Content (Join-Path $OutDir "SUMMARY.txt")
  exit 2
}

Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | ForEach-Object {
  WLog "KILL_PRIOR pid=$($_.Id)"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep 2

# Clear prior breadcrumbs under tip module dir
$crumbDir = Join-Path $TipDir "evidence\P1_UI_MENU_E2E_001"
New-Item -ItemType Directory -Force -Path $crumbDir | Out-Null
$crumb = Join-Path $crumbDir "CMD_BREADCRUMB.txt"
if (Test-Path $crumb) { Remove-Item $crumb -Force -ErrorAction SilentlyContinue }

$env:RAWRXD_P1_CMD_DIAG = "1"
$env:RAWRXD_GUI = "1"
$env:RAWRXD_SWARM_N = "16"
$env:RAWRXD_SWARM_MAX_PARALLEL = "4"
$env:RAWRXD_MODELS = "G:\~dev\rawrxd\models"
$env:RAWRXD_SWARM_MODEL_DIR = "G:\~dev\rawrxd\models"
$env:LOCAL_ONLY = "1"
Remove-Item Env:RAWRXD_HEADLESS -ErrorAction SilentlyContinue
Remove-Item Env:LOCAL_ONLY_NO_OLLAMA -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_SWARM_SEQUENTIAL -ErrorAction SilentlyContinue

# NO stdout/stderr redirect — prior RUNTIME_003 PostMessage=0 with redirect.
WLog "LAUNCH tip GUI cwd=$TipDir NO_REDIRECT=1"
$p = Start-Process -FilePath $TipExe -WorkingDirectory $TipDir -PassThru -WindowStyle Normal
WLog "PID=$($p.Id)"

$hwnd = [IntPtr]::Zero
$menuReady = $false
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
  if ($p.HasExited) { WLog ("EARLY_EXIT code={0}" -f $p.ExitCode); break }
  $hwnd = [PathB748]::FindMain([uint32]$p.Id)
  if ($hwnd -ne [IntPtr]::Zero) {
    $menuReady = [PathB748]::MenuReady($hwnd)
    if ($menuReady) { break }
  }
  Start-Sleep -Milliseconds 250
}
WLog ("MAIN_HWND=0x{0:X} MENU_READY={1}" -f $hwnd.ToInt64(), [int]$menuReady)

$postOk = 0; $sendOk = 0; $sendTimedOut = 0; $sendResult = 0; $seeded = 0
$uiHit = "NOT_OBSERVED"; $crumbHit = "NOT_OBSERVED"; $logHit = "NOT_OBSERVED"
$onInv = "NOT_OBSERVED"; $resolveInv = "NOT_OBSERVED"; $execInv = "NOT_OBSERVED"
$runtimeReached = 0; $runtimePass = 0
$rootCause = "NOT_SET"

if ($hwnd -eq [IntPtr]::Zero) {
  $rootCause = "MAIN_HWND_ZERO"
} else {
  if (-not $menuReady) {
    WLog "WARN MENU_READY=0 after wait - still posting (fail-closed if no orch)"
  }
  Start-Sleep 2
  $seedText = 'int main(){ /* pathb swarm orch seed */ return 0; }' + "`n"
  $seeded = [PathB748]::SeedEditor($hwnd, $seedText)
  WLog "EDITOR_SEEDED_CONTROLS=$seeded"
  Start-Sleep 1

  $postOk = [PathB748]::Post4111($hwnd)
  WLog "POSTMESSAGE_4111=$postOk"
  Start-Sleep 2

  $sr = 0L; $to = 0
  $sendOk = [PathB748]::Send4111($hwnd, 15000, [ref]$sr, [ref]$to)
  $sendResult = $sr; $sendTimedOut = $to
  WLog "SENDMESSAGETIMEOUT_4111=$sendOk timedOut=$sendTimedOut result=$sendResult"

  # Wait for orch side-effects
  Start-Sleep 20

  $ui = [PathB748]::Scrape($hwnd)
  $ui | Set-Content (Join-Path $Logs "ui_scrape.txt") -Encoding UTF8

  $crumbText = ""
  if (Test-Path $crumb) {
    $crumbText = Get-Content $crumb -Raw -ErrorAction SilentlyContinue
    Copy-Item $crumb (Join-Path $Logs "CMD_BREADCRUMB.txt") -Force
  }
  $crumbText | Set-Content (Join-Path $Logs "crumb_copy.txt")

  # Tip IDE logs (newest)
  $ideLogs = @()
  $logDir = Join-Path $TipDir "logs"
  if (Test-Path $logDir) {
    Get-ChildItem $logDir -Filter "RawrXD_IDE_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 3 | ForEach-Object {
      $ideLogs += (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue)
      Copy-Item $_.FullName (Join-Path $Logs $_.Name) -Force -ErrorAction SilentlyContinue
    }
  }
  $audit = ""
  $auditPath = Join-Path $TipDir "rawrxd_audit.jsonl"
  if (Test-Path $auditPath) {
    $audit = Get-Content $auditPath -Tail 200 -ErrorAction SilentlyContinue | Out-String
    $audit | Set-Content (Join-Path $Logs "audit_tail.txt")
  }

  $nl = [Environment]::NewLine
  $blob = $ui + $nl + $crumbText + $nl + ($ideLogs -join $nl) + $nl + $audit
  $blob | Set-Content (Join-Path $Logs "witness_blob_head.txt")
  # Keep witness search compact
  if ($crumbText -match "id=4111") { $crumbHit = "HIT" }
  if ($blob -match "onSubAgentSwarm|Starting HexMag swarm|HexMag swarm N=") { $onInv = "OBSERVED"; $uiHit = "HIT" }
  if ($blob -match "resolveSwarmModelOrchPlan|FAIL_CLOSED: swarm model inventory") { $resolveInv = "OBSERVED"; $onInv = "OBSERVED" }
  if ($blob -match "executeSwarm|Swarm complete|Swarm FAIL_CLOSED|Starting HexMag swarm") { $execInv = "OBSERVED" }
  if ($blob -match "SubAgentManager not initialized|No editor content for swarm|agent bridge unavailable") {
    $onInv = "OBSERVED"
    $uiHit = "HIT"
  }
  if ($ideLogs -match "onSubAgentSwarm" -or $audit -match "onSubAgentSwarm") { $logHit = "HIT"; $onInv = "OBSERVED" }

  # RUNTIME_REACHED: orch handler entered (onSubAgentSwarm) OR resolve/execute witnessed on tip PathB
  if ($onInv -eq "OBSERVED" -or $resolveInv -eq "OBSERVED" -or $execInv -eq "OBSERVED") {
    $runtimeReached = 1
  }
  # RUNTIME_PASS requires executeSwarm completion with non-empty product merge — not invented here
  if ($execInv -eq "OBSERVED" -and $blob -match "Swarm complete") {
    $runtimePass = 0  # still require honest token/product — keep 0 unless clear PASS witness
  }

  if ($runtimeReached -eq 1) {
    $rootCause = "NONE_ORCH_REACHED"
  } elseif ($crumbHit -eq "HIT" -and $onInv -ne "OBSERVED") {
    $rootCause = "WM_COMMAND_4111_DISPATCHED_ORCH_HANDLER_UNWITNESSED"
  } elseif ($postOk -eq 1 -or $sendOk -eq 1) {
    if ($crumbHit -ne "HIT") {
      $rootCause = "MSG_QUEUED_OR_SENT_BUT_NO_CMD_DIAG_4111_BREADCRUMB"
    } else {
      $rootCause = "CMD_DIAG_SEEN_ORCH_NOT_OBSERVED"
    }
  } elseif ($sendTimedOut -eq 1) {
    $rootCause = "SENDMESSAGE_TIMEOUT_UI_THREAD_HUNG"
  } else {
    $rootCause = "POST_AND_SEND_FAILED"
  }
}

if (-not $p.HasExited) {
  WLog "STOP pid=$($p.Id)"
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep 2
}

$disposition = if ($runtimeReached -eq 1) { "PATH_B_RUNTIME_REACHED" } else { "FAIL_CLOSED_PATH_B_ORCH_NOT_REACHED" }

@"
GATE=SWARM_16_RUNTIME_004_PATH_B
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))
WORKSTREAM=G07_PATH_B_SWARM_RUNTIME
TOP10=3
AUTHORITY_EXE=$TipExe
TIP_SHA=$sha
SHA_MATCH=1
REBUILD_TIP=0
ABSORB=NOT_AUTHORIZED
GHOSTTEXT_B421=NOT_ATTRIBUTED
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
MAIN_HWND=0x$('{0:X}' -f $hwnd.ToInt64())
MENU_READY=$([int]$menuReady)
EDITOR_SEEDED_CONTROLS=$seeded
POSTMESSAGE_WM_COMMAND_4111=$postOk
SENDMESSAGETIMEOUT_WM_COMMAND_4111=$sendOk
SEND_TIMED_OUT=$sendTimedOut
SEND_RESULT=$sendResult
CMD_DIAG_4111=$crumbHit
IDE_LOG_onSubAgentSwarm=$logHit
UI_ORCH_WITNESS=$uiHit
onSubAgentSwarm=$onInv
resolveSwarmModelOrchPlan=$resolveInv
executeSwarm=$execInv
RUNTIME_REACHED=$runtimeReached
RUNTIME_PASS=$runtimePass
DISPOSITION=$disposition
ROOT_CAUSE=$rootCause
NOTE=Post/Send != orch E2E; PathA headless orch must not invent PathB PASS
NOTE2=SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS
"@ | Set-Content (Join-Path $OutDir "SUMMARY.txt")

WLog "DISPOSITION=$disposition RUNTIME_REACHED=$runtimeReached ROOT_CAUSE=$rootCause"
WLog "END SWARM_16_RUNTIME_004_PATH_B"
exit 0
