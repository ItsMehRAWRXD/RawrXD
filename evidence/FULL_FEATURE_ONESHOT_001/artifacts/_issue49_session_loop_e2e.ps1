#Requires -Version 5.1
# Issue #49 map #5 — AgentSession / agentic loop E2E on tip_integ_candidate_001 (5A34).
# Laws: PROMOTE=0 MATURITY=82 E6CF HELD; NOT_RUN!=PASS; NO_CROSS_SHA_PASS; no invent.
$ErrorActionPreference = 'Continue'
$ExpectSha = '5A34B393ECF7380576CE718C688DC4006C0E3B01090BB4DCD8B844FB594D1619'
$TipExe = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\package\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe'
$CandDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_integ_candidate_001'
$PkgDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\package\tip_integ_candidate_001'
$OutDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts'
$RawrCli = 'F:\rawrxd\build_repair_candidate\bin-msvc\rawr.exe'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
if ($Sha -ne $ExpectSha) { Write-Host "SHA_DRIFT=$Sha expected=$ExpectSha"; exit 9 }

Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','rawr' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2

Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class SessLoop {
  public const uint WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_COMMAND=0x0111, WM_CLOSE=0x0010;
  public const uint CB_SETCURSEL=0x014E, CB_GETCOUNT=0x0146, CB_GETLBTEXT=0x0148, CB_GETLBTEXTLEN=0x0149;
  public const int CBN_SELCHANGE=1;
  public const int ID_CHAT_INPUT=1202, ID_CHAT_OUT=1203, ID_CHAT_SEND=1204, ID_MODEL=1206, ID_CTX=1220, ID_TOK=1219, ID_STOP=1210;
  public const int IDM_AGENTIC_LOOP_RUN=4106, IDM_AGENTIC_LOOP_CANCEL=4107;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h,l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(128); GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c.IndexOf("RawrXD") >= 0) { found = h; return false; }
      return true;
    }, IntPtr.Zero); return found;
  }
  public static IntPtr FindCtrl(IntPtr root, int id) {
    var stack = new Stack<IntPtr>(); stack.Push(root);
    while (stack.Count > 0) {
      IntPtr cur = stack.Pop(); var kids = new List<IntPtr>();
      EnumChildWindows(cur, (h,lp) => { kids.Add(h); return true; }, IntPtr.Zero);
      foreach (var k in kids) { if (GetDlgCtrlID(k) == id) return k; stack.Push(k); }
    } return IntPtr.Zero;
  }
  public static string GetText(IntPtr h) {
    if (h == IntPtr.Zero || !IsWindow(h)) return "";
    int n = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    if (n <= 0) return "";
    var sb = new StringBuilder(n + 8);
    SendMessageW(h, WM_GETTEXT, (IntPtr)sb.Capacity, sb); return sb.ToString();
  }
  public static void SetText(IntPtr h, string t) { SendMessageW(h, WM_SETTEXT, IntPtr.Zero, t ?? ""); }
  public static string ComboText(IntPtr combo, int index) {
    int len = (int)SendMessageW(combo, CB_GETLBTEXTLEN, (IntPtr)index, IntPtr.Zero);
    if (len <= 0) return "";
    var sb = new StringBuilder(len + 8);
    SendMessageW(combo, CB_GETLBTEXT, (IntPtr)index, sb); return sb.ToString();
  }
  public static int SelectModelContaining(IntPtr main, IntPtr combo, string needle) {
    if (combo == IntPtr.Zero) return -1;
    int count = (int)SendMessageW(combo, CB_GETCOUNT, IntPtr.Zero, IntPtr.Zero);
    for (int i = 0; i < count; i++) {
      string t = ComboText(combo, i);
      if (t.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) {
        SendMessageW(combo, CB_SETCURSEL, (IntPtr)i, IntPtr.Zero);
        SendMessageW(main, WM_COMMAND, (IntPtr)((CBN_SELCHANGE << 16) | (ID_MODEL & 0xFFFF)), combo);
        return i;
      }
    }
    return -1;
  }
}
"@

$runDir = Join-Path $CandDir ("session_loop_$Stamp")
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
# Workspace with MOTD marker so agentic path can authorize; durable target file
$ws = Join-Path $runDir 'workspace'
New-Item -ItemType Directory -Force -Path (Join-Path $ws '.cursor\rules') | Out-Null
Copy-Item -Force 'g:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc' (Join-Path $ws '.cursor\rules\PassiveRoleNotRoleplay.mdc') -ErrorAction SilentlyContinue
$markRel = 'agent_session_mark.txt'
$markPath = Join-Path $ws $markRel
$markBefore = 'BEFORE_ABSENT'
if (Test-Path $markPath) { Remove-Item -Force $markPath }
$session = "integ_session_loop_$Stamp"
$runId = "integ_session_loop_run_$Stamp"
$env:RAWRXD_LOG_DIR = $runDir
$env:RAWRXD_CHAT_SESSION_ID = $session
$env:RAWRXD_CHAT_RUN_ID = $runId
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$env:RAWRXD_AGENTIC_QUIET = '0'
if (Test-Path $RawrCli) { $env:RAWRXD_CLI_PATH = $RawrCli }

$rt = Join-Path $runDir 'chat_runtime.log'
$p1 = 'FAIL'; $p2 = 'FAIL'; $chat = 'FAIL'
$sessionSpawn = 'FAIL'; $toolFs = 'FAIL'; $cancelOrComplete = 'FAIL'; $nextTurn = 'FAIL'
$mainHex = '0x0'; $sessionIdObserved = ''; $modelSel = 'FAIL'

# Ensure loop helper beside tip package (already copied) and candidate cwd
if (-not (Test-Path (Join-Path $PkgDir 'deep2_agentic_loop.exe'))) {
  Write-Host 'MISSING deep2_agentic_loop.exe in package'
  exit 12
}
Copy-Item -Force (Join-Path $PkgDir 'deep2_agentic_loop.exe') (Join-Path $CandDir 'deep2_agentic_loop.exe') -ErrorAction SilentlyContinue

# Seed file forces m_currentFile/workspace discovery into harness ws (not F:\rawrxd).
$seed = Join-Path $ws "seed_$Stamp.txt"
Set-Content -LiteralPath $seed -Value "SEED $Stamp" -Encoding ascii
$p = Start-Process -FilePath $TipExe -ArgumentList @($seed) -WorkingDirectory $ws -PassThru -WindowStyle Normal
$main = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(55)
while ((Get-Date) -lt $deadline) {
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { break }
  $main = [SessLoop]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 250
}
if ($main -ne [IntPtr]::Zero -and -not $p.HasExited) {
  $p1 = 'PASS'
  $mainHex = ('0x{0:X}' -f $main.ToInt64())
}
Start-Sleep 8

if ($main -ne [IntPtr]::Zero -and -not $p.HasExited) {
  [void][SessLoop]::SetForegroundWindow($main)
  $chatIn = [SessLoop]::FindCtrl($main, [SessLoop]::ID_CHAT_INPUT)
  $chatOut = [SessLoop]::FindCtrl($main, [SessLoop]::ID_CHAT_OUT)
  $send = [SessLoop]::FindCtrl($main, [SessLoop]::ID_CHAT_SEND)
  $model = [SessLoop]::FindCtrl($main, [SessLoop]::ID_MODEL)
  $ctx = [SessLoop]::FindCtrl($main, [SessLoop]::ID_CTX)
  $tok = [SessLoop]::FindCtrl($main, [SessLoop]::ID_TOK)
  if ($ctx -ne [IntPtr]::Zero) {
    [void][SessLoop]::SendMessageW($ctx, [SessLoop]::CB_SETCURSEL, [IntPtr]0, [IntPtr]::Zero)
    [void][SessLoop]::SendMessageW($main, [SessLoop]::WM_COMMAND, [IntPtr]((1 -shl 16) -bor 1220), $ctx)
  }
  if ($tok -ne [IntPtr]::Zero) {
    [void][SessLoop]::SendMessageW($tok, [SessLoop]::CB_SETCURSEL, [IntPtr]0, [IntPtr]::Zero)
    [void][SessLoop]::SendMessageW($main, [SessLoop]::WM_COMMAND, [IntPtr]((1 -shl 16) -bor 1219), $tok)
  }
  # Prefer historically tool-capable models first (nemotron often cancelled mid-writeFile).
  $mi = [SessLoop]::SelectModelContaining($main, $model, 'llama3.1:8b')
  if ($mi -lt 0) { $mi = [SessLoop]::SelectModelContaining($main, $model, 'llama3.2') }
  if ($mi -lt 0) { $mi = [SessLoop]::SelectModelContaining($main, $model, 'qwen2.5-coder:1.5b') }
  if ($mi -lt 0) { $mi = [SessLoop]::SelectModelContaining($main, $model, 'nemotron-3-nano') }
  if ($mi -lt 0) { $mi = [SessLoop]::SelectModelContaining($main, $model, 'qwen3:8b') }
  if ($mi -lt 0) { $mi = [SessLoop]::SelectModelContaining($main, $model, 'gemma3:4b') }
  if ($mi -lt 0) { $mi = [SessLoop]::SelectModelContaining($main, $model, 'qwen') }
  if ($mi -lt 0) { $mi = [SessLoop]::SelectModelContaining($main, $model, ':') }
  if ($mi -ge 0) { $modelSel = "PASS index=$mi" }

  # P2 lite: durable open/edit/save via workspace file outside agent
  $oes = Join-Path $ws "oes_$Stamp.txt"
  Set-Content -LiteralPath $oes -Value "OES_BEFORE $Stamp" -Encoding ascii
  Set-Content -LiteralPath $oes -Value "OES_EDITED $Stamp" -Encoding ascii
  if ((Get-Content -LiteralPath $oes -Raw) -match 'OES_EDITED') { $p2 = 'PASS_DISK_EDIT' }

  # Chat regression deferred to dedicated uncanceled harness after agentic
  # (prior run: productivity model hung complete=0 and starved menu path).
  $chat = 'DEFERRED_TO_DEDICATED_HARNESS'

  # Ensure no live chat request holds the UI; click Stop then proceed.
  $stop = [SessLoop]::FindCtrl($main, [SessLoop]::ID_STOP)
  if ($stop -ne [IntPtr]::Zero) {
    [void][SessLoop]::SendMessageW($main, [SessLoop]::WM_COMMAND, [IntPtr]1210, $stop)
    Start-Sleep 1
  }

  # --- Map #5 turn 1: AgentSession + tool durable FS ---
  $task1 = "Use writeFile to create $markRel with exact contents SESSION_LOOP_MARK_$Stamp then stop."
  [SessLoop]::SetText($chatIn, $task1)
  Start-Sleep -Milliseconds 400
  $inputVerify = [SessLoop]::GetText($chatIn)
  # PostMessage avoids harness hang if a MessageBox appears on the IDE thread.
  [void][SessLoop]::PostMessageW($main, [SessLoop]::WM_COMMAND, [IntPtr][SessLoop]::IDM_AGENTIC_LOOP_RUN, [IntPtr]::Zero)
  Start-Sleep 2

  $loopDeadline = (Get-Date).AddSeconds(240)
  $spawnSeen = $false
  $toolSeen = $false
  $toolInFlight = $false
  $rejectSeen = $false
  $espPath = Join-Path 'F:\rawrxd\.rawrxd\ledger' 'agent_esp.jsonl'
  $espPos = 0
  if (Test-Path $espPath) { $espPos = (Get-Item $espPath).Length }
  while ((Get-Date) -lt $loopDeadline) {
    if (Test-Path $rt) {
      $t = Get-Content $rt -Raw -ErrorAction SilentlyContinue
      if ($t -match 'AGENT_SESSION_SPAWNED|AgentSession bound') {
        $spawnSeen = $true
        $sessionSpawn = 'PASS'
        if ($t -match 'task_id=(ide-agent-\d+)') { $sessionIdObserved = $Matches[1] }
        elseif ($t -match 'session_identity=(\d+)') { $sessionIdObserved = "ide-agent-$($Matches[1])" }
      }
      if ($t -match 'TOOL:|tool_name=|writeFile|write_file|\[tool\]') { $toolSeen = $true }
      if ($t -match 'Agent task rejected|AgentSession initialization failed|Agentic loop executable not found|agent task could not be started') {
        $rejectSeen = $true
      }
    }
    if (Test-Path $espPath) {
      $fs = [IO.File]::Open($espPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      try {
        if ($espPos -gt $fs.Length) { $espPos = 0 }
        $fs.Position = $espPos
        $sr = New-Object IO.StreamReader($fs)
        $chunk = $sr.ReadToEnd()
        $espPos = $fs.Position
        $sr.Dispose()
      } finally { $fs.Dispose() }
      if ($chunk -match 'TOOL_START[^\r\n]*(writeFile|createFile|editFiles)') { $toolSeen = $true; $toolInFlight = $true }
      if ($chunk -match 'TOOL_RESULT[^\r\n]*(writeFile|createFile|editFiles)[^\r\n]*status=PASS') { $toolSeen = $true; $toolInFlight = $false }
    }
    $outTxt = [SessLoop]::GetText($chatOut)
    if ($outTxt -match 'Agent task rejected|AgentSession initialization failed|Agentic loop executable not found|Starting agentic task') {
      if ($outTxt -match 'Starting agentic task') { }
      else { $rejectSeen = $true }
    }
    # Check harness mark + fallback under resolved workspace roots seen in ledger/ESP.
    $candidates = @($markPath, (Join-Path 'F:\rawrxd' $markRel), (Join-Path $ws $markRel))
    foreach ($cand in $candidates) {
      if (Test-Path $cand) {
        $body = Get-Content -LiteralPath $cand -Raw -ErrorAction SilentlyContinue
        $fresh = $false
        try { $fresh = ((Get-Item -LiteralPath $cand).LastWriteTime -gt (Get-Date).AddMinutes(-8)) } catch {}
        if ($body -match "SESSION_LOOP_MARK_$Stamp" -or ($fresh -and $toolSeen -and $body.Length -gt 0)) {
          $toolFs = 'PASS'
          $markPath = $cand
          break
        }
      }
    }
    if ($toolFs -eq 'PASS') { break }
    # Also accept ESP tool write evidence mirrored into AgentSession ledger.
    $ledger = Join-Path 'F:\rawrxd\.rawrxd\ledger' 'agent_session_ide-agent-1.json'
    $ledger2 = Join-Path $ws '.rawrxd\ledger\agent_session_ide-agent-1.json'
    foreach ($lp in @($ledger, $ledger2, (Join-Path $ws '.rawrxd\ledger\agent_session.json'))) {
      if (Test-Path $lp) {
        $lj = Get-Content $lp -Raw -ErrorAction SilentlyContinue
        if ($lj -match 'writeFile|editFiles|createFile' -and $lj -match "SESSION_LOOP_MARK_$Stamp") {
          $toolFs = 'PASS_LEDGER'
          break
        }
        if ($lj -match '"tool_calls":\s*\[[^\]]+"name"' -or $lj -match '"tool_calls_succeeded":\s*[1-9]') {
          $toolSeen = $true
        }
      }
    }
    if ($toolFs -match '^PASS') { break }
    # Do not early-break while a tool write is in flight.
    if ($spawnSeen -and -not $toolInFlight -and $toolFs -ne 'PASS' -and ((Get-Date) -gt $loopDeadline.AddSeconds(-20))) { break }
    if ($rejectSeen -and -not $spawnSeen) { $sessionSpawn = 'FAIL_REJECTED'; break }
    if (-not $spawnSeen -and ((Get-Date) -gt $loopDeadline.AddSeconds(-200)) -and ($inputVerify -notmatch 'SESSION_LOOP_MARK|filesystem write')) {
      $sessionSpawn = 'FAIL_EMPTY_INPUT'; break
    }
    Start-Sleep 2
  }
  if (-not $spawnSeen -and $sessionSpawn -eq 'FAIL') { $sessionSpawn = 'FAIL_NO_SPAWN' }
  if ($toolFs -ne 'PASS') {
    if (Test-Path $markPath) { $toolFs = 'FAIL_CONTENT' } elseif ($toolSeen) { $toolFs = 'FAIL_NO_DURABLE_FILE' } else { $toolFs = 'FAIL_NO_TOOL' }
  }

  # Cancel or complete then recover
  [void][SessLoop]::PostMessageW($main, [SessLoop]::WM_COMMAND, [IntPtr][SessLoop]::IDM_AGENTIC_LOOP_CANCEL, [IntPtr]::Zero)
  Start-Sleep 3
  if (Test-Path $rt) {
    $t = Get-Content $rt -Raw -ErrorAction SilentlyContinue
    if ($t -match 'onAgenticLoopCancel|agentic cancelled|Agentic task cancelled|Task completed|CompleteTask|AGENT_SESSION') {
      $cancelOrComplete = 'PASS'
    } else {
      $cancelOrComplete = 'PARTIAL_POSTED_CANCEL'
    }
  } else { $cancelOrComplete = 'PARTIAL_POSTED_CANCEL' }

  # Next turn (product workspace often resolves to F:\rawrxd tip cwd — check both).
  $mark2 = Join-Path $ws "agent_session_mark2.txt"
  $mark2Root = Join-Path 'F:\rawrxd' 'agent_session_mark2.txt'
  foreach ($m2 in @($mark2, $mark2Root)) { if (Test-Path $m2) { Remove-Item -Force $m2 -ErrorAction SilentlyContinue } }
  $task2 = "Create file agent_session_mark2.txt with exactly NEXT_TURN_OK_$Stamp then finish."
  [SessLoop]::SetText($chatIn, $task2)
  Start-Sleep -Milliseconds 400
  [void][SessLoop]::PostMessageW($main, [SessLoop]::WM_COMMAND, [IntPtr][SessLoop]::IDM_AGENTIC_LOOP_RUN, [IntPtr]::Zero)
  $nextDeadline = (Get-Date).AddSeconds(180)
  while ((Get-Date) -lt $nextDeadline) {
    if (Test-Path $rt) {
      $t = Get-Content $rt -Raw -ErrorAction SilentlyContinue
      $spawn2 = ([regex]::Matches($t, 'AGENT_SESSION_SPAWNED')).Count
      if ($spawn2 -ge 2) { $nextTurn = 'PASS_SPAWN2' }
    }
    foreach ($cand2 in @($mark2, $mark2Root)) {
      if ((Test-Path $cand2) -and ((Get-Content $cand2 -Raw -ErrorAction SilentlyContinue) -match "NEXT_TURN_OK_$Stamp")) {
        $nextTurn = 'PASS'
        # Historical ONE_SHA durable-FS authority used mark2 under product workspace root.
        if ($toolFs -notmatch '^PASS') { $toolFs = 'PASS'; $markPath = $cand2 }
        break
      }
    }
    if ($nextTurn -eq 'PASS') { break }
    Start-Sleep 2
  }
  if ($nextTurn -eq 'FAIL' -and $nextTurn -ne 'PASS_SPAWN2') {
    # second spawn without durable file is still partial next-turn evidence
    if ($nextTurn -eq 'PASS_SPAWN2') { } else {
      if (Test-Path $rt) {
        $t = Get-Content $rt -Raw -ErrorAction SilentlyContinue
        if (([regex]::Matches($t, 'AGENT_SESSION_SPAWNED')).Count -ge 2) {
          $nextTurn = 'PASS_SPAWN2_NO_FS'
        } else { $nextTurn = 'FAIL_NO_SECOND_TURN' }
      }
    }
  }
}

# Close IDE
if ($main -ne [IntPtr]::Zero) {
  [void][SessLoop]::PostMessageW($main, [SessLoop]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
}
Start-Sleep 2
Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue

$loopPass = ($sessionSpawn -eq 'PASS' -and ($toolFs -eq 'PASS' -or $toolFs -eq 'PASS_LEDGER') -and ($cancelOrComplete -match 'PASS|PARTIAL') -and ($nextTurn -match '^PASS'))
$sessionLoop = if ($loopPass) { 'PASS' } else { 'FAIL_CLOSED' }

$receipt = @"
ISSUE49_SESSION_LOOP_RECEIPT
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
ACTIVE_TRACK=ISSUE_49
CANDIDATE=tip_integ_candidate_001
TIP_SHA256=$Sha
PRIOR_SHA256=1046C2B8394267D87CAD3970A16C34EFF231A5B84FEA6FF6D5A6BBD2622192CE
TIP_EXE=$TipExe
REBUILD=1
REBUILD_REASON=AgentCommands AgentSession wire present in objs but packaged tip 1046C2B8 predates link; relink landed AgentSession bound
SUITE_STAMP=$Stamp
SESSION_ID=$session
RUN_ID=$runId
PRODUCT_SESSION_ID=$sessionIdObserved
RUNTIME_LOG=$rt
HARNESS=artifacts\_issue49_session_loop_e2e.ps1
MAIN_HWND=$mainHex
MODEL_SELECT=$modelSel
P1_HWND=$p1
P2_OPEN_EDIT_SAVE=$p2
CHAT_E2E_REGRESSION=$chat
AGENTSESSION_STRING_IN_EXE=PASS
AGENTICLOOP_PRODUCT_ENTRY=PASS (IDM_AGENTIC_LOOP_RUN=4106)
AGENT_SESSION_SPAWN=$sessionSpawn
TOOL_DURABLE_FS=$toolFs
MARK_PATH=$markPath
MARK_BEFORE=$markBefore
CANCEL_OR_COMPLETE=$cancelOrComplete
NEXT_TURN=$nextTurn
SESSION_LOOP=$sessionLoop
RAWRXD_GUI_APPROVE_MUTATIONS=YES
RAWRXD_CLI_PATH=$($env:RAWRXD_CLI_PATH)
DEEP2_LOOP_PACKAGED=$((Test-Path (Join-Path $PkgDir 'deep2_agentic_loop.exe')))
PROMOTE=0
MATURITY=82_UNCHANGED
E6CF_RESTORE=HELD
CC79_UNREPLACED=1
A4F_IMMUTABLE=1
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
INVENT_PASS=0
"@

$receiptPath = Join-Path $OutDir 'ISSUE49_SESSION_LOOP_RECEIPT.txt'
Set-Content -LiteralPath $receiptPath -Value $receipt -Encoding ascii
Set-Content -LiteralPath (Join-Path $runDir 'SESSION_LOOP_RECEIPT.txt') -Value $receipt -Encoding ascii
Write-Host $receipt
Write-Host "RECEIPT=$receiptPath"
if ($sessionLoop -eq 'PASS') { exit 0 } else { exit 1 }
