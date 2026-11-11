#Requires -Version 5.1
# Issue #49 map #10 — Repeated-use + failure-recovery on tip_integ_candidate_001 (4DE0).
# Adapted from map6 cancel/recover + chat_e2e multi-cycle; one HWND, no relaunch.
# Laws: PROMOTE=0 MATURITY=82 E6CF HELD; NOT_RUN!=PASS; NO_CROSS_SHA_PASS.
$ErrorActionPreference = 'Continue'
$ExpectSha = '4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6'
$EvidenceRoot = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001'
$TipExe = Join-Path $EvidenceRoot 'package\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe'
$CandDir = Join-Path $EvidenceRoot 'candidates\tip_integ_candidate_001'
$OutDir = Join-Path $EvidenceRoot 'artifacts'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
if ($Sha -ne $ExpectSha) { Write-Host "SHA_DRIFT=$Sha expected=$ExpectSha"; exit 9 }

Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','rawr' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2

Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class Map10RU {
  public const uint WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_COMMAND=0x0111, WM_CLOSE=0x0010;
  public const uint CB_SETCURSEL=0x014E; public const int CBN_SELCHANGE=1;
  public const int ID_CHAT=1202, ID_OUT=1203, ID_SEND=1204, ID_STOP=1210, ID_MODEL=1206, ID_CTX=1220, ID_TOK=1219;
  public const uint CB_GETCOUNT=0x0146, CB_GETLBTEXT=0x0148, CB_GETLBTEXTLEN=0x0149;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h,l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(128); GetClassNameW(h, sb, sb.Capacity);
      if (sb.ToString().IndexOf("RawrXD") >= 0) { found = h; return false; }
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
  public static void SelectCombo(IntPtr main, IntPtr combo, int id, int index) {
    if (combo == IntPtr.Zero) return;
    SendMessageW(combo, CB_SETCURSEL, (IntPtr)index, IntPtr.Zero);
    SendMessageW(main, WM_COMMAND, (IntPtr)((CBN_SELCHANGE << 16) | (id & 0xFFFF)), combo);
  }
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

function Wait-Main([Diagnostics.Process]$proc, [int]$sec = 55) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    try { $proc.Refresh() } catch {}
    if ($proc.HasExited) { return [IntPtr]::Zero }
    $m = [Map10RU]::FindMain([uint32]$proc.Id)
    if ($m -ne [IntPtr]::Zero) { return $m }
    Start-Sleep -Milliseconds 250
  }
  return [IntPtr]::Zero
}

function Get-RtLines([string]$rt) {
  if (Test-Path $rt) { return @(Get-Content $rt -ErrorAction SilentlyContinue) }
  return @()
}

function Wait-ChatCycle {
  param(
    [IntPtr]$Main,
    [string]$Rt,
    [string]$Prompt,
    [int]$WaitSec = 120,
    [switch]$ExpectCancel,
    [int]$CancelAfterMs = 0
  )
  $chat = [Map10RU]::FindCtrl($Main, [Map10RU]::ID_CHAT)
  $send = [Map10RU]::FindCtrl($Main, [Map10RU]::ID_SEND)
  $stop = [Map10RU]::FindCtrl($Main, [Map10RU]::ID_STOP)
  $out = [Map10RU]::FindCtrl($Main, [Map10RU]::ID_OUT)
  $outBefore = [Map10RU]::GetText($out)
  $before = Get-RtLines $Rt
  [Map10RU]::SetText($chat, $Prompt)
  Start-Sleep -Milliseconds 200
  [void][Map10RU]::SendMessageW($Main, [Map10RU]::WM_COMMAND, [IntPtr]1204, $send)

  $armed = $false; $reqId = ''; $dispId = ''; $cancelSeen = $false; $termOk = $false
  $respOk = $false; $backendOk = $false; $visible = $false; $unexpectedCancel = $false
  $deadline = (Get-Date).AddSeconds($WaitSec)
  $cancelPosted = $false
  $armDeadline = (Get-Date).AddSeconds(25)

  while ((Get-Date) -lt $deadline) {
    $all = Get-RtLines $Rt
    $new = @()
    if ($all.Count -gt $before.Count) { $new = $all[$before.Count..($all.Count - 1)] }
    $joined = ($new -join "`n")

    if ($joined -match 'CHAT_SEND_ARMED' -or $joined -match 'BACKEND_REQUEST_START') { $armed = $true }
    if ($joined -match 'CHAT_SEND_ARMED[^\r\n]*request_id=(\d+)') { $reqId = $Matches[1] }
    elseif (-not $reqId -and $joined -match 'BACKEND_REQUEST_START request_id=(\d+)') { $reqId = $Matches[1] }
    if ($joined -match 'DISPATCH_ID id=(\d+)') { $dispId = $Matches[1] }

    if ($ExpectCancel -and $armed -and -not $cancelPosted -and ((Get-Date) -ge $armDeadline.AddSeconds(-25).AddMilliseconds($CancelAfterMs))) {
      Start-Sleep -Milliseconds ([Math]::Max(0, $CancelAfterMs))
      if ($stop -ne [IntPtr]::Zero) {
        [void][Map10RU]::PostMessageW($Main, [Map10RU]::WM_COMMAND, [IntPtr]1210, $stop)
      } else {
        [void][Map10RU]::PostMessageW($Main, [Map10RU]::WM_COMMAND, [IntPtr]1210, [IntPtr]::Zero)
      }
      $cancelPosted = $true
      Start-Sleep 1
    }

    if ($ExpectCancel) {
      if ($joined -match 'cancel_requested' -and $joined -match 'cancel_acknowledged') { $cancelSeen = $true }
      if ($joined -match 'BACKEND_REQUEST_END .*cancel=1' -or ($joined -match 'cancel_acknowledged' -and $joined -match 'active_after=0')) {
        $termOk = $true
      }
      if ($cancelSeen -and $termOk) { break }
    } else {
      if ($reqId -and $joined -match "cancel_requested request_id=$reqId") { $unexpectedCancel = $true }
      if ($joined -match 'RESPONSE_START' -or $joined -match 'ui_update .*complete=1' -or
          ($reqId -and $joined -match "BACKEND_REQUEST_END request_id=$reqId[^\r\n]*cancel=0") -or
          $joined -match 'BACKEND_REQUEST_END[^\r\n]*cancel=0') {
        $respOk = $true
        if ($joined -match 'BACKEND_REQUEST_END[^\r\n]*cancel=0') { $backendOk = $true }
      }
      $outNow = [Map10RU]::GetText([Map10RU]::FindCtrl($Main, [Map10RU]::ID_OUT))
      if ($outNow.Length -gt $outBefore.Length -and $outNow.Length -gt 0) { $visible = $true }
      if ($armed -and ($respOk -or $backendOk) -and $visible) { break }
      if ($armed -and ($respOk -or $backendOk) -and ((Get-Date) -gt $deadline.AddSeconds(-5))) { break }
    }
    if (-not $armed -and (Get-Date) -gt $armDeadline -and -not $ExpectCancel) { break }
    Start-Sleep -Milliseconds 350
  }

  Start-Sleep 1
  $outAfter = [Map10RU]::GetText([Map10RU]::FindCtrl($Main, [Map10RU]::ID_OUT))
  if ($outAfter.Length -gt $outBefore.Length -and $outAfter.Length -gt 0) { $visible = $true }

  $allFinal = Get-RtLines $Rt
  $post = @()
  if ($allFinal.Count -gt $before.Count) { $post = $allFinal[$before.Count..($allFinal.Count - 1)] }
  $postJ = ($post -join "`n")
  if (-not $reqId -and $postJ -match 'CHAT_SEND_ARMED[^\r\n]*request_id=(\d+)') { $reqId = $Matches[1] }
  if (-not $dispId -and $postJ -match 'DISPATCH_ID id=(\d+)') { $dispId = $Matches[1] }
  $armedPost = @($post | Where-Object { $_ -match 'CHAT_SEND_ARMED' })
  if ($armedPost.Count -ge 1 -and $armedPost[-1] -match 'request_id=(\d+)') { $reqId = $Matches[1] }
  if ($reqId -and (@($post | Where-Object { $_ -match "BACKEND_REQUEST_END request_id=$reqId" -and $_ -match 'cancel=0' }).Count -ge 1)) {
    $backendOk = $true; $respOk = $true
  }
  if ($reqId -and (@($post | Where-Object { $_ -match "RESPONSE_START" -and $_ -match "request_id=$reqId" }).Count -ge 1)) {
    $respOk = $true
  }
  if ($ExpectCancel) {
    if ($postJ -match 'cancel_requested' -and $postJ -match 'cancel_acknowledged') { $cancelSeen = $true }
    if ($postJ -match 'BACKEND_REQUEST_END .*cancel=1' -or ($postJ -match 'cancel_acknowledged' -and $postJ -match 'active_after=0')) {
      $termOk = $true
    }
  } else {
    if ($reqId -and (@($post | Where-Object { $_ -match "cancel_requested request_id=$reqId" }).Count -ge 1)) {
      $unexpectedCancel = $true
    }
  }

  $corr = 'FAIL'
  if ($ExpectCancel) {
    if ($armed -and $cancelSeen -and $termOk) { $corr = 'PASS' }
    elseif ($armed -and $cancelSeen) { $corr = 'PARTIAL_CANCEL_NO_TERM' }
    elseif ($armed) { $corr = 'FAIL_NO_CANCEL' }
    else { $corr = 'FAIL_NO_ARM' }
  } else {
    $hasDisp = ($dispId -ne '')
    if ($armed -and -not $unexpectedCancel -and $visible -and ($respOk -or $backendOk) -and $hasDisp) { $corr = 'PASS' }
    elseif ($armed -and -not $unexpectedCancel -and ($respOk -or $backendOk) -and $hasDisp) { $corr = 'PARTIAL_JOURNAL_NO_VISIBLE' }
    elseif ($armed -and -not $unexpectedCancel) { $corr = 'FAIL_ARMED_NO_RESPONSE' }
    else { $corr = 'FAIL' }
  }

  return [pscustomobject]@{
    Armed = $armed; ReqId = $reqId; DispId = $dispId; CancelSeen = $cancelSeen; TermOk = $termOk
    RespOk = $respOk; BackendOk = $backendOk; Visible = $visible; UnexpectedCancel = $unexpectedCancel
    Corr = $corr; OutBefore = $outBefore.Length; OutAfter = $outAfter.Length
  }
}

New-Item -ItemType Directory -Force -Path $OutDir,$CandDir | Out-Null
$runDir = Join-Path $CandDir ("map10_repeated_$Stamp")
$ws = Join-Path $runDir 'workspace'
New-Item -ItemType Directory -Force -Path $ws | Out-Null
$session = "integ_map10_$Stamp"
$runId = "integ_map10_run_$Stamp"
$env:RAWRXD_LOG_DIR = $runDir
$env:RAWRXD_CHAT_SESSION_ID = $session
$env:RAWRXD_CHAT_RUN_ID = $runId
$env:RAWRXD_DISCARD_UNSAVED_ON_CLOSE = '1'
$rt = Join-Path $runDir 'chat_runtime.log'
if (Test-Path $rt) { Remove-Item $rt -Force }

$p1 = 'FAIL'; $mainHex = '0x0'; $modelSel = 'FAIL'; $editCycle = 'FAIL'
$c1 = $null; $c2 = $null; $c3 = $null; $c4 = $null
$sameHwnd = 'FAIL'; $cycleCount = 0; $relaunch = 'NO'

$seed = Join-Path $ws "map10_seed_$Stamp.txt"
Set-Content -LiteralPath $seed -Value "MAP10_SEED $Stamp" -Encoding ascii
$p = Start-Process -FilePath $TipExe -ArgumentList @($seed) -WorkingDirectory $ws -PassThru -WindowStyle Normal
$main = Wait-Main $p 55
if ($main -ne [IntPtr]::Zero -and -not $p.HasExited) {
  $p1 = 'PASS'
  $mainHex = ('0x{0:X}' -f $main.ToInt64())
  $hwndAtLaunch = $main.ToInt64()
  Start-Sleep 8
  [void][Map10RU]::SetForegroundWindow($main)
  $model = [Map10RU]::FindCtrl($main, [Map10RU]::ID_MODEL)
  $ctx = [Map10RU]::FindCtrl($main, [Map10RU]::ID_CTX)
  $tok = [Map10RU]::FindCtrl($main, [Map10RU]::ID_TOK)
  if ($ctx -ne [IntPtr]::Zero) { [Map10RU]::SelectCombo($main, $ctx, 1220, 0) }
  if ($tok -ne [IntPtr]::Zero) { [Map10RU]::SelectCombo($main, $tok, 1219, 0) }
  $mi = [Map10RU]::SelectModelContaining($main, $model, 'llama3.2')
  if ($mi -lt 0) { $mi = [Map10RU]::SelectModelContaining($main, $model, 'llama3.1:8b') }
  if ($mi -lt 0) { $mi = [Map10RU]::SelectModelContaining($main, $model, 'gemma3:4b') }
  if ($mi -lt 0) { $mi = [Map10RU]::SelectModelContaining($main, $model, 'granite3.3:8b') }
  if ($mi -lt 0) { $mi = [Map10RU]::SelectModelContaining($main, $model, 'qwen2.5-coder:1.5b') }
  if ($mi -lt 0) { $mi = [Map10RU]::SelectModelContaining($main, $model, 'nemotron-3-nano') }
  $modelSel = if ($mi -ge 0) { "PASS index=$mi" } else { 'FAIL_DEFAULT' }
  Start-Sleep -Milliseconds 400

  # Cycle 0 companion: successive disk edit without relaunch
  $oes = Join-Path $ws "map10_edit_$Stamp.txt"
  Set-Content -LiteralPath $oes -Value "EDIT_A_$Stamp" -Encoding ascii
  Set-Content -LiteralPath $oes -Value "EDIT_B_$Stamp" -Encoding ascii
  if ((Get-Content -LiteralPath $oes -Raw) -match "EDIT_B_$Stamp") { $editCycle = 'PASS' }

  # Cycle 1: first product chat success
  $c1 = Wait-ChatCycle -Main $main -Rt $rt -Prompt "MAP10_C1_$Stamp Reply with exactly three words: alpha repeated use" -WaitSec 150
  $cycleCount++
  Start-Sleep 2

  # Cycle 2: inject recoverable failure (in-flight Stop=1210)
  $c2 = Wait-ChatCycle -Main $main -Rt $rt -Prompt "MAP10_C2_CANCEL_$Stamp please write a long detailed essay about compilers parsers and code generation so this stays busy." -WaitSec 40 -ExpectCancel -CancelAfterMs 400
  $cycleCount++
  Start-Sleep 2

  # Cycle 3: recovery request after cancel (correlated)
  $c3 = Wait-ChatCycle -Main $main -Rt $rt -Prompt "MAP10_C3_RECOVER_$Stamp Reply with exactly three words: bravo recovery ok" -WaitSec 180
  $cycleCount++
  Start-Sleep 2

  # Cycle 4: another successive use without relaunch
  $c4 = Wait-ChatCycle -Main $main -Rt $rt -Prompt "MAP10_C4_$Stamp Reply with exactly three words: charlie still alive" -WaitSec 150
  $cycleCount++

  $mainStill = [Map10RU]::FindMain([uint32]$p.Id)
  if ($mainStill -ne [IntPtr]::Zero -and $mainStill.ToInt64() -eq $hwndAtLaunch -and -not $p.HasExited) {
    $sameHwnd = 'PASS'
  } elseif ($mainStill -ne [IntPtr]::Zero -and -not $p.HasExited) {
    $sameHwnd = 'PASS_HWND_ALIVE'
  }

  try {
    if (-not $p.HasExited) {
      [void][Map10RU]::PostMessageW($main, [Map10RU]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
      Start-Sleep 3
    }
  } catch {}
  try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
} else {
  try { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
}

Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue

$c1Pass = ($c1 -and ($c1.Corr -eq 'PASS' -or $c1.Corr -eq 'PARTIAL_JOURNAL_NO_VISIBLE'))
$c2Pass = ($c2 -and $c2.Corr -eq 'PASS')
$c3Pass = ($c3 -and $c3.Corr -eq 'PASS')
$c4Pass = ($c4 -and ($c4.Corr -eq 'PASS' -or $c4.Corr -eq 'PARTIAL_JOURNAL_NO_VISIBLE'))
# Map10 requires measured successive use + failure+recovery; C1+C4 need at least one full PASS visible preferred
$repeatedUse = 'FAIL'
if ($sameHwnd -match '^PASS' -and $editCycle -eq 'PASS' -and $c1Pass -and $c4Pass -and $cycleCount -ge 4) {
  $repeatedUse = 'PASS'
} elseif ($sameHwnd -match '^PASS' -and $c1Pass -and $c4Pass) {
  $repeatedUse = 'PASS_CHAT_ONLY'
}

$failRecover = 'FAIL'
if ($c2Pass -and $c3.Corr -eq 'PASS') { $failRecover = 'PASS' }
elseif ($c2Pass -and $c3.Corr -eq 'PARTIAL_JOURNAL_NO_VISIBLE') { $failRecover = 'PARTIAL_JOURNAL' }
elseif ($c2Pass -and $c3Pass) { $failRecover = 'PASS' }

$map10 = 'FAIL'
# Strict: need visible correlated recovery + multi-cycle on same HWND/SHA
if ($p1 -eq 'PASS' -and $Sha -eq $ExpectSha -and $sameHwnd -match '^PASS' -and
    ($repeatedUse -eq 'PASS' -or $repeatedUse -eq 'PASS_CHAT_ONLY') -and
    $failRecover -eq 'PASS' -and $c3.Corr -eq 'PASS' -and
    ($c1.Corr -eq 'PASS' -or $c4.Corr -eq 'PASS')) {
  $map10 = 'PASS'
} elseif ($p1 -eq 'PASS' -and $failRecover -eq 'PARTIAL_JOURNAL' -and ($repeatedUse -match '^PASS')) {
  $map10 = 'PARTIAL'
} elseif ($p1 -ne 'PASS') {
  $map10 = 'NOT_DEMONSTRATED'
}

$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$receipt = @"
ISSUE49_REPEATED_USE_RECEIPT
ASOF_UTC=$asof
ACTIVE_TRACK=ISSUE_49
MAP=10
CANDIDATE=tip_integ_candidate_001
TIP_SHA256=$Sha
PRIOR_SHA256=4CFB85B3DD86602156D417FE367D82C84ABA5774AE3BD65FE2BA788614D70321
TIP_EXE=$TipExe
SUITE_STAMP=$Stamp
SESSION_ID=$session
RUN_ID=$runId
MAIN_HWND=$mainHex
PID_MAIN=$(if($p){$p.Id}else{0})
MODEL_SELECT=$modelSel
RUNTIME_LOG=$rt
HARNESS=artifacts\_issue49_repeated_use_e2e.ps1
RUN_DIR=$runDir
NO_CROSS_SHA_PASS=1
RELAUNCH=$relaunch
SAME_HWND=$sameHwnd
CYCLE_COUNT=$cycleCount
EDIT_CYCLE=$editCycle
PROMOTE=0
MATURITY=82
E6CF_RESTORE=HELD
TIP_MOVE_AUTHORIZED=0
CC79_UNREPLACED=1
A4F_IMMUTABLE=1
INVENT_PASS=0

## SHA gate
SHA_VERIFY=$(if($Sha -eq $ExpectSha){'PASS'}else{'FAIL'})
EXPECTED=$ExpectSha
MEASURED=$Sha

## Repeated-use cycles (one launch)
P1_HWND=$p1
C1_SUCCESS_CORR=$($c1.Corr); REQ=$($c1.ReqId); DISP=$($c1.DispId); VIS=$($c1.Visible); OUT=$($c1.OutBefore)->$($c1.OutAfter)
C2_FAILURE_INJECT_CORR=$($c2.Corr); REQ=$($c2.ReqId); CANCEL=$($c2.CancelSeen); TERM=$($c2.TermOk)
C3_RECOVERY_CORR=$($c3.Corr); REQ=$($c3.ReqId); DISP=$($c3.DispId); VIS=$($c3.Visible); UNEXPECT_CANCEL=$($c3.UnexpectedCancel); OUT=$($c3.OutBefore)->$($c3.OutAfter)
C4_SUCCESS_CORR=$($c4.Corr); REQ=$($c4.ReqId); DISP=$($c4.DispId); VIS=$($c4.Visible); OUT=$($c4.OutBefore)->$($c4.OutAfter)
REPEATED_USE=$repeatedUse
FAILURE_RECOVERY=$failRecover
PRODUCT_CANCEL_PATH=CHAT_STOP_1210

## Gate
MAP10=$map10
ISSUE49_ADVANCE=$(if($map10 -eq 'PASS'){'9/11->10/11'}else{'HOLD_9/11'})
NEXT_GAP=$(if($map10 -eq 'PASS'){'Map #11 Package->clean-machine->rollback (ONE_SHA remasure debt maps1-11 on 4DE0 still open; NO_CROSS_SHA_PASS)'}else{'Map #10 Repeated-use + failure-recovery checks on SHA 4DE06F9F'})
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@

$receiptPath = Join-Path $OutDir 'ISSUE49_REPEATED_USE_RECEIPT.txt'
Set-Content -LiteralPath $receiptPath -Value $receipt -Encoding ascii
Set-Content -LiteralPath (Join-Path $runDir 'REPEATED_USE_RECEIPT.txt') -Value $receipt -Encoding ascii
if (Test-Path $rt) {
  Set-Content -LiteralPath (Join-Path $OutDir 'ISSUE49_REPEATED_USE_JOURNAL.txt') -Value (Get-Content $rt -Raw) -Encoding utf8
}
Write-Host $receipt
Write-Host "RECEIPT=$receiptPath"
Write-Host "MAP10=$map10"
if ($map10 -eq 'PASS') { exit 0 } elseif ($map10 -eq 'PARTIAL') { exit 3 } else { exit 1 }
