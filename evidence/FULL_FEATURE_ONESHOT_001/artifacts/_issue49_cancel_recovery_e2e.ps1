#Requires -Version 5.1
# Issue #49 map #6 — product cancel + recovery on tip_integ_candidate_001 (5A34B393).
# Adapted from _integ_p2_verify_suite.ps1 T05 + _chat_e2e_uncanceled_4CFB.ps1 recovery.
# Laws: PROMOTE=0 MATURITY=82 E6CF HELD; NOT_RUN!=PASS; NO_CROSS_SHA_PASS from 4CFB/1046.
$ErrorActionPreference = 'Continue'
$ExpectSha = '5A34B393ECF7380576CE718C688DC4006C0E3B01090BB4DCD8B844FB594D1619'
$TipExe = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\package\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe'
$CandDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_integ_candidate_001'
$OutDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
if ($Sha -ne $ExpectSha) { Write-Host "SHA_DRIFT=$Sha expected=$ExpectSha"; exit 9 }

Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','rawr' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2

Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class Map6CR {
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
      string c = sb.ToString();
      if (c == "RawrXD_IDE_MainWindow" || c == "RawrXD_IDE_Window" || c.IndexOf("RawrXD") >= 0) { found = h; return false; }
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
    $m = [Map6CR]::FindMain([uint32]$proc.Id)
    if ($m -ne [IntPtr]::Zero) { return $m }
    Start-Sleep -Milliseconds 250
  }
  return [IntPtr]::Zero
}

$runDir = Join-Path $CandDir ("map6_cancel_$Stamp")
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
$session = "integ_map6_$Stamp"
$runId = "integ_map6_run_$Stamp"
$env:RAWRXD_LOG_DIR = $runDir
$env:RAWRXD_CHAT_SESSION_ID = $session
$env:RAWRXD_CHAT_RUN_ID = $runId
$rt = Join-Path $runDir 'chat_runtime.log'
if (Test-Path $rt) { Remove-Item $rt -Force }

$p1 = 'FAIL'; $t05Start = 'FAIL'; $t05Cancel = 'FAIL'; $t05Term = 'FAIL'
$t05Late = 'NOT_OBSERVED'; $recoverArmed = 'FAIL'; $recoverCorr = 'FAIL'
$recoverVisible = 'FAIL'; $recoverCancel = 'NO'; $cancelPath = 'CHAT_STOP_1210'
$mainHex = '0x0'; $cancelReqId = ''; $recoverReqId = ''; $recoverDispId = ''
$outBeforeB = ''; $outAfterB = ''; $script:modelSel = 'FAIL'

$p = Start-Process -FilePath $TipExe -WorkingDirectory $CandDir -PassThru -WindowStyle Normal
$main = Wait-Main $p 55
if ($main -ne [IntPtr]::Zero -and -not $p.HasExited) {
  $p1 = 'PASS'
  $mainHex = ('0x{0:X}' -f $main.ToInt64())
  Start-Sleep 8
  [void][Map6CR]::SetForegroundWindow($main)
  $chat = [Map6CR]::FindCtrl($main, [Map6CR]::ID_CHAT)
  $send = [Map6CR]::FindCtrl($main, [Map6CR]::ID_SEND)
  $stop = [Map6CR]::FindCtrl($main, [Map6CR]::ID_STOP)
  $out = [Map6CR]::FindCtrl($main, [Map6CR]::ID_OUT)
  $model = [Map6CR]::FindCtrl($main, [Map6CR]::ID_MODEL)
  $ctx = [Map6CR]::FindCtrl($main, [Map6CR]::ID_CTX)
  $tok = [Map6CR]::FindCtrl($main, [Map6CR]::ID_TOK)
  if ($ctx -ne [IntPtr]::Zero) { [Map6CR]::SelectCombo($main, $ctx, 1220, 0) }
  if ($tok -ne [IntPtr]::Zero) { [Map6CR]::SelectCombo($main, $tok, 1219, 0) }
  # Prefer small/fast completion models; productivity hung after cancel in prior map6 run.
  $mi = [Map6CR]::SelectModelContaining($main, $model, 'llama3.2')
  if ($mi -lt 0) { $mi = [Map6CR]::SelectModelContaining($main, $model, 'llama3.1:8b') }
  if ($mi -lt 0) { $mi = [Map6CR]::SelectModelContaining($main, $model, 'gemma3:4b') }
  if ($mi -lt 0) { $mi = [Map6CR]::SelectModelContaining($main, $model, 'granite3.3:8b') }
  if ($mi -lt 0) { $mi = [Map6CR]::SelectModelContaining($main, $model, 'nemotron-3-nano') }
  if ($mi -lt 0) { $mi = [Map6CR]::SelectModelContaining($main, $model, 'qwen2.5-coder:1.5b') }
  $script:modelSel = if ($mi -ge 0) { "PASS index=$mi" } else { 'FAIL_DEFAULT' }
  Start-Sleep -Milliseconds 500

  # --- Cancel chain: long in-flight chat request then product Stop (1210) ---
  [Map6CR]::SetText($chat, "MAP6_A_CANCEL_$Stamp please write a long detailed essay about compilers, parsers, and code generation so this request stays busy.")
  Start-Sleep -Milliseconds 200
  [void][Map6CR]::SendMessageW($main, [Map6CR]::WM_COMMAND, [IntPtr]1204, $send)
  $armedA = $false
  $dl = (Get-Date).AddSeconds(25)
  while ((Get-Date) -lt $dl) {
    if (Test-Path $rt) {
      $t = Get-Content $rt -Raw -ErrorAction SilentlyContinue
      if ($t -match 'CHAT_SEND_ARMED' -or $t -match 'BACKEND_REQUEST_START') {
        $armedA = $true
        if ($t -match 'CHAT_SEND_ARMED[^\r\n]*request_id=(\d+)') { $cancelReqId = $Matches[1] }
        elseif ($t -match 'BACKEND_REQUEST_START request_id=(\d+)') { $cancelReqId = $Matches[1] }
        break
      }
    }
    Start-Sleep -Milliseconds 200
  }
  if ($armedA) { $t05Start = 'PASS' }

  # Brief settle so cancel hits mid-flight (not pre-arm)
  Start-Sleep -Milliseconds 400
  if ($stop -ne [IntPtr]::Zero) {
    [void][Map6CR]::PostMessageW($main, [Map6CR]::WM_COMMAND, [IntPtr]1210, $stop)
  } else {
    [void][Map6CR]::PostMessageW($main, [Map6CR]::WM_COMMAND, [IntPtr]1210, [IntPtr]::Zero)
  }
  Start-Sleep 3
  $t = if (Test-Path $rt) { Get-Content $rt -Raw -ErrorAction SilentlyContinue } else { '' }
  if ($t -match 'cancel_requested' -and $t -match 'cancel_acknowledged') { $t05Cancel = 'PASS' }
  if ($t -match 'BACKEND_REQUEST_END .*cancel=1' -and $t -match 'active_after=0') { $t05Term = 'PASS' }
  elseif ($t -match 'cancel_acknowledged' -and $t -match 'active_after=0' -and $t -match 'worker_joinable=0') { $t05Term = 'PASS' }
  elseif ($t -match 'cancel_acknowledged' -and $t -match 'active_after=0') { $t05Term = 'PASS' }
  if (-not $cancelReqId -and $t -match 'cancel_acknowledged request_id=(\d+)') { $cancelReqId = $Matches[1] }

  # Late callback window after cancel ack
  Start-Sleep 3
  $lines = if (Test-Path $rt) { @(Get-Content $rt) } else { @() }
  $rid = if ($cancelReqId) { $cancelReqId } else { '1' }
  $cancelLine = ($lines | Select-String -Pattern "cancel_acknowledged request_id=$rid" | Select-Object -First 1)
  $lateHits = 0; $lateRejected = 0
  if ($cancelLine) {
    $after = $lines[($cancelLine.LineNumber)..($lines.Count - 1)]
    $lateHits = @($after | Where-Object { $_ -match "callback request_id=$rid|ui_update request_id=$rid|RESPONSE_START request_id=$rid" }).Count
    $lateRejected = @($after | Where-Object { $_ -match "reject.*request_id=$rid|late.*request_id=$rid|CHAT_SEND_REJECTED|stale|ignored.*request_id=$rid" }).Count
  }
  if ($lateHits -eq 0) { $t05Late = 'PASS_NO_LATE_CALLBACK' }
  elseif ($lateRejected -ge 1) { $t05Late = 'PASS_LATE_REJECTED' }
  else { $t05Late = 'FAIL_LATE_UNREJECTED' }

  # --- Recovery chain: uncanceled next request must correlate ---
  # Re-resolve controls after cancel; wait until active_after=0 settled.
  Start-Sleep 2
  $chat = [Map6CR]::FindCtrl($main, [Map6CR]::ID_CHAT)
  $send = [Map6CR]::FindCtrl($main, [Map6CR]::ID_SEND)
  $out = [Map6CR]::FindCtrl($main, [Map6CR]::ID_OUT)
  $outBeforeB = [Map6CR]::GetText($out)
  $promptB = "MAP6_B_RECOVER_$Stamp Reply with exactly three words: hello native chat"
  [Map6CR]::SetText($chat, $promptB)
  Start-Sleep -Milliseconds 250
  $beforeB = if (Test-Path $rt) { @(Get-Content $rt) } else { @() }
  [void][Map6CR]::SendMessageW($main, [Map6CR]::WM_COMMAND, [IntPtr]1204, $send)

  $waitSec = 180
  $dl = (Get-Date).AddSeconds($waitSec)
  while ((Get-Date) -lt $dl) {
    $afterB = if (Test-Path $rt) { @(Get-Content $rt) } else { @() }
    $new = @()
    if ($afterB.Count -gt $beforeB.Count) { $new = $afterB[$beforeB.Count..($afterB.Count - 1)] }
    $newJoined = ($new -join "`n")
    if ($newJoined -match 'cancel_requested') {
      # Only fail if recovery request itself was cancelled
      if ($newJoined -match "cancel_requested request_id=$recoverReqId" -or ($recoverReqId -and $newJoined -match "cancel_requested request_id=$recoverReqId")) {
        $recoverCancel = 'YES_UNEXPECTED'
      } elseif ($newJoined -match 'cancel_requested request_id=(\d+)') {
        $cand = $Matches[1]
        if ($recoverReqId -and $cand -eq $recoverReqId) { $recoverCancel = 'YES_UNEXPECTED' }
        elseif (-not $recoverReqId -and $newJoined -match 'CHAT_SEND_ARMED') {
          # if armed recover id known later
        }
      }
    }
    if ($newJoined -match 'CHAT_SEND_ARMED' -or $newJoined -match 'BACKEND_REQUEST_START') { $recoverArmed = 'PASS' }
    if ($newJoined -match 'DISPATCH_ID id=(\d+)') { $recoverDispId = $Matches[1] }
    if ($newJoined -match 'CHAT_SEND_ARMED[^\r\n]*request_id=(\d+)') { $recoverReqId = $Matches[1] }
    elseif ($newJoined -match 'BACKEND_REQUEST_START request_id=(\d+)') { if (-not $recoverReqId) { $recoverReqId = $Matches[1] } }
    if ($newJoined -match 'RESPONSE_START' -or $newJoined -match 'ui_update .*complete=1' -or $newJoined -match 'BACKEND_REQUEST_END[^\r\n]*cancel=0') {
      break
    }
    Start-Sleep -Milliseconds 400
  }

  Start-Sleep 1
  $out = [Map6CR]::FindCtrl($main, [Map6CR]::ID_OUT)
  $outAfterB = [Map6CR]::GetText($out)
  if ($outAfterB.Length -gt $outBeforeB.Length -and $outAfterB.Length -gt 0) { $recoverVisible = 'PASS' }

  $all = if (Test-Path $rt) { @(Get-Content $rt) } else { @() }
  $afterCancelIdx = 0
  if ($cancelLine) { $afterCancelIdx = $cancelLine.LineNumber }
  $post = if ($afterCancelIdx -lt $all.Count) { $all[$afterCancelIdx..($all.Count - 1)] } else { @() }
  $postJoined = ($post -join "`n")
  if ($postJoined -match 'CHAT_SEND_ARMED') { $recoverArmed = 'PASS' }
  if (-not $recoverReqId -and $postJoined -match 'CHAT_SEND_ARMED[^\r\n]*request_id=(\d+)') { $recoverReqId = $Matches[1] }
  if (-not $recoverDispId -and $postJoined -match 'DISPATCH_ID id=(\d+)') { $recoverDispId = $Matches[1] }
  # Prefer the last armed request after cancel as recovery id
  $armedPost = @($post | Where-Object { $_ -match 'CHAT_SEND_ARMED' })
  if ($armedPost.Count -ge 1 -and $armedPost[-1] -match 'request_id=(\d+)') { $recoverReqId = $Matches[1] }
  $dispPost = @($post | Where-Object { $_ -match 'DISPATCH_ID id=' })
  if ($dispPost.Count -ge 1 -and $dispPost[-1] -match 'DISPATCH_ID id=(\d+)') { $recoverDispId = $Matches[1] }

  if ($recoverReqId -and (@($post | Where-Object { $_ -match "cancel_requested request_id=$recoverReqId" }).Count -ge 1)) {
    $recoverCancel = 'YES_UNEXPECTED'
  }
  $hasArmedReq = ($recoverReqId -and (@($post | Where-Object { $_ -match 'CHAT_SEND_ARMED' -and $_ -match "request_id=$recoverReqId" }).Count -ge 1))
  $hasRespReq = ($recoverReqId -and (@($post | Where-Object { $_ -match "request_id=$recoverReqId" -and $_ -match 'RESPONSE_START|ui_update|BACKEND_REQUEST_END|callback' }).Count -ge 1))
  $hasDisp = ($recoverDispId -and (@($post | Where-Object { $_ -match "dispatch_id=$recoverDispId|DISPATCH_ID id=$recoverDispId" }).Count -ge 1))
  $backendOk = ($recoverReqId -and (@($post | Where-Object { $_ -match "BACKEND_REQUEST_END request_id=$recoverReqId" -and $_ -match 'cancel=0' }).Count -ge 1))
  $respStartOk = ($recoverReqId -and (@($post | Where-Object { $_ -match "RESPONSE_START" -and $_ -match "request_id=$recoverReqId" }).Count -ge 1)) `
    -or (@($post | Where-Object { $_ -match 'RESPONSE_START' }).Count -ge 1 -and $hasArmedReq)

  if ($hasArmedReq -and $hasDisp -and $recoverCancel -eq 'NO' -and $recoverVisible -eq 'PASS' -and ($hasRespReq -or $backendOk -or $respStartOk)) {
    $recoverCorr = 'PASS'
  } elseif ($hasArmedReq -and $hasDisp -and $recoverCancel -eq 'NO' -and ($hasRespReq -or $backendOk -or $respStartOk)) {
    $recoverCorr = 'PARTIAL_JOURNAL_NO_VISIBLE'
  } elseif ($recoverArmed -eq 'PASS' -and $recoverCancel -eq 'NO') {
    $recoverCorr = 'FAIL_ARMED_NO_RESPONSE'
  } else {
    $recoverCorr = 'FAIL'
  }

  try { if (-not $p.HasExited) { [void][Map6CR]::PostMessageW($main, [Map6CR]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero); Start-Sleep 2 } } catch {}
  try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
} else {
  try { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
}

Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue

$cancelChain = 'FAIL'
if ($t05Start -eq 'PASS' -and $t05Cancel -eq 'PASS' -and $t05Term -eq 'PASS' -and ($t05Late -match '^PASS')) {
  $cancelChain = 'PASS'
}
$recoverChain = 'FAIL'
if ($recoverArmed -eq 'PASS' -and $recoverCancel -eq 'NO' -and ($recoverCorr -eq 'PASS' -or $recoverCorr -eq 'PARTIAL_JOURNAL_NO_VISIBLE')) {
  # Map #6 requires correlated response; PARTIAL_JOURNAL counts only if journal has response evidence
  if ($recoverCorr -eq 'PASS') { $recoverChain = 'PASS' }
  elseif ($recoverCorr -eq 'PARTIAL_JOURNAL_NO_VISIBLE') { $recoverChain = 'PARTIAL_JOURNAL' }
}
$map6 = 'FAIL'
if ($p1 -eq 'PASS' -and $Sha -eq $ExpectSha -and $cancelChain -eq 'PASS' -and $recoverChain -eq 'PASS') { $map6 = 'PASS' }
elseif ($p1 -eq 'PASS' -and $cancelChain -eq 'PASS' -and $recoverChain -eq 'PARTIAL_JOURNAL') { $map6 = 'PARTIAL' }
elseif ($p1 -ne 'PASS') { $map6 = 'NOT_DEMONSTRATED' }
else { $map6 = 'FAIL' }

$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$receipt = @"
ISSUE49_CANCEL_RECOVERY_RECEIPT
ASOF_UTC=$asof
ACTIVE_TRACK=ISSUE_49
MAP=6
CANDIDATE=tip_integ_candidate_001
TIP_SHA256=$Sha
PRIOR_SHA256=1046C2B8394267D87CAD3970A16C34EFF231A5B84FEA6FF6D5A6BBD2622192CE
TIP_EXE=$TipExe
SUITE_STAMP=$Stamp
SESSION_ID=$session
RUN_ID=$runId
MAIN_HWND=$mainHex
MODEL_SELECT=$($script:modelSel)
RUNTIME_LOG=$rt
HARNESS=artifacts\_issue49_cancel_recovery_e2e.ps1
PRODUCT_CANCEL_PATH=$cancelPath
NO_CROSS_SHA_PASS=1
PRIOR_1046_T05_NE_MAP6=1

## Cancel chain (in-flight chat Stop=1210)
P1_HWND=$p1
T05_START=$t05Start
T05_CANCEL=$t05Cancel
T05_TERMINATE=$t05Term
T05_LATE=$t05Late
CANCEL_REQUEST_ID=$cancelReqId
CANCEL_CHAIN=$cancelChain

## Recovery chain (uncanceled subsequent request)
RECOVER_ARMED=$recoverArmed
RECOVER_DISPATCH_ID=$recoverDispId
RECOVER_REQUEST_ID=$recoverReqId
RECOVER_UNEXPECTED_CANCEL=$recoverCancel
RECOVER_VISIBLE=$recoverVisible
RECOVER_CORRELATED=$recoverCorr
OUTPUT_LEN_BEFORE_B=$($outBeforeB.Length)
OUTPUT_LEN_AFTER_B=$($outAfterB.Length)
RECOVERY_CHAIN=$recoverChain

## Gate
MAP6=$map6
ISSUE49_ADVANCE=$(if($map6 -eq 'PASS'){'5/11->6/11'}else{'HOLD_5/11'})
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MATURITY=82_UNCHANGED
E6CF_RESTORE=HELD
CC79_UNREPLACED=1
A4F_IMMUTABLE=1
TIP_MOVE_AUTHORIZED=0
INVENT_PASS=0
"@

$receiptPath = Join-Path $OutDir 'ISSUE49_CANCEL_RECOVERY_RECEIPT.txt'
Set-Content -LiteralPath $receiptPath -Value $receipt -Encoding ascii
Set-Content -LiteralPath (Join-Path $runDir 'CANCEL_RECOVERY_RECEIPT.txt') -Value $receipt -Encoding ascii
if (Test-Path $rt) {
  Set-Content -LiteralPath (Join-Path $OutDir 'ISSUE49_CANCEL_RECOVERY_JOURNAL.txt') -Value (Get-Content $rt -Raw) -Encoding utf8
}
Write-Host $receipt
Write-Host "RECEIPT=$receiptPath"
Write-Host "MAP6=$map6"
if ($map6 -eq 'PASS') { exit 0 } elseif ($map6 -eq 'PARTIAL') { exit 3 } else { exit 1 }
