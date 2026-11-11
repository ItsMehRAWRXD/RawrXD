#Requires -Version 5.1
# Uncanceled chat E2E — journal-polled during flight (no SendMessage while request live).
$ErrorActionPreference = 'Continue'
$__i49lock = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\ISSUE49_EXCLUSIVE.lock'
if (Test-Path -LiteralPath $__i49lock) {
  Write-Host 'SKIP: ISSUE49_EXCLUSIVE.lock present — not killing Native-Ext / not launching'
  exit 0
}
$ExpectSha = '1046C2B8394267D87CAD3970A16C34EFF231A5B84FEA6FF6D5A6BBD2622192CE'
$TipExe = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\package\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe'
$CandDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_integ_candidate_001'
$OutDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
if ($Sha -ne $ExpectSha) { Write-Host "SHA_DRIFT=$Sha"; exit 9 }
Get-Process -Name 'RawrXD-Win32IDE-Native*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2
Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class ChatE2E3 {
  public const uint WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_COMMAND=0x0111, WM_CLOSE=0x0010;
  public const uint CB_SETCURSEL=0x014E; public const int CBN_SELCHANGE=1;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
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
      if (c == "RawrXD_IDE_MainWindow" || c == "RawrXD_IDE_Window") { found = h; return false; }
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
}
"@
function Wait-Main([Diagnostics.Process]$proc, [int]$sec = 50) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    try { $proc.Refresh() } catch {}
    if ($proc.HasExited) { return [IntPtr]::Zero }
    $m = [ChatE2E3]::FindMain([uint32]$proc.Id)
    if ($m -ne [IntPtr]::Zero) { return $m }
    Start-Sleep -Milliseconds 250
  }
  return [IntPtr]::Zero
}
$runDir = Join-Path $CandDir ("chat_e2e_$Stamp")
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
$session = "integ_chat_e2e_$Stamp"; $runId = "integ_chat_e2e_run_$Stamp"
$env:RAWRXD_LOG_DIR = $runDir; $env:RAWRXD_CHAT_SESSION_ID = $session; $env:RAWRXD_CHAT_RUN_ID = $runId
$rt = Join-Path $runDir 'chat_runtime.log'; $dbg = Join-Path $runDir 'ollama_debug.log'
$prompt = "CHAT_E2E_$Stamp Reply with exactly three words: hello native chat"
$waitSec = 180
$p = Start-Process -FilePath $TipExe -WorkingDirectory $CandDir -PassThru -WindowStyle Normal
$main = Wait-Main $p 55
$mainHex='0x0'; $chatHwnd='0x0'; $sendHwnd='0x0'; $outHwnd='0x0'
$inputSet='FAIL'; $armed='FAIL'; $respStart='FAIL'; $uiComplete='FAIL'
$visible='FAIL'; $corr='FAIL'; $canceled='NO'
$dispatchId=''; $requestId=''; $outBefore=''; $outAfter=''
$ctxSel='FAIL'; $tokSel='FAIL'; $effCtx=''; $effTok=''; $recvOk='FAIL'
if ($main -ne [IntPtr]::Zero -and -not $p.HasExited) {
  $mainHex = ('0x{0:X}' -f $main.ToInt64()); Start-Sleep 10
  $chat = [ChatE2E3]::FindCtrl($main, 1202); $send = [ChatE2E3]::FindCtrl($main, 1204)
  $out = [ChatE2E3]::FindCtrl($main, 1203); $ctx = [ChatE2E3]::FindCtrl($main, 1220); $tok = [ChatE2E3]::FindCtrl($main, 1219)
  $chatHwnd = ('0x{0:X}' -f $chat.ToInt64()); $sendHwnd = ('0x{0:X}' -f $send.ToInt64()); $outHwnd = ('0x{0:X}' -f $out.ToInt64())
  [void][ChatE2E3]::SetForegroundWindow($main); Start-Sleep -Milliseconds 200
  if ($ctx -ne [IntPtr]::Zero) { [ChatE2E3]::SelectCombo($main, $ctx, 1220, 0); $ctxSel='PASS' }
  if ($tok -ne [IntPtr]::Zero) { [ChatE2E3]::SelectCombo($main, $tok, 1219, 0); $tokSel='PASS' }
  Start-Sleep -Milliseconds 400
  [ChatE2E3]::SetText($chat, $prompt); Start-Sleep -Milliseconds 200
  if (([ChatE2E3]::GetText($chat)) -match 'CHAT_E2E_') { $inputSet = 'PASS' }
  $outBefore = [ChatE2E3]::GetText($out)
  [void][ChatE2E3]::SendMessageW($main, [ChatE2E3]::WM_COMMAND, [IntPtr]1204, $send)
  $deadline = (Get-Date).AddSeconds($waitSec)
  while ((Get-Date) -lt $deadline) {
    if (Test-Path $rt) {
      $t = Get-Content $rt -Raw -ErrorAction SilentlyContinue
      if ($t -match 'cancel_requested') { $canceled = 'YES_UNEXPECTED' }
      if ($t -match 'CHAT_SEND_ARMED') { $armed = 'PASS' }
      if ($t -match 'RESPONSE_START') { $respStart = 'PASS' }
      if ($t -match 'ui_update .*complete=1') { $uiComplete = 'PASS' }
      elseif ($t -match 'BACKEND_REQUEST_END request_id=\d+ cancel=0') { $uiComplete = 'PASS_BACKEND_END_NO_CANCEL' }
      if ($t -match 'DISPATCH_ID id=(\d+)') { $dispatchId = $Matches[1] }
      if ($t -match 'CHAT_SEND_ARMED[^\r\n]*request_id=(\d+)') { $requestId = $Matches[1] }
    }
    if (Test-Path $dbg) {
      $d = Get-Content $dbg -Raw -ErrorAction SilentlyContinue
      if ($d -match 'EFFECTIVE_CONTEXT=(\d+)') { $effCtx = $Matches[1] }
      if ($d -match 'MAX_OUTPUT_TOKENS=(\d+)') { $effTok = $Matches[1] }
      if ($d -match 'ReceiveResponse ok') { $recvOk = 'PASS' }
    }
    if ($armed -eq 'PASS' -and $canceled -eq 'NO' -and ($uiComplete -match '^PASS' -or $respStart -eq 'PASS')) { break }
    Start-Sleep -Milliseconds 400
  }
  Start-Sleep 1
  $out = [ChatE2E3]::FindCtrl($main, 1203); $outAfter = [ChatE2E3]::GetText($out)
  if ($outAfter.Length -gt $outBefore.Length -and $outAfter.Length -gt 0) { $visible = 'PASS' }
  $lines = if (Test-Path $rt) { @(Get-Content $rt) } else { @() }
  $joined = ($lines -join "`n")
  if ($joined -match 'CHAT_SEND_ARMED') { $armed = 'PASS' }
  if ($joined -match 'RESPONSE_START') { $respStart = 'PASS' }
  if ($joined -match 'ui_update .*complete=1') { $uiComplete = 'PASS' }
  if ($joined -match 'BACKEND_REQUEST_END[^\r\n]*cancel=0') { if ($uiComplete -ne 'PASS') { $uiComplete = 'PASS_BACKEND_END_NO_CANCEL' } }
  if ($joined -match 'cancel_requested') { $canceled = 'YES_UNEXPECTED' }
  if (-not $dispatchId -and $joined -match 'DISPATCH_ID id=(\d+)') { $dispatchId = $Matches[1] }
  if (-not $requestId -and $joined -match 'CHAT_SEND_ARMED[^\r\n]*request_id=(\d+)') { $requestId = $Matches[1] }
  $hasArmedReq = ($requestId -and (@($lines | Where-Object { $_ -match 'CHAT_SEND_ARMED' -and $_ -match "request_id=$requestId" }).Count -ge 1))
  $hasRespReq = ($requestId -and (@($lines | Where-Object { $_ -match "request_id=$requestId" -and $_ -match 'RESPONSE_START|ui_update|BACKEND_REQUEST_END|callback' }).Count -ge 1))
  $hasDisp = ($dispatchId -and (@($lines | Where-Object { $_ -match "dispatch_id=$dispatchId|DISPATCH_ID id=$dispatchId" }).Count -ge 1))
  if ($hasArmedReq -and $hasDisp -and $canceled -eq 'NO' -and $visible -eq 'PASS' -and $armed -eq 'PASS' -and ($hasRespReq -or ($uiComplete -match '^PASS') -or $respStart -eq 'PASS')) { $corr = 'PASS' }
  elseif ($hasArmedReq -and $hasDisp -and $canceled -eq 'NO' -and $armed -eq 'PASS' -and ($respStart -eq 'PASS' -or ($uiComplete -match '^PASS'))) { $corr = 'PARTIAL_JOURNAL_NO_VISIBLE' }
  else { $corr = 'FAIL' }
  try { if (-not $p.HasExited) { [void][ChatE2E3]::PostMessageW($main, [ChatE2E3]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero); Start-Sleep 2 } } catch {}
  try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
} else { try { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {} }
$e2e = if ($corr -eq 'PASS' -and $inputSet -eq 'PASS' -and $canceled -eq 'NO') { 'PASS' } else { 'FAIL' }
$receipt = @"
TIP_SHA256=$Sha
SUITE_STAMP=$Stamp
SESSION_ID=$session
RUN_ID=$runId
RUNTIME_LOG=$rt
MAIN_HWND=$mainHex
CHAT_INPUT_HWND=$chatHwnd
SEND_HWND=$sendHwnd
CHAT_OUTPUT_HWND=$outHwnd
CHAT_INPUT_SET=$inputSet
CONTEXT_COMBO_8K=$ctxSel
MAXTOK_COMBO_512=$tokSel
EFFECTIVE_CONTEXT=$effCtx
MAX_OUTPUT_TOKENS=$effTok
RECEIVE_RESPONSE_OK=$recvOk
DISPATCH_ID=$dispatchId
REQUEST_ID=$requestId
CHAT_SEND_ARMED=$armed
RESPONSE_START=$respStart
UI_OR_BACKEND_COMPLETE=$uiComplete
VISIBLE_NATIVE_CHAT_OUTPUT=$visible
UNEXPECTED_CANCEL=$canceled
E2E_CHAT_RESPONSE_CORRELATED=$corr
E2E_UNCANCELED_CHAT=$e2e
OUTPUT_LEN_BEFORE=$($outBefore.Length)
OUTPUT_LEN_AFTER=$($outAfter.Length)
WAIT_SEC=$waitSec
HARNESS_NOTE=POST_SEND_JOURNAL_POLL_NO_UI_SENDMESSAGE_DURING_FLIGHT
PROMOTE=0
MATURITY=82_UNCHANGED
"@
Set-Content (Join-Path $OutDir 'INTEG_CANDIDATE_001_CHAT_E2E_UNCANCELED_RECEIPT.txt') $receipt -Encoding ASCII
Set-Content (Join-Path $runDir 'RECEIPT.txt') $receipt -Encoding ASCII
Set-Content (Join-Path $OutDir 'INTEG_CANDIDATE_001_CHAT_E2E_UNCANCELED_JOURNAL.txt') $(if (Test-Path $rt) { Get-Content $rt -Raw } else { 'JOURNAL_ABSENT' }) -Encoding UTF8
Write-Host '==== CHAT_E2E_UNCANCELED ===='; Write-Host $receipt
if (Test-Path $rt) { Write-Host '==== JOURNAL ===='; Get-Content $rt }
if (Test-Path $dbg) { Write-Host '==== OLLAMA_DEBUG ===='; Get-Content $dbg }
exit $(if ($e2e -eq 'PASS') { 0 } else { 2 })

