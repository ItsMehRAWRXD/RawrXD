param(
  [string]$TipExe = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$ExpectSha = "A190495C58E49D97E155771026E56899FAB116AC1001BE56A448CE7BE0705D36",
  [string]$OutDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\eo_freeze_e950",
  [int]$IdleTimeoutMs = 90000,
  [int]$BootWaitSec = 5
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runlog = Join-Path $OutDir ("freeze_eo_run_" + $stamp + ".txt")
$receipt = Join-Path $OutDir "FREEZE_EXACTLY_ONCE_RECEIPT.txt"
$mdPath = "F:\rawrxd\evidence\RELEASE_FREEZE_001\FREEZE_EXACTLY_ONCE.md"
$rt = Join-Path $LogDir "chat_runtime.log"
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class FreezeEo {
  public const uint WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_COMMAND=0x0111;
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  public static void SetText(IntPtr h, string t) { SendMessageW(h, WM_SETTEXT, IntPtr.Zero, t ?? ""); }
  public static string GetText(IntPtr h) {
    int len = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    if (len < 0) len = 0;
    var sb = new StringBuilder(len + 8);
    SendMessageW(h, WM_GETTEXT, (IntPtr)sb.Capacity, sb);
    return sb.ToString();
  }
  public static IntPtr FindCtrl(IntPtr parent, int wantId, string classPart) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(parent, (h, lp) => {
      int id = GetDlgCtrlID(h);
      var sb = new StringBuilder(64); GetClassNameW(h, sb, 64);
      if (id == wantId && sb.ToString().IndexOf(classPart, StringComparison.OrdinalIgnoreCase) >= 0) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
public static class FreezeEoKeys {
  public const uint KEYEVENTF_KEYUP=0x0002;
  [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr extra);
  public static void CtrlEnter() {
    keybd_event(0x11, 0, 0, UIntPtr.Zero);
    keybd_event(0x0D, 0, 0, UIntPtr.Zero);
    keybd_event(0x0D, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
    keybd_event(0x11, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
  }
}
public static class FreezeEoHwnd {
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint wpid; GetWindowThreadProcessId(h, out wpid);
      if (wpid != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256); GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c == "RawrXD_IDE_MainWindow" || c == "RawrXD_IDE_Window") { found = h; return false; }
      if (found == IntPtr.Zero) found = h;
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@

$hash = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "TIP_EXE=$TipExe SHA=$hash EXPECT=$ExpectSha"
if ($hash -ne $ExpectSha) {
  Set-Content $receipt "EXACTLY_ONCE=FAIL`nREASON=SHA_MISMATCH`nMEASURED=$hash`nEXPECT=$ExpectSha`nPROMOTE=0"
  exit 2
}
Get-Process -Name "RawrXD-Win32IDE-Native*","debuggee_fixture" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
if (Test-Path $rt) { Remove-Item $rt -Force }
$env:RAWRXD_LOG_DIR = $LogDir
$fixture = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp"
$p = Start-Process -FilePath $TipExe -ArgumentList @($fixture) -PassThru -WindowStyle Normal
Log ("PID=" + $p.Id)
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log ("EXIT_EARLY " + $p.ExitCode); break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $by = [FreezeEoHwnd]::FindMain([uint32]$p.Id)
  if ($by -ne [IntPtr]::Zero) { $main = $by; break }
}
Log ("MAIN=0x{0:X}" -f $main.ToInt64())
if ($main -eq [IntPtr]::Zero) {
  Set-Content $receipt "EXACTLY_ONCE=FAIL`nREASON=no_main_hwnd`nPROMOTE=0"
  exit 3
}
$chat = [FreezeEo]::FindCtrl($main, 1202, "Edit")
$send = [FreezeEo]::FindCtrl($main, 1204, "Button")
$tr = [FreezeEo]::FindCtrl($main, 1203, "Edit")
Log ("CHAT=0x{0:X} SEND=0x{1:X} TR=0x{2:X}" -f $chat.ToInt64(), $send.ToInt64(), $tr.ToInt64())
if ($chat -eq [IntPtr]::Zero -or $send -eq [IntPtr]::Zero) {
  Set-Content $receipt "EXACTLY_ONCE=FAIL`nREASON=controls_missing`nPROMOTE=0"
  try { Stop-Process -Id $p.Id -Force } catch {}
  exit 4
}
function Read-Rt { if (Test-Path $rt) { @(Get-Content $rt -ErrorAction SilentlyContinue) } else { @() } }
function Count-Pat([string[]]$lines, [string]$pat) { @($lines | Where-Object { $_ -match $pat }).Count }
function Wait-SubmitComplete([int]$minSubmit, [int]$timeoutMs) {
  $deadline = [Environment]::TickCount64 + $timeoutMs
  while ([Environment]::TickCount64 -lt $deadline) {
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { Log "IDLE_ABORT exited"; return $false }
    $lines = Read-Rt
    $sub = Count-Pat $lines '^exactly_once_submit'
    $done = Count-Pat $lines 'ui_update .*complete=1'
    if ($sub -ge $minSubmit -and $done -ge $minSubmit) { Log ("IDLE ok submit=$sub done=$done"); return $true }
    Start-Sleep -Milliseconds 400
  }
  $lines = Read-Rt
  Log ("IDLE_TIMEOUT submit=" + (Count-Pat $lines '^exactly_once_submit') + " done=" + (Count-Pat $lines 'ui_update .*complete=1'))
  return $false
}
Start-Sleep -Seconds $BootWaitSec
$bootSub = Count-Pat (Read-Rt) '^exactly_once_submit'
if ($bootSub -gt 0) { [void](Wait-SubmitComplete $bootSub 30000) }

$before = Read-Rt
$bSub = Count-Pat $before '^exactly_once_submit'
$bReq = Count-Pat $before '^request_started'
$bDone = Count-Pat $before 'ui_update .*complete=1'
$bRej = Count-Pat $before '^exactly_once_reject'
[FreezeEo]::SetText($chat, "freeze-eo-send-1")
Start-Sleep -Milliseconds 150
[void][FreezeEo]::SendMessageW($main, 0x0111, [IntPtr]1204, $send)
Log "SEND1_CLICK"
Start-Sleep -Milliseconds 500
[FreezeEo]::SetText($chat, "freeze-eo-busy-should-reject")
[void][FreezeEo]::SendMessageW($main, 0x0111, [IntPtr]1204, $send)
Log "SEND_BUSY_CLICK"
Start-Sleep -Milliseconds 400
$mid = Read-Rt
$dRejBusy = (Count-Pat $mid '^exactly_once_reject') - $bRej
Log ("BUSY_DELTA reject=$dRejBusy")
[void](Wait-SubmitComplete ($bSub + 1) $IdleTimeoutMs)
$after1 = Read-Rt
$dSub1 = (Count-Pat $after1 '^exactly_once_submit') - $bSub
$dReq1 = (Count-Pat $after1 '^request_started') - $bReq
$dDone1 = (Count-Pat $after1 'ui_update .*complete=1') - $bDone
Log ("SEND1_DELTA submit=$dSub1 req=$dReq1 done=$dDone1")

$b2 = Read-Rt
$b2Sub = Count-Pat $b2 '^exactly_once_submit'
$b2Req = Count-Pat $b2 '^request_started'
$b2Done = Count-Pat $b2 'ui_update .*complete=1'
[FreezeEo]::SetText($chat, "freeze-eo-send-2")
Start-Sleep -Milliseconds 100
[void][FreezeEo]::SendMessageW($main, 0x0111, [IntPtr]1204, $send)
Log "SEND2_CLICK"
[void](Wait-SubmitComplete ($b2Sub + 1) $IdleTimeoutMs)
$after2 = Read-Rt
$dSub2 = (Count-Pat $after2 '^exactly_once_submit') - $b2Sub
$dReq2 = (Count-Pat $after2 '^request_started') - $b2Req
$dDone2 = (Count-Pat $after2 'ui_update .*complete=1') - $b2Done
Log ("SEND2_DELTA submit=$dSub2 req=$dReq2 done=$dDone2")

$b3 = Read-Rt
$b3Sub = Count-Pat $b3 '^exactly_once_submit'
[FreezeEo]::SetText($chat, "line1")
[void][FreezeEo]::SetForegroundWindow($main)
[void][FreezeEo]::SetFocus($chat)
Start-Sleep -Milliseconds 100
[void][FreezeEo]::PostMessageW($chat, 0x0102, [IntPtr]0x0D, [IntPtr]::Zero)
Start-Sleep -Milliseconds 400
$chatAfterEnter = [FreezeEo]::GetText($chat)
$dSubEnter = (Count-Pat (Read-Rt) '^exactly_once_submit') - $b3Sub
$enterNewline = ($chatAfterEnter -match "`r`n|`n")
Log ("ENTER_ALONE dSubmit=$dSubEnter newline=$enterNewline len=" + $chatAfterEnter.Length)

$b4 = Read-Rt
$b4Sub = Count-Pat $b4 '^exactly_once_submit'
$b4Req = Count-Pat $b4 '^request_started'
$b4Done = Count-Pat $b4 'ui_update .*complete=1'
[FreezeEo]::SetText($chat, "freeze-eo-ctrl-enter")
[void][FreezeEo]::SetForegroundWindow($main)
[void][FreezeEo]::SetFocus($chat)
Start-Sleep -Milliseconds 100
[void][FreezeEo]::SetFocus($chat)
Start-Sleep -Milliseconds 100
[FreezeEoKeys]::CtrlEnter()
Log "CTRL_ENTER_SENDINPUT"
Start-Sleep -Milliseconds 800
[void](Wait-SubmitComplete ($b4Sub + 1) ([Math]::Min($IdleTimeoutMs, 60000)))
$a4 = Read-Rt
$dSubCE = (Count-Pat $a4 '^exactly_once_submit') - $b4Sub
$dReqCE = (Count-Pat $a4 '^request_started') - $b4Req
$dDoneCE = (Count-Pat $a4 'ui_update .*complete=1') - $b4Done
Log ("CTRL_ENTER_DELTA submit=$dSubCE req=$dReqCE done=$dDoneCE")

$vis = ""
try { if ($tr -ne [IntPtr]::Zero) { $vis = [FreezeEo]::GetText($tr) } } catch {}
Set-Content (Join-Path $LogDir ("visible_transcript_" + $stamp + ".txt")) -Value $vis -Encoding UTF8
if (Test-Path $rt) { Copy-Item $rt (Join-Path $OutDir ("freeze_eo_runtime_" + $stamp + ".log")) -Force }

$final = Read-Rt
$submitU = @(); $reqU = @(); $doneU = @()
foreach ($line in $final) {
  if ($line -match 'exactly_once_submit session=\d+ request_id=(\d+)') { $submitU += [int]$Matches[1] }
  if ($line -match '^request_started request_id=(\d+)') { $reqU += [int]$Matches[1] }
  if ($line -match 'ui_update request_id=(\d+).*complete=1') { $doneU += [int]$Matches[1] }
}
$submitU = @($submitU | Select-Object -Unique)
$reqU = @($reqU | Select-Object -Unique)
$doneU = @($doneU | Select-Object -Unique)
Log ("SUBMIT_IDS=" + ($submitU -join ',') + " REQ=" + ($reqU -join ',') + " DONE=" + ($doneU -join ','))

$send1ok = ($dSub1 -eq 1 -and $dReq1 -eq 1 -and $dDone1 -ge 1)
$send2ok = ($dSub2 -eq 1 -and $dReq2 -eq 1 -and $dDone2 -ge 1)
$busyok = ($dRejBusy -ge 1)
$enterok = ($dSubEnter -eq 0)
$ctrlok = ($dSubCE -eq 1 -and $dReqCE -eq 1 -and $dDoneCE -ge 1)
$idsAligned = $true
foreach ($id in $submitU) {
  if ($reqU -notcontains $id) { $idsAligned = $false }
  if ($doneU -notcontains $id) { $idsAligned = $false }
}
$enoughSends = ($submitU.Count -ge 2)
$reason = @()
if (-not $send1ok) { $reason += "SEND1_NOT_1_1" }
if (-not $send2ok) { $reason += "SEND2_NOT_1_1" }
if (-not $busyok) { $reason += "BUSY_REJECT_MISSING" }
if (-not $enterok) { $reason += "ENTER_TRIGGERED_SUBMIT" }
if (-not $ctrlok) { $reason += "CTRL_ENTER_NOT_1_1" }
if (-not $idsAligned) { $reason += "REQUEST_ID_CHAIN_MISALIGN" }
if (-not $enoughSends) { $reason += "INSUFFICIENT_SUBMIT_IDS" }
$eo = "FAIL"
if ($send1ok -and $send2ok -and $busyok -and $enterok -and $ctrlok -and $idsAligned -and $enoughSends) { $eo = "PASS" }
try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } } catch {}

$rec = @(
  "EXACTLY_ONCE=$eo",
  "SHA=$hash",
  "SHA_MATCH=1",
  "SEND1_1_1=$send1ok dSub=$dSub1 dReq=$dReq1 dDone=$dDone1",
  "SEND2_1_1=$send2ok dSub=$dSub2 dReq=$dReq2 dDone=$dDone2",
  "BUSY_REJECT=$busyok dReject=$dRejBusy",
  "ENTER_NEWLINE_ONLY=$enterok dSubEnter=$dSubEnter",
  "CTRL_ENTER_1_1=$ctrlok dSub=$dSubCE dReq=$dReqCE dDone=$dDoneCE",
  "REQUEST_IDS_ALIGNED=$idsAligned",
  "SUBMIT_IDS=$($submitU -join ',')",
  "REQ_IDS=$($reqU -join ',')",
  "DONE_IDS=$($doneU -join ',')",
  "REASON=$($reason -join ',')",
  "TIP_EXE=$TipExe",
  "TRANSCRIPT_LEN=$($vis.Length)",
  "RUNLOG=$runlog",
  "CHAT_RUNTIME=$rt",
  "PROMOTE=0",
  "CERTIFIED=0",
  "MATURITY=82%"
)
$rec | Tee-Object -FilePath $receipt
@(
  "# FREEZE_EXACTLY_ONCE",
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))",
  "EXACTLY_ONCE=$eo",
  "SHA=$hash",
  "SEND1=$send1ok BUSY=$busyok SEND2=$send2ok ENTER=$enterok CTRL_ENTER=$ctrlok ALIGN=$idsAligned",
  "REASON=$($reason -join ',')",
  "PROMOTE=0",
  "MATURITY=82%"
) | Set-Content $mdPath -Encoding UTF8
if ($eo -eq "PASS") { exit 0 } else { exit 5 }





