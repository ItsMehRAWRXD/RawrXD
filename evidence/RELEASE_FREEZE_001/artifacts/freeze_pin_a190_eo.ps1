param(
  [string]$TipExe = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RawrXD-FreezeEO-A190.exe",
  [string]$ExpectSha = "35C22E8AAFC1E9B30E40C2505AF7B4DEB66BDFB73D56B75D31C937D8C70D8563",
  [string]$PreferModel = "nemotron-3-nano:4b",
  [string]$OutDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\eo_pin_a190",
  [int]$IdleTimeoutMs = 240000,
  [int]$BootWaitSec = 12
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
using System; using System.Runtime.InteropServices; using System.Text;
public static class PinEoA {
  public const uint WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_COMMAND=0x0111;
  public const uint CB_GETCOUNT=0x0146, CB_GETLBTEXT=0x0148, CB_SETCURSEL=0x014E;
  public const ushort CBN_SELCHANGE=1, CBN_SELENDOK=9;
  public const uint KEYEVENTF_KEYUP=0x0002;
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool f);
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
    public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; public uint p1; public uint p2;
  }
  [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  public static void SetText(IntPtr h, string t) { SendMessageW(h, WM_SETTEXT, IntPtr.Zero, t ?? ""); }
  public static string GetText(IntPtr h) {
    int len = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    if (len < 0) len = 0;
    var sb = new StringBuilder(len + 8);
    SendMessageW(h, WM_GETTEXT, (IntPtr)sb.Capacity, sb);
    return sb.ToString();
  }
  static EnumChildProc _findCb;
  static IntPtr _findHit;
  static int _wantId;
  static string _classPart;
  public static IntPtr FindCtrl(IntPtr parent, int wantId, string classPart) {
    _findHit = IntPtr.Zero; _wantId = wantId; _classPart = classPart ?? "";
    if (_findCb == null) {
      _findCb = (h, lp) => {
        int id = GetDlgCtrlID(h);
        if (id != _wantId) return true;
        var sb = new StringBuilder(64); GetClassNameW(h, sb, 64);
        if (_classPart.Length == 0 || sb.ToString().IndexOf(_classPart, StringComparison.OrdinalIgnoreCase) >= 0) {
          _findHit = h; return false;
        }
        return true;
      };
    }
    EnumChildWindows(parent, _findCb, IntPtr.Zero);
    if (_findHit == IntPtr.Zero && !string.IsNullOrEmpty(classPart)) {
      // fallback: id-only match
      _classPart = "";
      EnumChildWindows(parent, _findCb, IntPtr.Zero);
    }
    return _findHit;
  }
  public static string SelectModel(IntPtr main, IntPtr combo, string prefer) {
    int n = (int)SendMessageW(combo, CB_GETCOUNT, IntPtr.Zero, IntPtr.Zero);
    int hit = -1; string hitText = "";
    for (int i = 0; i < n; i++) {
      var sb = new StringBuilder(512); SendMessageW(combo, CB_GETLBTEXT, (IntPtr)i, sb);
      string t = sb.ToString();
      if (t.IndexOf(prefer, StringComparison.OrdinalIgnoreCase) >= 0) { hit = i; hitText = t; break; }
      if (hit < 0 && (t.IndexOf("llama3.2:3b", StringComparison.OrdinalIgnoreCase) >= 0 ||
          t.IndexOf("nemotron-3-nano", StringComparison.OrdinalIgnoreCase) >= 0 ||
          t.IndexOf("qwen2.5-coder:1.5b", StringComparison.OrdinalIgnoreCase) >= 0 ||
          t.IndexOf("tinyllama", StringComparison.OrdinalIgnoreCase) >= 0)) { hit = i; hitText = t; }
    }
    if (hit < 0 && n > 0) { var sb = new StringBuilder(512); SendMessageW(combo, CB_GETLBTEXT, IntPtr.Zero, sb); hit = 0; hitText = sb.ToString(); }
    if (hit >= 0) {
      SendMessageW(combo, CB_SETCURSEL, (IntPtr)hit, IntPtr.Zero);
      SendMessageW(main, WM_COMMAND, (IntPtr)((CBN_SELCHANGE << 16) | 1206), combo);
      SendMessageW(main, WM_COMMAND, (IntPtr)((CBN_SELENDOK << 16) | 1206), combo);
    }
    return hitText;
  }
  static uint ideTid; static uint myTid; static bool attached;
  public static void FocusChat(IntPtr main, IntPtr chat) {
    uint pid = 0; ideTid = GetWindowThreadProcessId(main, out pid); myTid = GetCurrentThreadId();
    if (!attached && ideTid != 0 && ideTid != myTid) { attached = AttachThreadInput(myTid, ideTid, true); }
    ShowWindow(main, 9); BringWindowToTop(main); SetForegroundWindow(main); SetFocus(chat);
  }
  public static void Detach() { if (attached) { AttachThreadInput(myTid, ideTid, false); attached = false; } }
  static void Key(ushort vk, bool up) {
    INPUT[] a = new INPUT[1]; a[0].type = 1; a[0].ki.wVk = vk;
    if (up) a[0].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(1, a, Marshal.SizeOf(typeof(INPUT)));
  }
  public static void CtrlEnterLatched() {
    Key(0x11, false); System.Threading.Thread.Sleep(100);
    Key(0x0D, false); System.Threading.Thread.Sleep(80);
    Key(0x0D, true); System.Threading.Thread.Sleep(50);
    Key(0x11, true);
  }
  // AIM-parity single batch (proven submit path)
  public static void CtrlEnterAim() {
    INPUT[] a = new INPUT[4];
    a[0].type = 1; a[0].ki.wVk = 0x11;
    a[1].type = 1; a[1].ki.wVk = 0x0D;
    a[2].type = 1; a[2].ki.wVk = 0x0D; a[2].ki.dwFlags = KEYEVENTF_KEYUP;
    a[3].type = 1; a[3].ki.wVk = 0x11; a[3].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(4, a, Marshal.SizeOf(typeof(INPUT)));
  }
}
public static class PinEoAHwnd {
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
      if (sb.ToString().Contains("RawrXD_IDE")) { found = h; return false; }
      if (found == IntPtr.Zero) found = h;
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@

if (-not (Test-Path $TipExe)) {
  Set-Content $receipt "EXACTLY_ONCE=FAIL`nREASON=TIP_EXE_MISSING`nTIP_EXE=$TipExe`nPROMOTE=0"
  exit 2
}
$hash = (certutil -hashfile $TipExe SHA256 | Where-Object { $_ -match '^[0-9A-Fa-f]{64}$' }).ToUpper()
Log "TIP_EXE=$TipExe SHA=$hash EXPECT=$ExpectSha PREFER_MODEL=$PreferModel PIN=A190"
if ($hash -ne $ExpectSha) {
  Set-Content $receipt "EXACTLY_ONCE=FAIL`nREASON=SHA_MISMATCH`nMEASURED=$hash`nEXPECT=$ExpectSha`nPROMOTE=0`nLAW=NEVER_OVERWRITE_A190_WITH_430B"
  exit 2
}
# Kill ONLY this tip image name — never Stop-Process FreezeEO/Seal (Issue#49 race) and never touch Ext/430B.
$tipBase = [IO.Path]::GetFileNameWithoutExtension($TipExe)
Get-Process -Name $tipBase -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2
# Fresh runtime log per run (avoid interleaved harness pollution)
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
if (Test-Path $rt) { Remove-Item $rt -Force }
Get-ChildItem $LogDir -Filter "chat_runtime*.log" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_CHAT_SESSION_ID = "pin_eo_$stamp"
$env:RAWRXD_CHAT_RUN_ID = "pin_eorun_$stamp"
$p = Start-Process -FilePath $TipExe -PassThru -WindowStyle Normal
Log ("PID=" + $p.Id)
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 80; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log ("EXIT_EARLY " + $p.ExitCode); break }
  # Prefer classed IDE window over transient MainWindowHandle
  $by = [PinEoAHwnd]::FindMain([uint32]$p.Id)
  if ($by -ne [IntPtr]::Zero) { $main = $by; break }
}
Log ("MAIN=0x{0:X}" -f $main.ToInt64())
if ($main -eq [IntPtr]::Zero) {
  Set-Content $receipt "EXACTLY_ONCE=FAIL`nREASON=no_main_hwnd`nSHA=$hash`nPROMOTE=0"
  exit 3
}
Start-Sleep -Seconds $BootWaitSec
$chat = [IntPtr]::Zero; $send = [IntPtr]::Zero; $tr = [IntPtr]::Zero; $combo = [IntPtr]::Zero
for ($i = 0; $i -lt 40; $i++) {
  $by = [PinEoAHwnd]::FindMain([uint32]$p.Id)
  if ($by -ne [IntPtr]::Zero) { $main = $by }
  $chat = [PinEoA]::FindCtrl($main, 1202, "Edit")
  $send = [PinEoA]::FindCtrl($main, 1204, "Button")
  $tr = [PinEoA]::FindCtrl($main, 1203, "Edit")
  $combo = [PinEoA]::FindCtrl($main, 1206, "ComboBox")
  if ($chat -ne [IntPtr]::Zero -and $send -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 500
}
Log ("MAIN2=0x{0:X} CHAT=0x{1:X} SEND=0x{2:X} TR=0x{3:X} COMBO=0x{4:X}" -f $main.ToInt64(), $chat.ToInt64(), $send.ToInt64(), $tr.ToInt64(), $combo.ToInt64())
if ($chat -eq [IntPtr]::Zero -or $send -eq [IntPtr]::Zero) {
  Set-Content $receipt "EXACTLY_ONCE=FAIL`nREASON=controls_missing`nSHA=$hash`nPROMOTE=0"
  try { Stop-Process -Id $p.Id -Force } catch {}
  exit 4
}
if ($combo -ne [IntPtr]::Zero) {
  $sel = [PinEoA]::SelectModel($main, $combo, $PreferModel)
  Log "MODEL_SELECT=$sel"
  Start-Sleep -Milliseconds 500
}
function Read-Rt { if (Test-Path $rt) { @(Get-Content $rt -ErrorAction SilentlyContinue) } else { @() } }
function Count-Pat([string[]]$lines, [string]$pat) { @($lines | Where-Object { $_ -match $pat }).Count }
function Wait-SubmitComplete([int]$minSubmit, [int]$timeoutMs) {
  $deadline = [Environment]::TickCount64 + $timeoutMs
  while ([Environment]::TickCount64 -lt $deadline) {
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { Log ("IDLE_ABORT exited code=" + $p.ExitCode); return $false }
    $lines = Read-Rt
    $sub = Count-Pat $lines '^exactly_once_submit'
    $done = Count-Pat $lines 'ui_update .*complete=1'
    if ($sub -ge $minSubmit -and $done -ge $minSubmit) { Log ("IDLE ok submit=$sub done=$done"); return $true }
    Start-Sleep -Milliseconds 500
  }
  $lines = Read-Rt
  Log ("IDLE_TIMEOUT submit=" + (Count-Pat $lines '^exactly_once_submit') + " done=" + (Count-Pat $lines 'ui_update .*complete=1'))
  return $false
}
function Wait-ReqComplete([int]$reqId, [int]$timeoutMs) {
  $deadline = [Environment]::TickCount64 + $timeoutMs
  $pat = "ui_update request_id=$reqId .*complete=1"
  while ([Environment]::TickCount64 -lt $deadline) {
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { Log ("REQ_ABORT exited code=" + $p.ExitCode + " waiting req=$reqId"); return $false }
    $lines = Read-Rt
    if ((Count-Pat $lines $pat) -ge 1) { Log ("REQ_COMPLETE id=$reqId"); return $true }
    Start-Sleep -Milliseconds 500
  }
  Log ("REQ_TIMEOUT id=$reqId")
  return $false
}

$before = Read-Rt
$bSub = Count-Pat $before '^exactly_once_submit'
$bReq = Count-Pat $before '^request_started'
$bDone = Count-Pat $before 'ui_update .*complete=1'
$bRej = Count-Pat $before '^exactly_once_reject'
[PinEoA]::SetText($chat, "Reply with only: OK1"); Start-Sleep -Milliseconds 150
[void][PinEoA]::SendMessageW($main, 0x0111, [IntPtr]1204, $send); Log "SEND1_CLICK"
# Busy probe while request 1 still in-flight (short delay only)
Start-Sleep -Milliseconds 120
[PinEoA]::SetText($chat, "freeze-eo-busy-should-reject")
[void][PinEoA]::SendMessageW($main, 0x0111, [IntPtr]1204, $send); Log "SEND_BUSY_CLICK"; Start-Sleep -Milliseconds 500
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
[PinEoA]::SetText($chat, "Reply with only: OK2"); Start-Sleep -Milliseconds 100
[void][PinEoA]::SendMessageW($main, 0x0111, [IntPtr]1204, $send); Log "SEND2_CLICK"
[void](Wait-SubmitComplete ($b2Sub + 1) $IdleTimeoutMs)
$after2 = Read-Rt
$dSub2 = (Count-Pat $after2 '^exactly_once_submit') - $b2Sub
$dReq2 = (Count-Pat $after2 '^request_started') - $b2Req
$dDone2 = (Count-Pat $after2 'ui_update .*complete=1') - $b2Done
Log ("SEND2_DELTA submit=$dSub2 req=$dReq2 done=$dDone2")

$b3 = Read-Rt
$b3Sub = Count-Pat $b3 '^exactly_once_submit'
[PinEoA]::FocusChat($main, $chat)
[PinEoA]::SetText($chat, "line1"); Start-Sleep -Milliseconds 100
[void][PinEoA]::PostMessageW($chat, 0x0102, [IntPtr]0x0D, [IntPtr]::Zero); Start-Sleep -Milliseconds 400
$chatAfterEnter = [PinEoA]::GetText($chat)
$dSubEnter = (Count-Pat (Read-Rt) '^exactly_once_submit') - $b3Sub
Log ("ENTER_ALONE dSubmit=$dSubEnter newline=" + ($chatAfterEnter -match "`r`n|`n") + " len=" + $chatAfterEnter.Length)

$b4 = Read-Rt
$b4Sub = Count-Pat $b4 '^exactly_once_submit'
$b4Req = Count-Pat $b4 '^request_started'
$b4Done = Count-Pat $b4 'ui_update .*complete=1'
[PinEoA]::SetText($chat, "Reply with only: OK3")
[PinEoA]::FocusChat($main, $chat)
Start-Sleep -Milliseconds 250
# Try AIM batch first (prior submit-seen path); retry latched if no submit
[PinEoA]::CtrlEnterAim(); Log "CTRL_ENTER_AIM_BATCH"
Start-Sleep -Milliseconds 1500
if ((Count-Pat (Read-Rt) '^exactly_once_submit') -le $b4Sub) {
  [PinEoA]::FocusChat($main, $chat)
  Start-Sleep -Milliseconds 200
  [PinEoA]::CtrlEnterLatched(); Log "CTRL_ENTER_LATCHED_RETRY"
  Start-Sleep -Milliseconds 1000
}
[PinEoA]::Detach()
$waitSub = Wait-SubmitComplete ($b4Sub + 1) ([Math]::Min($IdleTimeoutMs, 90000))
$a4peek = Read-Rt
$newReq = 0
foreach ($line in $a4peek) {
  if ($line -match '^request_started request_id=(\d+)') {
    $rid = [int]$Matches[1]
    if ($rid -gt $newReq) { $newReq = $rid }
  }
}
if ($newReq -gt 0) {
  Log "CTRL_ENTER_WAIT_REQ=$newReq"
  [void](Wait-ReqComplete $newReq $IdleTimeoutMs)
}
$a4 = Read-Rt
$dSubCE = (Count-Pat $a4 '^exactly_once_submit') - $b4Sub
$dReqCE = (Count-Pat $a4 '^request_started') - $b4Req
$dDoneCE = (Count-Pat $a4 'ui_update .*complete=1') - $b4Done
Log ("CTRL_ENTER_DELTA submit=$dSubCE req=$dReqCE done=$dDoneCE waitSub=$waitSub")
[PinEoA]::Detach()

$vis = ""
try { if ($tr -ne [IntPtr]::Zero) { $vis = [PinEoA]::GetText($tr) } } catch {}
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

@(
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
  "LAUNCH=PIN_A190_NORMAL_NO_FIXTURE",
  "PROMOTE=0",
  "CERTIFIED=0",
  "MATURITY=82%"
) | Tee-Object -FilePath $receipt
@(
  "# FREEZE_EXACTLY_ONCE",
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))",
  "EXACTLY_ONCE=$eo",
  "SHA=$hash",
  "PIN=A190",
  "SEND1=$send1ok BUSY=$busyok SEND2=$send2ok ENTER=$enterok CTRL_ENTER=$ctrlok ALIGN=$idsAligned",
  "REASON=$($reason -join ',')",
  "PROMOTE=0",
  "MATURITY=82%"
) | Set-Content $mdPath -Encoding UTF8
if ($eo -eq "PASS") { exit 0 } else { exit 5 }
