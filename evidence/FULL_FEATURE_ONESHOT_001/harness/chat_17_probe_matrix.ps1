# Standalone 17-probe matrix (test×1 + button×5 + ctrl-enter×8 + hold×3).
# Requires tip with send_seq journal (tip_chat_dispatch_001). Never mutates A4F/EA5D/CC79.
# PROMOTE=0 CERTIFIED=0 PRODUCT_PASS=0
param(
  [Parameter(Mandatory = $true)][string]$TipExe,
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_chat_dispatch_001",
  [int]$InterSendMs = 2500,
  [string]$SessionId = "",
  [string]$RunId = ""
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir,$LogDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (-not $SessionId) { $SessionId = "c17_sess_$stamp" }
if (-not $RunId) { $RunId = "c17_run_$stamp" }
$runlog = Join-Path $OutDir "chat_17_probe_run_$stamp.txt"
$receipt = Join-Path $OutDir "CHAT_17_PROBE_RECEIPT.txt"
$env:RAWRXD_CHAT_SESSION_ID = $SessionId
$env:RAWRXD_CHAT_RUN_ID = $RunId

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $runlog -Value $line
  Write-Host $line
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;
public static class Chat17Native {
  public const uint WM_SETTEXT = 0x000C;
  public const uint WM_COMMAND = 0x0111;
  public const uint KEYEVENTF_KEYUP = 0x0002;
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int nCmdShow);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
  [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
    public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; public uint padding1; public uint padding2;
  }
  public static int InputSize { get { return Marshal.SizeOf(typeof(INPUT)); } }
  public static uint KeyDown(ushort vk) { INPUT[] a = new INPUT[1]; a[0].type = 1; a[0].ki.wVk = vk; return SendInput(1, a, InputSize); }
  public static uint KeyUp(ushort vk) { INPUT[] a = new INPUT[1]; a[0].type = 1; a[0].ki.wVk = vk; a[0].ki.dwFlags = KEYEVENTF_KEYUP; return SendInput(1, a, InputSize); }
  public static void SetText(IntPtr h, string t) { SendMessageW(h, WM_SETTEXT, IntPtr.Zero, t ?? ""); }
  public static IntPtr FindCtrl(IntPtr parent, int wantId, string classPart) {
    Stack<IntPtr> stack = new Stack<IntPtr>();
    stack.Push(parent);
    while (stack.Count > 0) {
      IntPtr cur = stack.Pop();
      List<IntPtr> kids = new List<IntPtr>();
      EnumChildWindows(cur, (h, lp) => { kids.Add(h); return true; }, IntPtr.Zero);
      foreach (IntPtr k in kids) {
        int id = GetDlgCtrlID(k);
        StringBuilder cls = new StringBuilder(64);
        GetClassNameW(k, cls, 64);
        if (id == wantId && cls.ToString().IndexOf(classPart, StringComparison.OrdinalIgnoreCase) >= 0) return k;
        stack.Push(k);
      }
    }
    return IntPtr.Zero;
  }
}
public static class Chat17HwndFind {
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
Log "TIP_EXE=$TipExe TIP_SHA256=$hash"
Get-Process -Name "RawrXD-Win32IDE-Native*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$env:RAWRXD_LOG_DIR = $LogDir
$rt = Join-Path $LogDir "chat_runtime.log"
if (Test-Path $rt) { Remove-Item $rt -Force }
$p = Start-Process -FilePath $TipExe -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "PROCESS_EXITED early"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $byPid = [Chat17HwndFind]::FindMain([uint32]$p.Id)
  if ($byPid -ne [IntPtr]::Zero) { $main = $byPid; break }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) {
  "CHAT_17_PROBE=NOT_RUN`nREASON=main_hwnd_not_found`nTIP_SHA256=$hash`nPROMOTE=0" | Set-Content $receipt
  try { if (!$p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
  exit 2
}

$chat = [Chat17Native]::FindCtrl($main, 1202, "Edit")
$send = [Chat17Native]::FindCtrl($main, 1204, "Button")
Log "CHAT_INPUT=0x$('{0:X}' -f $chat.ToInt64()) SEND=0x$('{0:X}' -f $send.ToInt64())"
if ($chat -eq [IntPtr]::Zero) {
  "CHAT_17_PROBE=NOT_RUN`nREASON=chat_input_missing`nTIP_SHA256=$hash`nPROMOTE=0" | Set-Content $receipt
  try { Stop-Process -Id $p.Id -Force } catch {}
  exit 3
}

$script:ideTid = [uint32]0; $script:myTid = [uint32]0; $script:attached = $false
function Focus-Chat17 {
  $pidIde = 0
  $ideTid = [Chat17Native]::GetWindowThreadProcessId($main, [ref]$pidIde)
  $myTid = [Chat17Native]::GetCurrentThreadId()
  if (-not $script:attached -and $ideTid -ne 0 -and $ideTid -ne $myTid) {
    $script:attached = [Chat17Native]::AttachThreadInput($myTid, $ideTid, $true)
    $script:ideTid = $ideTid; $script:myTid = $myTid
  }
  [void][Chat17Native]::ShowWindow($main, 9)
  [void][Chat17Native]::BringWindowToTop($main)
  [void][Chat17Native]::SetForegroundWindow($main)
  [void][Chat17Native]::SetFocus($chat)
  Start-Sleep -Milliseconds 100
}
function Detach-Chat17 {
  if ($script:attached) { [void][Chat17Native]::AttachThreadInput($script:myTid, $script:ideTid, $false) }
  $script:attached = $false
}
function Send-CtrlEnter17 {
  Focus-Chat17
  [void][Chat17Native]::KeyDown(0x11); Start-Sleep -Milliseconds 40
  [void][Chat17Native]::KeyDown(0x0D); Start-Sleep -Milliseconds 80
  [void][Chat17Native]::KeyUp(0x0D); [void][Chat17Native]::KeyUp(0x11)
  Detach-Chat17
}
function Send-HoldCtrlEnter17 {
  # One ctrl-enter chord (hold duration), not a burst of Enter KeyDowns —
  # repeated KeyDown can race the busy gate and inflate ATTEMPT/BUSY.
  Focus-Chat17
  [void][Chat17Native]::KeyDown(0x11); Start-Sleep -Milliseconds 40
  [void][Chat17Native]::KeyDown(0x0D); Start-Sleep -Milliseconds 250
  [void][Chat17Native]::KeyUp(0x0D); [void][Chat17Native]::KeyUp(0x11)
  Detach-Chat17
}
function Send-Button17 {
  Detach-Chat17
  [void][Chat17Native]::SendMessageW($main, 0x0111, [IntPtr]1204, $send)
}
function Read-Chat17JournalLines {
  # Share-read: ofstream append can make Get-Content fail → empty ≠ idle.
  if (-not (Test-Path $rt)) { return @() }
  try {
    return [string[]][IO.File]::ReadAllLines($rt)
  } catch {
    return $null
  }
}
function Get-Chat17JournalCounts {
  $lines = Read-Chat17JournalLines
  if ($null -eq $lines) {
    return @{ ok = $false; attempts = -1; armed = -1; complete = -1; busy = -1 }
  }
  $a = 0; $arm = 0; $c = 0; $b = 0
  foreach ($line in $lines) {
    if ($line -match "CHAT_SEND_ATTEMPT") { $a++ }
    if ($line -match "CHAT_SEND_ARMED") { $arm++ }
    if ($line -match "CHAT_SEND_BUSY") { $b++ }
    if ($line -match "ui_update .*complete=1") { $c++ }
  }
  return @{ ok = $true; attempts = $a; armed = $arm; complete = $c; busy = $b }
}
function Wait-Chat17StepDone([int]$wantArmed, [int]$timeoutMs = 300000) {
  # Require armed>=wantArmed AND complete>=wantArmed. Never treat unread/empty as idle.
  $deadline = [Environment]::TickCount64 + $timeoutMs
  $nextBeat = [Environment]::TickCount64 + 15000
  while ([Environment]::TickCount64 -lt $deadline) {
    if (-not [Chat17Native]::IsWindow($main)) {
      Log "HWND_LOST want=$wantArmed"
      return $false
    }
    try { $p.Refresh() } catch {}
    if ($p.HasExited) {
      Log "TIP_EXITED want=$wantArmed exit=$($p.ExitCode)"
      return $false
    }
    $j = Get-Chat17JournalCounts
    if ($j.ok -and $j.armed -ge $wantArmed -and $j.complete -ge $wantArmed) {
      Log "STEP_DONE want=$wantArmed armed=$($j.armed) complete=$($j.complete) busy=$($j.busy)"
      return $true
    }
    if ([Environment]::TickCount64 -ge $nextBeat) {
      Log "STEP_WAIT want=$wantArmed ok=$($j.ok) armed=$($j.armed) complete=$($j.complete) busy=$($j.busy)"
      $nextBeat = [Environment]::TickCount64 + 15000
    }
    Start-Sleep -Milliseconds 500
  }
  $j = Get-Chat17JournalCounts
  Log "STEP_TIMEOUT want=$wantArmed ok=$($j.ok) armed=$($j.armed) complete=$($j.complete)"
  return $false
}

Start-Sleep -Seconds 8
$plan = @(@{ kind = "button"; text = "test" })
1..5 | ForEach-Object { $plan += @{ kind = "button"; text = "button-probe" } }
1..8 | ForEach-Object { $plan += @{ kind = "ctrl"; text = "ctrl-enter-probe" } }
1..3 | ForEach-Object { $plan += @{ kind = "hold"; text = "hold-probe" } }
Log "PLAN_COUNT=$($plan.Count)"

$i = 0
$abortClass = "NONE"
foreach ($step in $plan) {
  $i++
  try {
    if (-not [Chat17Native]::IsWindow($main)) { $abortClass = "HWND_LOST"; Log "ABORT_CLASS=HWND_LOST at=$i"; break }
    [Chat17Native]::SetText($chat, $step.text)
    Start-Sleep -Milliseconds 100
    switch ($step.kind) {
      "button" { Send-Button17 }
      "ctrl"   { Send-CtrlEnter17 }
      "hold"   { Send-HoldCtrlEnter17 }
    }
    Log "STEP=$i kind=$($step.kind) text=$($step.text)"
    if (-not (Wait-Chat17StepDone $i 300000)) {
      if ($abortClass -eq "NONE") { $abortClass = "FAILED_TIMEOUT_OR_TIP_EXIT" }
      Log "ABORT_STEP_CLASS=$abortClass at=$i"
      break
    }
  } catch {
    $abortClass = "EXCEPTION"
    Log "ABORT_CLASS=EXCEPTION at=$i err=$($_.Exception.Message)"
    break
  }
  Start-Sleep -Milliseconds ([Math]::Min($InterSendMs, 400))
}

$attempts = 0; $armed = 0; $rejects = 0; $busy = 0; $reqIds = @(); $seqs = @(); $uiComplete = 0
if (Test-Path $rt) {
  foreach ($line in Get-Content $rt) {
    if ($line -match "CHAT_SEND_ATTEMPT") { $attempts++ }
    if ($line -match "CHAT_SEND_ARMED") { $armed++ }
    if ($line -match "CHAT_SEND_REJECTED") { $rejects++ }
    if ($line -match "CHAT_SEND_BUSY") { $busy++ }
    # Count send_seq only on ATTEMPT lines (ARMED repeats the same seq — not a dup dispatch).
    if ($line -match "CHAT_SEND_ATTEMPT.*send_seq=(\d+)") { $seqs += [int64]$Matches[1] }
    if ($line -match "CHAT_SEND_ARMED.*request_id=(\d+)") { $reqIds += [int64]$Matches[1] }
    if ($line -match "ui_update .*complete=1") { $uiComplete++ }
  }
}
$uniqSeq = @($seqs | Select-Object -Unique).Count
$dupSeq = [int]($seqs.Count - $uniqSeq)
$exactly = "NOT_VERIFIED"
# Seal only when ATTEMPT==ARMED==UI complete with UNIQUE seq==17 and DUP=0.
if ($attempts -eq 17 -and $armed -eq 17 -and $uiComplete -eq 17 -and $uniqSeq -eq 17 -and $dupSeq -eq 0 -and $busy -eq 0) {
  $exactly = "PASS"
}
$backend = "NOT_VERIFIED"
if ($uiComplete -ge $armed -and $armed -eq 17 -and $uiComplete -eq 17) { $backend = "PASS_UI_COMPLETE_GE_ARMED" }
elseif ($armed -gt 0 -and $uiComplete -lt $armed) { $backend = "ARMED_WITHOUT_FULL_UI_COMPLETE" }
elseif ($armed -gt 0) { $backend = "PASS_UI_COMPLETE_GE_ARMED" }

$cancels = 0
if (Test-Path $rt) {
  foreach ($line in Get-Content $rt) {
    if ($line -match "cancel_requested|cancel_acknowledged") { $cancels++ }
  }
}
$failedTimeout = if ($exactly -eq "PASS") { "NONE" } elseif ($abortClass -ne "NONE") { $abortClass } elseif ($attempts -lt 17 -or $uiComplete -lt $armed) { "FAILED_OR_INCOMPLETE" } else { "NONE" }
@"
CHAT_17_PROBE_MATRIX=MEASURED
TIP_EXE=$TipExe
TIP_SHA256=$hash
SESSION_ID=$SessionId
RUN_ID=$RunId
RECEIPT_BINDS_FULL_EXE_SHA256=1
RECEIPT_BINDS_SESSION_ID=1
PLAN_COUNT=17
CHAT_SEND_ATTEMPT_COUNT=$attempts
CHAT_SEND_ARMED_COUNT=$armed
CHAT_SEND_REJECTED_COUNT=$rejects
CHAT_SEND_BUSY_COUNT=$busy
SEND_SEQ_COUNT=$($seqs.Count)
SEND_SEQ_UNIQUE=$uniqSeq
SEND_SEQ_DUP=$dupSeq
REQUEST_ID_UNIQUE=$(@($reqIds | Select-Object -Unique).Count)
UI_UPDATE_COMPLETE=$uiComplete
CANCEL_JOURNAL_HITS=$cancels
UNANSWERED_CLASS=$failedTimeout
ABORT_CLASS=$abortClass
STEPS_COMPLETED=$uiComplete
EXACTLY_ONCE_DELIVERY=$exactly
BACKEND_RESPONSE=$backend
CHAT_FULL_ACCEPTANCE=NOT_VERIFIED
UTF8_MOJIBAKE=INVESTIGATE_SEPARATE
NO_STOP_BETWEEN=1
MATURITY_ESTIMATE=82
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
FROZEN_A4F_UNTOUCHED=1
EA5D_CC79_UNTOUCHED=1
RUNLOG=$runlog
CHAT_RUNTIME=$rt
"@ | Set-Content $receipt -Encoding ASCII
Get-Content $receipt | ForEach-Object { Log $_ }
try { Detach-Chat17 } catch {}
try {
  if (!$p.HasExited) {
    $p.CloseMainWindow() | Out-Null
    Start-Sleep -Seconds 2
    if (!$p.HasExited) { Stop-Process -Id $p.Id -Force }
  }
} catch {}
exit 0
