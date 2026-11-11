# POWERSHELL_PANEL_ROUTING measure — fail-closed. PROMOTE=0. No invent PASS.
param(
  [string]$TipExe = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_ps_routing_001\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_ps_routing_001",
  [int]$WaitMs = 8000
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$sessionId = "ps_routing_$stamp"
$runId = "ps_routing_run_$stamp"
$runlog = Join-Path $OutDir "powershell_panel_routing_run_$stamp.txt"
$receipt = Join-Path $OutDir "POWERSHELL_PANEL_ROUTING_RECEIPT.txt"
$env:RAWRXD_LOG_DIR = $LogDir

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class PsRouteNative {
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint WM_SETTEXT = 0x000C;
  public const uint WM_COPYDATA = 0x004A;
  public const uint PSCM = 0x5053434D; // 'PSCM' — kRawrxdPowerShellCopyDataCmd
  public const int IDC_PS_PANEL = 5600;
  public const int IDC_PS_OUTPUT = 5601;
  public const int IDC_PS_INPUT = 5602;
  public const int IDC_PS_EXECUTE = 5610;
  public const int IDC_OUTPUT_TABS = 1005;
  public const int IDC_COPILOT_CHAT_OUTPUT = 1202;
  public const int IDM_TOOLS_BUILD_PROJECT = 3014;
  [StructLayout(LayoutKind.Sequential)]
  public struct COPYDATASTRUCT {
    public IntPtr dwData;
    public int cbData;
    public IntPtr lpData;
  }
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref COPYDATASTRUCT l);
  [DllImport("user32.dll", CharSet=CharSet.Ansi)] public static extern IntPtr SendMessageA(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Ansi)] public static extern bool SetWindowTextA(IntPtr h, string t);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string t);
  [DllImport("user32.dll", CharSet=CharSet.Ansi)] public static extern int GetWindowTextA(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int nCmdShow);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint wpid; GetWindowThreadProcessId(h, out wpid);
      if (wpid != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c == "RawrXD_IDE_Window" || c == "RawrXD_IDE_MainWindow") { found = h; return false; }
      if (found == IntPtr.Zero) found = h;
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindById(IntPtr root, int id) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(root, (h, lp) => {
      if (GetDlgCtrlID(h) == id) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  // Prefer child-of-panel lookup: IDC_PS_INPUT(5002) collides with IDM_BUILD_RUN.
  public static IntPtr FindChildId(IntPtr parent, int id) {
    if (parent == IntPtr.Zero) return IntPtr.Zero;
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(parent, (h, lp) => {
      if (GetDlgCtrlID(h) == id) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static string GetText(IntPtr h) {
    if (h == IntPtr.Zero) return "";
    int len = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    if (len <= 0) return "";
    var sb = new StringBuilder(len + 16);
    SendMessageW(h, WM_GETTEXT, (IntPtr)sb.Capacity, sb);
    return sb.ToString();
  }
  public static void SetTextA(IntPtr h, string text) {
    // PS input is CreateWindowExW EDIT — SetWindowTextW is authoritative.
    // SetWindowTextA/SendMessageA(WM_SETTEXT) can leave a UTF-16 NUL after the
    // first byte so ANSI readers see only one character ("ls" → "l").
    SetWindowTextW(h, text ?? "");
  }
  public static bool SendPanelCommand(IntPtr panel, string cmd) {
    if (panel == IntPtr.Zero || string.IsNullOrEmpty(cmd)) return false;
    byte[] bytes = Encoding.UTF8.GetBytes(cmd);
    IntPtr p = Marshal.AllocHGlobal(bytes.Length);
    try {
      Marshal.Copy(bytes, 0, p, bytes.Length);
      COPYDATASTRUCT cds;
      cds.dwData = (IntPtr)unchecked((int)PSCM);
      cds.cbData = bytes.Length;
      cds.lpData = p;
      SendMessage(panel, WM_COPYDATA, IntPtr.Zero, ref cds);
      return true;
    } finally {
      Marshal.FreeHGlobal(p);
    }
  }
  public static string GetTextA(IntPtr h) {
    if (h == IntPtr.Zero) return "";
    var sb = new StringBuilder(16384);
    GetWindowTextW(h, sb, sb.Capacity);
    string w = sb.ToString();
    if (!string.IsNullOrEmpty(w)) return w;
    sb.Clear();
    GetWindowTextA(h, sb, sb.Capacity);
    return sb.ToString();
  }
}
"@

if (-not (Test-Path $TipExe)) {
  Log "TIP_MISSING=$TipExe"
  @"
POWERSHELL_PANEL_ROUTING=NOT_RUN
TIP_EXE_MISSING=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@ | Set-Content $receipt
  exit 2
}

$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "TIP_EXE=$TipExe"
Log "TIP_SHA256=$sha"
Log "SESSION_ID=$sessionId"
Log "RUN_ID=$runId"

Get-Process -Name 'RawrXD-Win32IDE-Native*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 1

$p = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 50; $i++) {
  Start-Sleep -Milliseconds 250
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT code=$($p.ExitCode)"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $main = [PsRouteNative]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) {
  @"
POWERSHELL_PANEL_ROUTING=NOT_RUN
TIP_SHA256=$sha
MAIN_HWND=0
SESSION_ID=$sessionId
RUN_ID=$runId
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@ | Set-Content $receipt
  exit 3
}

[void][PsRouteNative]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 800

$psPanel = [PsRouteNative]::FindById($main, [PsRouteNative]::IDC_PS_PANEL)
if ($psPanel -eq [IntPtr]::Zero) { $psPanel = [PsRouteNative]::FindById($main, 5000) } # legacy tip IDs
$psOut = [PsRouteNative]::FindChildId($psPanel, [PsRouteNative]::IDC_PS_OUTPUT)
if ($psOut -eq [IntPtr]::Zero) { $psOut = [PsRouteNative]::FindChildId($psPanel, 5001) }
if ($psOut -eq [IntPtr]::Zero) { $psOut = [PsRouteNative]::FindById($main, [PsRouteNative]::IDC_PS_OUTPUT) }
$psIn = [PsRouteNative]::FindChildId($psPanel, [PsRouteNative]::IDC_PS_INPUT)
if ($psIn -eq [IntPtr]::Zero) { $psIn = [PsRouteNative]::FindChildId($psPanel, 5002) }
$psExec = [PsRouteNative]::FindChildId($psPanel, [PsRouteNative]::IDC_PS_EXECUTE)
if ($psExec -eq [IntPtr]::Zero) { $psExec = [PsRouteNative]::FindChildId($psPanel, 5010) }
$outTabs = [PsRouteNative]::FindById($main, 1005)
$chat = [PsRouteNative]::FindById($main, 1202)
if ($chat -eq [IntPtr]::Zero) {
  for ($id = 1200; $id -le 1210; $id++) {
    $h = [PsRouteNative]::FindById($main, $id)
    if ($h -eq [IntPtr]::Zero) { continue }
    $cls = New-Object System.Text.StringBuilder 64
    [void][PsRouteNative]::GetClassNameW($h, $cls, $cls.Capacity)
    if ($cls.ToString() -match 'Edit') { $chat = $h; Log "CHAT_ID_FALLBACK=$id"; break }
  }
}

Log "PS_PANEL=0x$('{0:X}' -f $psPanel.ToInt64()) vis=$(if($psPanel -ne [IntPtr]::Zero -and [PsRouteNative]::IsWindowVisible($psPanel)){1}else{0})"
Log "PS_OUT=0x$('{0:X}' -f $psOut.ToInt64())"
Log "PS_IN=0x$('{0:X}' -f $psIn.ToInt64())"
Log "PS_EXEC=0x$('{0:X}' -f $psExec.ToInt64())"
Log "CHAT=0x$('{0:X}' -f $chat.ToInt64())"

if ($outTabs -ne [IntPtr]::Zero) {
  [void][PsRouteNative]::PostMessageW($outTabs, 0x130C, [IntPtr]4, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
}

$chatBefore = [PsRouteNative]::GetText($chat)
# RichEdit20A: prefer WM_GETTEXT (GetText); GetWindowTextA can return empty.
$psBefore = [PsRouteNative]::GetText($psOut)
if ([string]::IsNullOrEmpty($psBefore)) { $psBefore = [PsRouteNative]::GetTextA($psOut) }
Log "CHAT_BEFORE_LEN=$($chatBefore.Length)"
Log "PS_BEFORE_LEN=$($psBefore.Length)"
$psSampleLen = [Math]::Min(180, $psBefore.Length)
Log "PS_BEFORE_SAMPLE=$($psBefore.Substring(0, $psSampleLen).Replace("`r","\r").Replace("`n","\n"))"

if ($psPanel -ne [IntPtr]::Zero) {
  [void][PsRouteNative]::ShowWindow($psPanel, 5) # SW_SHOW
  Start-Sleep -Milliseconds 200
}
if ($psIn -ne [IntPtr]::Zero) {
  [PsRouteNative]::SetTextA($psIn, "ls")
  Start-Sleep -Milliseconds 150
  $verify = [PsRouteNative]::GetText($psIn)
  if ([string]::IsNullOrEmpty($verify)) { $verify = [PsRouteNative]::GetTextA($psIn) }
  Log "PS_INPUT_VERIFY='$verify' len=$($verify.Length) hwnd=0x$('{0:X}' -f $psIn.ToInt64())"
  if ($verify -ne 'ls') {
    [PsRouteNative]::SetTextA($psIn, "Get-ChildItem")
    Start-Sleep -Milliseconds 150
    $verify = [PsRouteNative]::GetText($psIn)
    if ([string]::IsNullOrEmpty($verify)) { $verify = [PsRouteNative]::GetTextA($psIn) }
    Log "PS_INPUT_VERIFY2='$verify' len=$($verify.Length)"
  }
}
$execPath = 'NONE'
$cmdToRun = 'ls'
if ($verify -and $verify.Length -gt 0 -and $verify -ne 'ls') { $cmdToRun = $verify }
# Prefer WM_COPYDATA — measured GetWindowText empty on UI thread after external SetWindowTextW.
if ($psPanel -ne [IntPtr]::Zero -and [PsRouteNative]::SendPanelCommand($psPanel, $cmdToRun)) {
  $execPath = "SEND_WM_COPYDATA_PSCM_$cmdToRun"
} else {
  $execId = [PsRouteNative]::GetDlgCtrlID($psExec)
  if ($execId -le 0) { $execId = [PsRouteNative]::IDC_PS_EXECUTE }
  if ($psExec -ne [IntPtr]::Zero -and $psPanel -ne [IntPtr]::Zero) {
    $wParam = [IntPtr]$execId
    [void][PsRouteNative]::SendMessageW($psPanel, 0x0111, $wParam, $psExec)
    $execPath = "SEND_WM_COMMAND_PANEL_$execId"
  } elseif ($psExec -ne [IntPtr]::Zero) {
    [void][PsRouteNative]::SendMessageW($psExec, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero)
    $execPath = "SEND_BM_CLICK_$execId"
  }
}
Log "EXEC_PATH=$execPath"

$deadline = [DateTime]::UtcNow.AddMilliseconds($WaitMs)
$psAfter = $psBefore
do {
  Start-Sleep -Milliseconds 400
  $psAfter = [PsRouteNative]::GetText($psOut)
  if ([string]::IsNullOrEmpty($psAfter)) { $psAfter = [PsRouteNative]::GetTextA($psOut) }
  if ($psAfter.Length -gt ($psBefore.Length + 8) -and ($psAfter -match 'Mode|LastWriteTime|Directory|Length|\.exe|\.cpp|\.dll|Directory:')) { break }
} while ([DateTime]::UtcNow -lt $deadline)

$chatAfter = [PsRouteNative]::GetText($chat)
Log "PS_AFTER_LEN=$($psAfter.Length)"
Log "CHAT_AFTER_LEN=$($chatAfter.Length)"
$psDelta = if ($psAfter.Length -gt $psBefore.Length) { $psAfter.Substring($psBefore.Length) } else { $psAfter }
$deltaSampleLen = [Math]::Min(400, $psDelta.Length)
Log "PS_DELTA_SAMPLE=$($psDelta.Substring(0, $deltaSampleLen).Replace("`r","\r").Replace("`n","\n"))"

$chatLeak = ($chatAfter -match '\[powershell\]')
$chatGrewWithPs = ($chatAfter.Length -gt $chatBefore.Length) -and ($chatAfter.Substring([Math]::Min($chatBefore.Length, $chatAfter.Length)) -match 'powershell|PS>')
$dupPrompt = ($psDelta -match 'PS>\s*PS>') -or ($psAfter -match 'PS>\s*PS>\s')
$dirListing = ($psDelta -match 'Mode\s+LastWriteTime') -or ($psDelta -match 'Directory:') -or
              (($psDelta -match '\.exe|\.cpp|\.dll|\.md|\.ps1') -and ($psAfter.Length -gt $psBefore.Length + 20))
$cmdEchoed = ($psDelta -match '(?m)^ls\r?$') -or ($psDelta -match 'ls\r?\n')

$psLs = if ($dirListing) { 'PASS' } elseif ($psAfter.Length -gt $psBefore.Length) { 'FAIL_NO_DIR_MARKERS' } else { 'FAIL_NO_OUTPUT' }
$chatUntouched = if (-not $chatLeak -and ($chatAfter -eq $chatBefore)) { 'PASS' } `
  elseif ($chatLeak) { 'FAIL_PS_TAG_LEAK' } `
  elseif ($chatGrewWithPs) { 'FAIL_CHAT_MUTATED' } `
  else { 'FAIL_CHAT_MUTATED' }

$buildProducer = 'NOT_RUN'
$buildTabTextLen = -1
if ($outTabs -ne [IntPtr]::Zero) {
  [void][PsRouteNative]::PostMessageW($outTabs, 0x130C, [IntPtr]0, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 300
  [void][PsRouteNative]::PostMessageW($main, 0x0111, [IntPtr]3014, [IntPtr]::Zero)
  Start-Sleep -Seconds 6
  $script:best = 0
  [PsRouteNative]::EnumChildWindows($main, {
    param($h, $lp)
    if (-not [PsRouteNative]::IsWindowVisible($h)) { return $true }
    $sb = New-Object System.Text.StringBuilder 64
    [void][PsRouteNative]::GetClassNameW($h, $sb, $sb.Capacity)
    $c = $sb.ToString()
    if ($c -notmatch 'RichEdit|Edit') { return $true }
    $id = [PsRouteNative]::GetDlgCtrlID($h)
    if ($id -eq 5601 -or $id -eq 5602 -or $id -eq 5001 -or $id -eq 5002) { return $true }
    $len = [int][PsRouteNative]::SendMessageW($h, 0x000E, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($len -gt $script:best) { $script:best = $len }
    return $true
  }, [IntPtr]::Zero) | Out-Null
  $buildTabTextLen = $script:best
  $buildProducer = if ($script:best -gt 20) { 'PARTIAL_TEXT_PRESENT' } else { 'FAIL_OR_BLANK' }
  Log "BUILD_PRODUCER_MAX_EDIT_LEN=$($script:best)"
}

$tracePath = Join-Path $LogDir 'ps_trace.log'
$traceTail = if (Test-Path $tracePath) { (Get-Content $tracePath -Tail 30) -join ' | ' } else { 'NO_TRACE' }
Log "PS_TRACE_TAIL=$traceTail"

$status = 'FAIL_CLOSED'
if ($psLs -eq 'PASS' -and $chatUntouched -eq 'PASS' -and $buildProducer -eq 'PARTIAL_TEXT_PRESENT') {
  $status = 'MEASURED_LS_CHAT_OK_BUILD_PARTIAL'
} elseif ($psLs -eq 'PASS' -and $chatUntouched -eq 'PASS') {
  $status = 'MEASURED_PARTIAL_PENDING_OTHER_CHANNELS'
}

@"
POWERSHELL_PANEL_ROUTING=$status
TIP_SHA256=$sha
TIP_EXE=$TipExe
TIP_PACKAGE=tip_ps_routing_001
SESSION_ID=$sessionId
RUN_ID=$runId
MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())
PS_PANEL_HWND=0x$('{0:X}' -f $psPanel.ToInt64())
PS_OUTPUT_HWND=0x$('{0:X}' -f $psOut.ToInt64())
PS_INPUT_HWND=0x$('{0:X}' -f $psIn.ToInt64())
PS_EXECUTE_HWND=0x$('{0:X}' -f $psExec.ToInt64())
CHAT_HWND=0x$('{0:X}' -f $chat.ToInt64())
EXEC_PATH=$execPath
PS_LS_DIR_LISTING_IN_PANE=$psLs
AI_TRANSCRIPT_UNTOUCHED_BY_PS=$chatUntouched
PS_TAG_LEAK_INTO_CHAT=$(if($chatLeak){'OBSERVED'}else{'ABSENT_THIS_RUN'})
DUP_PS_PROMPT_IN_DELTA=$(if($dupPrompt){'OBSERVED'}else{'ABSENT_THIS_RUN'})
CMD_ECHOED=$cmdEchoed
PS_BEFORE_LEN=$($psBefore.Length)
PS_AFTER_LEN=$($psAfter.Length)
CHAT_BEFORE_LEN=$($chatBefore.Length)
CHAT_AFTER_LEN=$($chatAfter.Length)
OTHER_CHANNEL_BUILD_PRODUCER=$buildProducer
BUILD_MAX_EDIT_LEN=$buildTabTextLen
BLANK_IDLE_TAB_NE_DEFECT=1
CLICKABLE_TAB_NE_FEATURE_PASS=1
SOURCE_FINDING_NE_RUNTIME_PASS=1
BANNER_NE_EXECUTION_PASS=1
CHAT_INJECTION_LOCUS=AgentStepTimeline.addChip->onRow->appendCopilotChatUtf8
CHAT_INJECTION_FIX=removed_panel_addChip_powershell
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
CC79_UNREPLACED=1
A4F_IMMUTABLE=1
CHAT_TRANSCRIPT_17_RECONCILE_PRESERVED=1
TIP006_5A71_OUTPUT_FAIL_SEAL_PRESERVED=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
RUNLOG=$runlog
PS_TRACE=$tracePath
"@ | Set-Content $receipt

Get-Content $receipt
try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
exit 0
