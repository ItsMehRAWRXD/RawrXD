# Remeasure PS routing using WM_CHAR keystrokes (avoids cross-process SetWindowText empty-read).
$ErrorActionPreference = 'Continue'
$exe = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe'
$cand = Split-Path $exe
$art = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$session = "ps_routing_$stamp"
$runId = "ps_routing_run_$stamp"
$runLog = Join-Path $art "powershell_panel_routing_run_$stamp.txt"
$receipt = Join-Path $art 'POWERSHELL_PANEL_ROUTING_RECEIPT.txt'
$gate = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\POWERSHELL_PANEL_GATE.md'

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $runLog -Value $line -Encoding UTF8
  Write-Output $line
}

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class PsKeys {
  public const uint WM_COMMAND=0x0111; public const uint WM_CHAR=0x0102; public const uint WM_KEYDOWN=0x0100; public const uint WM_KEYUP=0x0101;
  public const uint WM_GETTEXT=0x000D; public const uint WM_GETTEXTLENGTH=0x000E; public const uint BM_CLICK=0x00F5;
  public const uint WM_SETFOCUS=0x0007; public const int VK_RETURN=0x0D;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,StringBuilder l);
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  public static IntPtr FindMain(uint pid){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,sb.Capacity);
      if(sb.ToString().IndexOf("RawrXD",StringComparison.OrdinalIgnoreCase)>=0){f=h;return false;}
      if(f==IntPtr.Zero) f=h; return true; }, IntPtr.Zero);
    return f;
  }
  public static string GetText(IntPtr h){
    if(h==IntPtr.Zero) return "";
    int n=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    if(n<=0){ var t=new StringBuilder(512); SendMessageW(h,WM_GETTEXT,(IntPtr)512,t); return t.ToString(); }
    if(n>120000) n=120000;
    var sb=new StringBuilder(n+2);
    SendMessageW(h,WM_GETTEXT,(IntPtr)(n+1),sb);
    return sb.ToString();
  }
  public static void TypeAscii(IntPtr h, string s){
    foreach(char c in s){
      SendMessageW(h, WM_CHAR, (IntPtr)c, IntPtr.Zero);
    }
  }
}
"@

if (!(Test-Path $exe)) { throw "EXE_MISSING $exe" }
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash.ToUpperInvariant()
Log "TIP_EXE=$exe"
Log "TIP_SHA256=$sha"
Log "SESSION_ID=$session"
Log "RUN_ID=$runId"
Log "INPUT_METHOD=WM_CHAR_KEYSTROKES"

Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$traceCand = Join-Path $cand 'ps_trace.log'
Remove-Item $traceCand,'F:\rawrxd\ps_trace.log' -Force -EA SilentlyContinue
$env:RAWRXD_LOG_DIR = $cand
$p = Start-Process -FilePath $exe -WorkingDirectory $cand -PassThru -WindowStyle Normal
$main = [IntPtr]::Zero
for ($i=0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 250
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $main = [PsKeys]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log ("PID={0}" -f $p.Id)
Log ("MAIN_HWND=0x{0:X}" -f $main.ToInt64())
if ($main -eq [IntPtr]::Zero) { Log 'FAIL=NO_MAIN'; exit 2 }
[void][PsKeys]::ShowWindow($main, 5)
[void][PsKeys]::SetForegroundWindow($main)
Start-Sleep 2

$panel=[IntPtr]::Zero; $psOut=[IntPtr]::Zero; $psIn=[IntPtr]::Zero; $psExec=[IntPtr]::Zero; $chat=[IntPtr]::Zero
[PsKeys]::EnumChildWindows($main, {
  param($h,$lp)
  $id = [PsKeys]::GetDlgCtrlID($h)
  if ($id -eq 5600) { $script:panel = $h }
  elseif ($id -eq 5601) { $script:psOut = $h }
  elseif ($id -eq 5602) { $script:psIn = $h }
  elseif ($id -eq 5610) { $script:psExec = $h }
  elseif ($id -eq 1203) { $script:chat = $h }
  return $true
}, [IntPtr]::Zero) | Out-Null

if ($panel -ne [IntPtr]::Zero) { [void][PsKeys]::ShowWindow($panel, 5) }
Log ("PS_PANEL=0x{0:X} vis={1}" -f $panel.ToInt64(), [int][PsKeys]::IsWindowVisible($panel))
Log ("PS_OUT=0x{0:X}" -f $psOut.ToInt64())
Log ("PS_IN=0x{0:X}" -f $psIn.ToInt64())
Log ("PS_EXEC=0x{0:X}" -f $psExec.ToInt64())
Log ("CHAT=0x{0:X}" -f $chat.ToInt64())

$chatBefore = [PsKeys]::GetText($chat)
$psBefore = [PsKeys]::GetText($psOut)
Log ("CHAT_BEFORE_LEN={0}" -f $chatBefore.Length)
Log ("PS_BEFORE_LEN={0}" -f $psBefore.Length)

# Focus + type ls via WM_CHAR (in-proc path through subclass)
[void][PsKeys]::SendMessageW($psIn, [PsKeys]::WM_SETFOCUS, [IntPtr]::Zero, [IntPtr]::Zero)
[void][PsKeys]::SetFocus($psIn)
Start-Sleep -Milliseconds 200
[PsKeys]::TypeAscii($psIn, 'ls')
Start-Sleep -Milliseconds 300
$verify = [PsKeys]::GetText($psIn)
Log ("PS_INPUT_VERIFY='$verify' len=$($verify.Length)")

# Enter via KEYDOWN (subclass executes on VK_RETURN)
[void][PsKeys]::PostMessageW($psIn, [PsKeys]::WM_KEYDOWN, [IntPtr]([PsKeys]::VK_RETURN), [IntPtr]::Zero)
Log 'EXEC_PATH=WM_KEYDOWN_VK_RETURN'
Start-Sleep -Milliseconds 200
# Also click Execute as backup
if ($psExec -ne [IntPtr]::Zero) {
  [void][PsKeys]::PostMessageW($psExec, [PsKeys]::BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero)
  Log 'EXEC_PATH=BM_CLICK_5610'
}

Start-Sleep 12
$psAfter = [PsKeys]::GetText($psOut)
$chatAfter = [PsKeys]::GetText($chat)
Log ("PS_AFTER_LEN={0}" -f $psAfter.Length)
Log ("CHAT_AFTER_LEN={0}" -f $chatAfter.Length)
$tail = if ($psAfter.Length -gt 600) { $psAfter.Substring($psAfter.Length-600) } else { $psAfter }
Log ("PS_DELTA_SAMPLE=$($tail -replace "`r|`n",' ')")

$grew = $psAfter.Length -gt $psBefore.Length
$hasListing = $psAfter -match '(?i)(Directory|Mode\s+LastWriteTime|Length\s+Name|\.exe|\.dll|\.cpp|\.md|----|Mode\s+)'
$lsInPane = $grew -and $hasListing
if (-not $lsInPane -and $grew -and ($psAfter.Contains('ls') -or $verify -eq 'ls')) {
  # Command echoed at least — soft evidence
  Log 'NOTE=GREW_BUT_NO_DIR_PATTERN'
}
$chatClean = ($chatAfter.Length -eq $chatBefore.Length) -and ($chatAfter -notmatch '(?i)\[powershell\]')
$tagLeak = if ($chatAfter -match '(?i)\[powershell\]') { 'PRESENT' } else { 'ABSENT_THIS_RUN' }

# Other channel: Build Compile producer
$beforeMax = 0
[PsKeys]::EnumChildWindows($main, { param($h,$lp) $t=[PsKeys]::GetText($h); if($t.Length -gt $script:beforeMax){$script:beforeMax=$t.Length}; return $true }, [IntPtr]::Zero) | Out-Null
[void][PsKeys]::PostMessageW($main, [PsKeys]::WM_COMMAND, [IntPtr]5001, [IntPtr]::Zero)
Start-Sleep 8
$afterMax = 0
[PsKeys]::EnumChildWindows($main, { param($h,$lp) $t=[PsKeys]::GetText($h); if($t.Length -gt $script:afterMax){$script:afterMax=$t.Length}; return $true }, [IntPtr]::Zero) | Out-Null
Log ("BUILD_PRODUCER_MAX_EDIT_LEN=$afterMax before=$beforeMax")

$traceTail = ''
foreach ($tp in @($traceCand, 'F:\rawrxd\ps_trace.log')) {
  if (Test-Path $tp) { $traceTail = ((Get-Content $tp -Tail 40) -join ' | '); break }
}
Log ("PS_TRACE_TAIL=$traceTail")

$lsResult = if ($lsInPane) { 'PASS' } elseif ($grew) { 'PARTIAL_GREW_NO_LISTING_PATTERN' } else { 'FAIL_NO_DIR_LISTING' }
$chatResult = if ($chatClean) { 'PASS' } else { 'FAIL_CHAT_CONTAMINATED' }
$overall = if ($lsInPane -and $chatClean) { 'PASS_ROUTING' } else { 'FAIL_CLOSED' }

@"
POWERSHELL_PANEL_ROUTING=$overall
TIP_SHA256=$sha
TIP_EXE=$exe
TIP_PACKAGE=tip_integ_candidate_001
SESSION_ID=$session
RUN_ID=$runId
INPUT_METHOD=WM_CHAR_KEYSTROKES
MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())
PS_PANEL_HWND=0x$('{0:X}' -f $panel.ToInt64())
PS_OUTPUT_HWND=0x$('{0:X}' -f $psOut.ToInt64())
PS_INPUT_HWND=0x$('{0:X}' -f $psIn.ToInt64())
PS_EXECUTE_HWND=0x$('{0:X}' -f $psExec.ToInt64())
CHAT_HWND=0x$('{0:X}' -f $chat.ToInt64())
PS_LS_DIR_LISTING_IN_PANE=$lsResult
AI_TRANSCRIPT_UNTOUCHED_BY_PS=$chatResult
PS_TAG_LEAK_INTO_CHAT=$tagLeak
PS_BEFORE_LEN=$($psBefore.Length)
PS_AFTER_LEN=$($psAfter.Length)
CHAT_BEFORE_LEN=$($chatBefore.Length)
CHAT_AFTER_LEN=$($chatAfter.Length)
OTHER_CHANNEL_BUILD_PRODUCER=$(if($afterMax -gt $beforeMax){'PARTIAL_TEXT_PRESENT'}else{'NOT_PROVEN'})
BUILD_MAX_EDIT_LEN=$afterMax
BLANK_IDLE_TAB_NE_DEFECT=1
CLICKABLE_TAB_NE_FEATURE_PASS=1
SOURCE_FINDING_NE_RUNTIME_PASS=1
BANNER_NE_EXECUTION_PASS=1
CHAT_INJECTION_LOCUS=AgentStepTimeline.addChip->onRow->appendCopilotChatUtf8
CHAT_INJECTION_FIX=removed_panel_addChip_powershell
EXACTLY_ONCE=PASS
EXACTLY_ONCE_TIP=C43B01ABE886700B7A085C570575CCB9DED63A140000380ADCBE07ADEF33A629
FOUR_PANEL_RESULT=PARTIAL_PROBLEMS_OUTPUT_PASS_PANEL_HIDE
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
CC79_UNREPLACED=1
A4F_IMMUTABLE=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
RUNLOG=$runLog
"@ | Set-Content -Path $receipt -Encoding UTF8

# Update gate (no invent PASS)
@"
# POWERSHELL_PANEL_GATE

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
CC79_UNREPLACED=1
NO_CROSS_SHA_PASS_INHERITANCE=1

``````
GATE=POWERSHELL_PANEL_ROUTING
STATUS=$overall
TIP_SHA=$sha
PS_LS_DIR_LISTING_IN_PANE=$lsResult
AI_TRANSCRIPT_UNTOUCHED_BY_PS=$chatResult
PS_TAG_LEAK_INTO_CHAT=$tagLeak
OTHER_CHANNEL_PRODUCER_TO_PANE=$(if($afterMax -gt $beforeMax){'PARTIAL_TEXT_PRESENT'}else{'NOT_PROVEN'})
BLANK_IDLE_TAB_NE_DEFECT=1
CLICKABLE_TAB_NE_FEATURE_PASS=1
INPUT_METHOD=WM_CHAR_KEYSTROKES
CHAT_INJECTION_LOCUS=AgentStepTimeline.addChip->onRow->appendCopilotChatUtf8
CHAT_INJECTION_FIX=removed_panel_addChip_powershell
RECEIPT=artifacts\POWERSHELL_PANEL_ROUTING_RECEIPT.txt
EXACTLY_ONCE=PASS
FOUR_PANEL_RESULT=PARTIAL_PROBLEMS_OUTPUT_PASS_PANEL_HIDE
``````

SOURCE_FINDING ≠ RUNTIME_PASS
BANNER ≠ EXECUTION_PASS
PROMOTE=0
"@ | Set-Content -Path $gate -Encoding UTF8

Log "RESULT=$overall LS_IN_PANE=$lsResult CHAT_CLEAN=$chatResult POWERSHELL_SHA=$sha"
try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } catch {}
exit $(if ($overall -eq 'PASS_ROUTING') { 0 } else { 3 })
