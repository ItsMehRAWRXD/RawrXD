# PowerShell panel routing remeasure on tip_ps_routing_001 (1AE26…).
# SetWindowTextW on IDC_PS_INPUT=5602; WM_COMMAND Execute=5610 on panel.
$ErrorActionPreference = 'Continue'
$exe = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_ps_routing_001\RawrXD-Win32IDE-Native-Ext.exe'
$cand = Split-Path $exe
$art = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$session = "ps_routing_$stamp"
$runId = "ps_routing_run_$stamp"
$runLog = Join-Path $art "powershell_panel_routing_run_$stamp.txt"
$receipt = Join-Path $art 'POWERSHELL_PANEL_ROUTING_RECEIPT.txt'
$expectSha = '1AE26B8F3A6BE63462C1C6F860B09153DB077786505D32F9A4C051E1D80F0CB5'

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $runLog -Value $line -Encoding UTF8
  Write-Output $line
}

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class PsRoute {
  public const uint WM_COMMAND=0x0111; public const uint WM_GETTEXT=0x000D; public const uint WM_GETTEXTLENGTH=0x000E;
  public const uint BM_CLICK=0x00F5; public const int SW_SHOW=5;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string t);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,StringBuilder l);
  public static IntPtr FindMain(uint pid){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,sb.Capacity); string c=sb.ToString();
      if(c.IndexOf("RawrXD",StringComparison.OrdinalIgnoreCase)>=0){f=h;return false;}
      if(f==IntPtr.Zero) f=h; return true; }, IntPtr.Zero);
    return f;
  }
  public static string GetText(IntPtr h){
    if(h==IntPtr.Zero) return "";
    int n=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    if(n<=0){ var t=new StringBuilder(512); GetWindowTextW(h,t,512); return t.ToString(); }
    if(n>120000) n=120000;
    var sb=new StringBuilder(n+2);
    SendMessageW(h,WM_GETTEXT,(IntPtr)(n+1),sb);
    return sb.ToString();
  }
}
"@

if (!(Test-Path $exe)) { throw "EXE_MISSING $exe" }
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash.ToUpperInvariant()
Log "TIP_EXE=$exe"
Log "TIP_SHA256=$sha"
Log "SESSION_ID=$session"
Log "RUN_ID=$runId"
if ($sha -ne $expectSha) { Log "SHA_NOTE=expected_$expectSha got_$sha (proceed)" }

Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$traceCand = Join-Path $cand 'ps_trace.log'
$traceRoot = 'F:\rawrxd\ps_trace.log'
Remove-Item $traceCand,$traceRoot -Force -EA SilentlyContinue
$env:RAWRXD_LOG_DIR = $cand
$p = Start-Process -FilePath $exe -WorkingDirectory $cand -PassThru -WindowStyle Normal
$main = [IntPtr]::Zero
for ($i=0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 250
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $main = [PsRoute]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log ("PID={0}" -f $p.Id)
Log ("MAIN_HWND=0x{0:X}" -f $main.ToInt64())
if ($main -eq [IntPtr]::Zero) {
  Log 'FAIL=NO_MAIN'
  try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } catch {}
  exit 2
}
Start-Sleep 2

$panel=[IntPtr]::Zero; $psOut=[IntPtr]::Zero; $psIn=[IntPtr]::Zero; $psExec=[IntPtr]::Zero; $chat=[IntPtr]::Zero
[PsRoute]::EnumChildWindows($main, {
  param($h,$lp)
  $id = [PsRoute]::GetDlgCtrlID($h)
  if ($id -eq 5600) { $script:panel = $h }
  elseif ($id -eq 5601) { $script:psOut = $h }
  elseif ($id -eq 5602) { $script:psIn = $h }
  elseif ($id -eq 5610) { $script:psExec = $h }
  elseif ($id -eq 1203) { $script:chat = $h }
  return $true
}, [IntPtr]::Zero) | Out-Null

if ($panel -ne [IntPtr]::Zero) { [void][PsRoute]::ShowWindow($panel, 5) }
Log ("PS_PANEL=0x{0:X} vis={1}" -f $panel.ToInt64(), [int][PsRoute]::IsWindowVisible($panel))
Log ("PS_OUT=0x{0:X}" -f $psOut.ToInt64())
Log ("PS_IN=0x{0:X}" -f $psIn.ToInt64())
Log ("PS_EXEC=0x{0:X}" -f $psExec.ToInt64())
Log ("CHAT=0x{0:X}" -f $chat.ToInt64())

$chatBefore = [PsRoute]::GetText($chat)
$psBefore = [PsRoute]::GetText($psOut)
Log ("CHAT_BEFORE_LEN={0}" -f $chatBefore.Length)
Log ("PS_BEFORE_LEN={0}" -f $psBefore.Length)
$sample = if ($psBefore.Length -gt 180) { $psBefore.Substring(0,180) } else { $psBefore }
Log ("PS_BEFORE_SAMPLE=$($sample -replace "`r|`n",' ')")

[void][PsRoute]::SetWindowTextW($psIn, 'ls')
Start-Sleep -Milliseconds 200
$verify = [PsRoute]::GetText($psIn)
Log ("PS_INPUT_VERIFY='$verify' len=$($verify.Length)")

# Prefer BM_CLICK on Execute; also Post WM_COMMAND to panel.
if ($psExec -ne [IntPtr]::Zero) {
  [void][PsRoute]::PostMessageW($psExec, [PsRoute]::BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero)
  Log 'EXEC_PATH=BM_CLICK_5610'
}
if ($panel -ne [IntPtr]::Zero -and $psExec -ne [IntPtr]::Zero) {
  $wParam = [IntPtr](5610 -bor ([int]0 -shl 16))
  [void][PsRoute]::PostMessageW($panel, [PsRoute]::WM_COMMAND, [IntPtr]5610, $psExec)
  Log 'EXEC_PATH=POST_WM_COMMAND_PANEL_5610'
}

Start-Sleep 10
$psAfter = [PsRoute]::GetText($psOut)
$chatAfter = [PsRoute]::GetText($chat)
Log ("PS_AFTER_LEN={0}" -f $psAfter.Length)
Log ("CHAT_AFTER_LEN={0}" -f $chatAfter.Length)
$tail = if ($psAfter.Length -gt 500) { $psAfter.Substring($psAfter.Length-500) } else { $psAfter }
Log ("PS_DELTA_SAMPLE=$($tail -replace "`r|`n",' ')")

$lsInPane = ($psAfter.Length -gt $psBefore.Length) -and (
  $psAfter -match '(?i)(Directory|Mode\s+LastWriteTime|Length\s+Name|\.exe|\.dll|\.cpp|\.md|----)')
$chatClean = ($chatAfter.Length -eq $chatBefore.Length) -and ($chatAfter -notmatch '(?i)\[powershell\]')
$tagLeak = if ($chatAfter -match '(?i)\[powershell\]') { 'PRESENT' } else { 'ABSENT_THIS_RUN' }

# Build producer smoke (Output channel) — post Build Compile if present
$buildMax = 0
[PsRoute]::EnumChildWindows($main, {
  param($h,$lp)
  $t = [PsRoute]::GetText($h)
  if ($t.Length -gt $script:buildMax) { $script:buildMax = $t.Length }
  return $true
}, [IntPtr]::Zero) | Out-Null
# Trigger IDM_BUILD_COMPILE=5001 lightly
[void][PsRoute]::PostMessageW($main, [PsRoute]::WM_COMMAND, [IntPtr]5001, [IntPtr]::Zero)
Start-Sleep 8
$buildMax2 = 0
[PsRoute]::EnumChildWindows($main, {
  param($h,$lp)
  $t = [PsRoute]::GetText($h)
  if ($t.Length -gt $script:buildMax2) { $script:buildMax2 = $t.Length }
  return $true
}, [IntPtr]::Zero) | Out-Null
Log ("BUILD_PRODUCER_MAX_EDIT_LEN=$buildMax2")

$traceTail = ''
foreach ($tp in @($traceCand, $traceRoot, (Join-Path $cand 'ps_trace.log'))) {
  if (Test-Path $tp) {
    $traceTail = ((Get-Content $tp -Tail 30) -join ' | ')
    break
  }
}
Log ("PS_TRACE_TAIL=$traceTail")

$lsResult = if ($lsInPane) { 'PASS' } else { 'FAIL_NO_DIR_LISTING' }
$chatResult = if ($chatClean) { 'PASS' } else { 'FAIL_CHAT_CONTAMINATED' }
$overall = if ($lsInPane -and $chatClean) { 'PASS_ROUTING' } else { 'FAIL_CLOSED' }

@"
POWERSHELL_PANEL_ROUTING=$overall
TIP_SHA256=$sha
TIP_EXE=$exe
TIP_PACKAGE=tip_ps_routing_001
SESSION_ID=$session
RUN_ID=$runId
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
OTHER_CHANNEL_BUILD_PRODUCER=$(if($buildMax2 -gt $buildMax){'PARTIAL_TEXT_PRESENT'}else{'NOT_PROVEN'})
BUILD_MAX_EDIT_LEN=$buildMax2
BLANK_IDLE_TAB_NE_DEFECT=1
CLICKABLE_TAB_NE_FEATURE_PASS=1
SOURCE_FINDING_NE_RUNTIME_PASS=1
BANNER_NE_EXECUTION_PASS=1
CHAT_INJECTION_LOCUS=AgentStepTimeline.addChip->onRow->appendCopilotChatUtf8
CHAT_INJECTION_FIX=removed_panel_addChip_powershell
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
CC79_UNREPLACED=1
A4F_IMMUTABLE=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
RUNLOG=$runLog
"@ | Set-Content -Path $receipt -Encoding UTF8

Log "RESULT=$overall LS_IN_PANE=$lsResult CHAT_CLEAN=$chatResult"
try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } catch {}
exit $(if ($overall -eq 'PASS_ROUTING') { 0 } else { 3 })
