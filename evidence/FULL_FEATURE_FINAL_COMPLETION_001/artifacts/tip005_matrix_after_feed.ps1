# tip_005 matrix continue on frozen 27E2263E. Launch = v2 feed path. CONTROLLING=CC79. PROMOTE=0.
$ErrorActionPreference = 'Continue'
$tipDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_005'
$TipExe = Join-Path $tipDir 'RawrXD-Win32IDE-Native-Ext.exe'
$OutDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts'
$BrokenCpp = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp'
$Debuggee = Join-Path $tipDir 'debuggee_fixture.exe'
$LogDir = Join-Path $tipDir 'gui_probe_logs'
$Receipt = Join-Path $OutDir 'COMPILER_CAPTURE_RECEIPT.txt'
$IdeReceipt = Join-Path $OutDir 'IDE_COMPILER_FEED_RECEIPT.txt'
$MatrixReceipt = Join-Path $OutDir 'TIP005_MATRIX_CONTINUE_RECEIPT.txt'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunLog = Join-Path $OutDir "tip005_matrix_continue_$stamp.log"
New-Item -ItemType Directory -Force -Path $OutDir,$LogDir | Out-Null
function Log([string]$m) {
  $line = "{0:o} {1}" -f (Get-Date), $m
  Add-Content -LiteralPath $RunLog -Value $line -Encoding UTF8
  Write-Host $line
}

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class Tip005M {
  public const uint WM_COMMAND=0x0111; public const uint WM_NOTIFY=0x004E;
  public const uint LVM_GETITEMCOUNT=0x1004; public const uint TCM_FIRST=0x1300;
  public const uint TCM_GETITEMCOUNT=TCM_FIRST+4; public const uint TCM_SETCURSEL=TCM_FIRST+12;
  public const int TCN_FIRST=-550; public const int TCN_SELCHANGE=TCN_FIRST-1; public const int NM_DBLCLK=-3;
  public const uint SMTO_ABORTIFHUNG=0x0002; public const uint SMTO_NORMAL=0x0000;
  public const int IDNO=7;
  [StructLayout(LayoutKind.Sequential)] public struct NMHDR { public IntPtr hwndFrom; public IntPtr idFrom; public int code; }
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeout(IntPtr h, uint m, IntPtr w, ref NMHDR l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  public static IntPtr FindMain(uint pid) {
    IntPtr found=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,256);
      if(sb.ToString()=="RawrXD_IDE_Window"){ found=h; return false;} return true; }, IntPtr.Zero);
    return found;
  }
  public static int DismissUnsaved(uint pid) {
    int n=0;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid) return true;
      var c=new StringBuilder(64); var t=new StringBuilder(256);
      GetClassNameW(h,c,64); GetWindowTextW(h,t,256);
      if(c.ToString()=="#32770" && t.ToString().IndexOf("Unsaved",StringComparison.OrdinalIgnoreCase)>=0){
        PostMessageW(h, WM_COMMAND, (IntPtr)IDNO, IntPtr.Zero); n++; }
      return true; }, IntPtr.Zero);
    return n;
  }
  public static string Title(IntPtr h){ var sb=new StringBuilder(512); GetWindowTextW(h,sb,512); return sb.ToString(); }
  public static IntPtr FindById(IntPtr root, int id){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static bool CmdSend(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,SMTO_NORMAL,ms,out r)!=IntPtr.Zero; }
  public static bool CmdPost(IntPtr main,int id){ return PostMessageW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero); }
  public static int ListCount(IntPtr root,int id,uint ms){ IntPtr h=FindById(root,id); if(h==IntPtr.Zero) return -1; IntPtr r; if(SendMessageTimeoutW(h,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return -3; return r.ToInt32(); }
  public static int TabCount(IntPtr tab,uint ms){ if(tab==IntPtr.Zero) return -1; IntPtr r; if(SendMessageTimeoutW(tab,TCM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return -3; return r.ToInt32(); }
  public static bool SelectTab(IntPtr main, IntPtr tab, int idx, int idFrom, uint ms){
    if(tab==IntPtr.Zero) return false; IntPtr r;
    if(SendMessageTimeoutW(tab,TCM_SETCURSEL,(IntPtr)idx,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return false;
    NMHDR nm; nm.hwndFrom=tab; nm.idFrom=(IntPtr)idFrom; nm.code=TCN_SELCHANGE;
    return SendMessageTimeout(main,WM_NOTIFY,(IntPtr)idFrom,ref nm,SMTO_ABORTIFHUNG,ms,out r)!=IntPtr.Zero;
  }
  public static bool PostDblClk(IntPtr main, IntPtr lv, int id, uint ms){
    if(lv==IntPtr.Zero||main==IntPtr.Zero) return false;
    NMHDR nm; nm.hwndFrom=lv; nm.idFrom=(IntPtr)id; nm.code=NM_DBLCLK; IntPtr r;
    return SendMessageTimeout(main,WM_NOTIFY,(IntPtr)id,ref nm,SMTO_ABORTIFHUNG,ms,out r)!=IntPtr.Zero
      || PostMessageW(main,WM_NOTIFY,(IntPtr)id,IntPtr.Zero);
  }
  public static int MaxEditLen(IntPtr root,uint ms){
    int max=0;
    EnumChildWindows(root,(h,lp)=>{
      var c=new StringBuilder(64); GetClassNameW(h,c,64);
      if(c.ToString()=="Edit" || c.ToString().IndexOf("RichEdit",StringComparison.OrdinalIgnoreCase)>=0){
        if(!IsWindowVisible(h)) return true;
        IntPtr r; if(SendMessageTimeoutW(h,0x000E,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return true;
        int n=r.ToInt32(); if(n>max) max=n;
      }
      return true;
    },IntPtr.Zero);
    return max;
  }
  public static string GetEditText(IntPtr h,uint ms){
    if(h==IntPtr.Zero) return "";
    IntPtr r; if(SendMessageTimeoutW(h,0x000E,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return "";
    int n=r.ToInt32(); if(n<=0) return "";
    if(n>200000) n=200000;
    IntPtr buf=Marshal.AllocHGlobal((n+1)*2);
    try {
      if(SendMessageTimeoutW(h,0x000D,(IntPtr)(n+1),buf,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return "";
      return Marshal.PtrToStringUni(buf) ?? "";
    } finally { Marshal.FreeHGlobal(buf); }
  }
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string text);
  public static bool SetText(IntPtr h, string text){ return h!=IntPtr.Zero && SetWindowTextW(h, text); }
}
"@

Log 'PREP kill by image (no WMI)'
cmd.exe /c "taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1"
Start-Sleep 3
$sess = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
$stampS = Get-Date -Format 'yyyyMMdd_HHmmss'
if (Test-Path $sess) {
  Move-Item -LiteralPath $sess -Destination ($sess + ".bak_tip005_mx_$stampS") -Force -EA SilentlyContinue
  Log 'QUARANTINE ide_session.json'
}
@'
{"active":0,"chat_mode":0,"documents":[{"modified":false,"path":"","text":""}]}
'@ | Set-Content -LiteralPath $sess -Encoding UTF8

Remove-Item $Receipt -Force -EA SilentlyContinue
$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "SHA=$sha"
$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
# Do NOT set RAWRXD_DEBUGGEE before HWND bind (prior four-panel EARLY_EXIT race).

$p = Start-Process -FilePath $TipExe -ArgumentList @($BrokenCpp) -WorkingDirectory $tipDir -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
$dismissed = 0
for ($i=0; $i -lt 90; $i++) {
  Start-Sleep -Milliseconds 500
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode)"; break }
  $dismissed += [Tip005M]::DismissUnsaved([uint32]$p.Id)
  $main = [Tip005M]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero -and [Tip005M]::IsWindowVisible($main)) { break }
  if ($main -ne [IntPtr]::Zero -and $i -gt 12) { break }
}
Log "DISMISSED=$dismissed MAIN=0x$('{0:X}' -f $main.ToInt64())"
Start-Sleep 2
if (-not $p.HasExited) { $dismissed += [Tip005M]::DismissUnsaved([uint32]$p.Id) }
$title = if ($main -ne [IntPtr]::Zero) { [Tip005M]::Title($main) } else { '' }
Log "TITLE=$title"
$buildOk = $false; $buildMode = 'none'
if ($main -ne [IntPtr]::Zero -and -not $p.HasExited) {
  [void][Tip005M]::ShowWindow($main, 9)
  [void][Tip005M]::SetForegroundWindow($main)
  for ($t=0; $t -lt 5 -and -not $buildOk; $t++) {
    $dismissed += [Tip005M]::DismissUnsaved([uint32]$p.Id)
    $buildOk = [Tip005M]::CmdSend($main, 3014, 15000)
    if ($buildOk) { $buildMode = 'SendMessageTimeout'; break }
    Start-Sleep 1
  }
  if (-not $buildOk) { $buildOk = [Tip005M]::CmdPost($main, 3014); if ($buildOk) { $buildMode = 'PostMessage' } }
}
Log "BUILD_CMD_3014=$buildOk MODE=$buildMode"

$items = 0; $diag = 0; $exitDisp = 'running'; $hwndUpdated = $false
$deadline = (Get-Date).AddSeconds(100)
while ((Get-Date) -lt $deadline) {
  Start-Sleep 2
  if (-not $p.HasExited) { $dismissed += [Tip005M]::DismissUnsaved([uint32]$p.Id) }
  if (Test-Path $Receipt) {
    $txt = Get-Content $Receipt -Raw
    $diag = ([regex]::Matches($txt, 'DIAGNOSTIC_PARSED')).Count
    if ($txt -match 'BUILD_RESULT=(\w+)') { $exitDisp = $Matches[1] }
    if ($txt -match 'PROBLEMS_HWND_UPDATED') { $hwndUpdated = $true }
  }
  if (-not $p.HasExited -and $main -ne [IntPtr]::Zero -and [Tip005M]::IsWindow($main)) {
    $items = [Tip005M]::ListCount($main, 1312, 2000)
    if ($items -gt 0) { $hwndUpdated = $true; break }
  }
  if ($p.HasExited) { break }
}
Log "PROBLEMS_ITEMS=$items DIAG=$diag DISP=$exitDisp"

$TO = [uint32]2500
$clickToLine = 'NOT_RUN'
$selOut0=$false;$selBuild=$false;$selErr=$false;$selOutPanel=$false;$selProb=$false;$selTerm=$false;$selDbg=$false
$probVis = -1; $visEdit = 0; $outTabCount = -1; $panelTabCount = -1
$dbgResults = @(); $peak6043 = 0; $peak1317 = 0; $sessionReal = 0
$vtStatus = 'NOT_RUN'; $cmdExec = 'NOT_RUN'; $rawCsi = 'NOT_RUN'
$csiSample = ''

if ($main -ne [IntPtr]::Zero -and -not $p.HasExited -and $items -gt 0) {
  foreach ($cmd in @(2034,2025,2021,2029)) { [void][Tip005M]::CmdSend($main,$cmd,$TO) }
  $outTabs = [Tip005M]::FindById($main,1005)
  $panelTabs = [Tip005M]::FindById($main,1301)
  $outTabCount = [Tip005M]::TabCount($outTabs,$TO)
  $panelTabCount = [Tip005M]::TabCount($panelTabs,$TO)
  $visEdit = [Tip005M]::MaxEditLen($main,$TO)
  if ($outTabCount -gt 0) { $selOut0 = [Tip005M]::SelectTab($main,$outTabs,0,1005,$TO) }
  if ($outTabCount -gt 4) { $selBuild = [Tip005M]::SelectTab($main,$outTabs,4,1005,$TO) }
  if ($outTabCount -gt 1) { $selErr = [Tip005M]::SelectTab($main,$outTabs,1,1005,$TO) }
  if ($panelTabCount -gt 1) { $selOutPanel = [Tip005M]::SelectTab($main,$panelTabs,1,1301,$TO) }
  if ($panelTabCount -gt 2) { $selProb = [Tip005M]::SelectTab($main,$panelTabs,2,1301,$TO) }
  Start-Sleep -Milliseconds 400
  $items = [Tip005M]::ListCount($main,1312,$TO)
  $lv = [Tip005M]::FindById($main,1312)
  $probVis = if ($lv -ne [IntPtr]::Zero -and [Tip005M]::IsWindowVisible($lv)) { 1 } else { 0 }
  if ($items -gt 0) {
    if ([Tip005M]::PostDblClk($main,$lv,1312,$TO)) { $clickToLine = 'POSTED_NM_DBLCLK' } else { $clickToLine = 'LIST_HWND_MISSING' }
  }
  Log "CLICK_TO_LINE=$clickToLine items=$items"

  if ($panelTabCount -gt 0) { $selTerm = [Tip005M]::SelectTab($main,$panelTabs,0,1301,$TO) }
  if ($panelTabCount -gt 3) { $selDbg = [Tip005M]::SelectTab($main,$panelTabs,3,1301,$TO) }

  # IDE debug UI (after HWND stable). Set debuggee env late.
  $env:RAWRXD_DEBUGGEE = $Debuggee
  foreach ($act in @(1104,6004)) { [void][Tip005M]::CmdSend($main,$act,2000); Start-Sleep -Milliseconds 300 }
  foreach ($dc in @(
    @{n='TOOLS_DEBUG_START_5060';id=5060},
    @{n='DEBUG_START_10500';id=10500},
    @{n='SIDEBAR_DEBUG_START_6041';id=6041},
    @{n='SHOW_VARS_10508';id=10508},
    @{n='SHOW_CALLSTACK_10507';id=10507},
    @{n='STEP_OVER';id=10503},
    @{n='CONTINUE';id=10502}
  )) {
    if ($p.HasExited) { $dbgResults += "$($dc.n)=SKIP_EXITED"; break }
    $ok = [Tip005M]::CmdSend($main,$dc.id,5000)
    Start-Sleep -Milliseconds 800
    $v1317 = [Tip005M]::ListCount($main,1317,$TO)
    $v6043 = [Tip005M]::ListCount($main,6043,$TO)
    if ($v6043 -gt $peak6043) { $peak6043 = $v6043 }
    if ($v1317 -gt $peak1317) { $peak1317 = $v1317 }
    $dbgResults += "$($dc.n)=$ok"
    Log "DEBUG $($dc.n)=$ok vars6043=$v6043 vars1317=$v1317"
    if ($dc.id -in 5060,10500,6041) {
      for ($w=0; $w -lt 12; $w++) {
        Start-Sleep 1
        $v6043 = [Tip005M]::ListCount($main,6043,$TO)
        if ($v6043 -gt $peak6043) { $peak6043 = $v6043 }
        if ($v6043 -gt 0) { break }
      }
    }
  }
  $stopOk = [Tip005M]::CmdSend($main,10501,5000)
  $dbgResults += "STOP=$stopOk"
  if ($peak6043 -gt 0 -or $peak1317 -gt 0) { $sessionReal = 1 }

  # VT + CMD_EXEC: select PowerShell/terminal panel, send colored echo, check RichEdit for raw CSI.
  if (-not $p.HasExited) {
    if ($panelTabCount -gt 0) { [void][Tip005M]::SelectTab($main,$panelTabs,0,1301,$TO) }
    # Prefer PowerShell view commands if present.
    foreach ($psCmd in @(2029,3002,3006)) { [void][Tip005M]::CmdSend($main,$psCmd,$TO) }
    Start-Sleep 1
    # Inject via terminal execute path: write CSI-bearing echo into PS input if found (id 1202 common) else PostMessage build output path.
    $psIn = [Tip005M]::FindById($main,1202)
    $psOut = [Tip005M]::FindById($main,1201)
    if ($psOut -eq [IntPtr]::Zero) { $psOut = [Tip005M]::FindById($main,1012) }
    $marker = "TIP005_VT_MARK_$stamp"
    $cmdLine = "Write-Host `"$marker`" -ForegroundColor Green; Write-Output `"ok`""
    if ($psIn -ne [IntPtr]::Zero) {
      [void][Tip005M]::SetText($psIn, $cmdLine)
      Start-Sleep -Milliseconds 200
      [void][Tip005M]::CmdSend($main, 3002, 3000)
      $cmdExec = 'POSTED'
      Start-Sleep 4
      $txtOut = ''
      if ($psOut -ne [IntPtr]::Zero) { $txtOut = [Tip005M]::GetEditText($psOut, 3000) }
      if ([string]::IsNullOrEmpty($txtOut)) { Log "PS_OUT_EMPTY visEdit=$([Tip005M]::MaxEditLen($main,2000))" }
      if ($txtOut -match [regex]::Escape($marker)) { $cmdExec = 'VERIFIED' }
      elseif ($txtOut -match '(?i)\bok\b' -and $cmdExec -eq 'POSTED') { $cmdExec = 'PARTIAL_OK_TEXT' }
      elseif ($cmdExec -eq 'POSTED') { $cmdExec = 'POSTED_NO_CAPTURE' }
      if ($txtOut -match "`e\[" -or $txtOut -match '\x1b\[') {
        $vtStatus = 'FAIL_RAW_CSI'
        $rawCsi = 'PRESENT'
        $csiSample = ($txtOut.Substring(0, [Math]::Min(200, $txtOut.Length)) -replace "`r|`n",' ')
      } else {
        $vtStatus = 'PASS_NO_RAW_CSI'
        $rawCsi = 'ABSENT'
      }
      Log "CMD_EXEC=$cmdExec VT=$vtStatus RAW_CSI=$rawCsi OUT_LEN=$($txtOut.Length)"
    } else {
      $cmdExec = 'INPUT_HWND_MISSING'
      $vtStatus = 'NOT_RUN_NO_PS_INPUT'
      Log 'PS_INPUT id1202 missing'
    }
  }
}

$sessionRealUi = $sessionReal
$outPass = if ($visEdit -gt 20) { 'PASS' } else { 'PARTIAL' }
$probPass = if ($probVis -eq 1 -and $items -gt 0) { 'PASS' } elseif ($items -gt 0) { 'PARTIAL' } else { 'FAIL' }
$dbgPass = if ($sessionRealUi -eq 1) { 'PASS' } elseif (($dbgResults -join ';') -match '=True') { 'PARTIAL_UI_HOOKS_POSTED' } else { 'FAIL' }
$four = 'FAIL_CLOSED_GAPS'
if ($outPass -eq 'PASS' -and $probPass -eq 'PASS' -and $dbgPass -eq 'PASS') { $four = 'PASS' }

$recTxt = if (Test-Path $Receipt) { Get-Content $Receipt -Raw } else { '' }
$stdoutLines = ([regex]::Matches($recTxt, 'STDOUT_LINE')).Count
$problemAdded = ([regex]::Matches($recTxt, 'PROBLEM_ADDED')).Count
$titleEnd = if ($main -ne [IntPtr]::Zero -and [Tip005M]::IsWindow($main)) { [Tip005M]::Title($main) } else { $title }

$feedBody = @"
IDE_COMPILER_FEED=MEASURED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
CONTROLLING_TIP=CC79
CANDIDATE_SHA256=$sha
CANDIDATE_NOT_PROMOTED=1
TIP_EXE=$TipExe
TITLE=$titleEnd
BUILD_CMD_3014=$buildOk
BUILD_CMD_MODE=$buildMode
COMPILER_EXECUTION=$(if($recTxt -match 'PROCESS_STARTED'){'VERIFIED'}else{'NOT_VERIFIED'})
COMPILER_OUTPUT_CAPTURE=$(if($stdoutLines -gt 1){'VERIFIED'}else{'NOT_VERIFIED'})
DIAGNOSTIC_FEED=$(if($diag -gt 0){'VERIFIED'}else{'NOT_VERIFIED'})
DIAGNOSTIC_PARSED_COUNT=$diag
PROBLEM_ADDED_COUNT=$problemAdded
STDOUT_LINE_COUNT=$stdoutLines
PROBLEMS_ID1312_ITEMS=$items
PROBLEMS_HWND_UPDATED=$hwndUpdated
BUILD_RESULT_DISPOSITION=$exitDisp
PROCESS_EXIT_SEEN=$($recTxt -match 'PROCESS_EXIT')
BOUNDARY_BUILD_REQUEST=$($recTxt -match 'BUILD_REQUEST')
BOUNDARY_PROCESS_CREATE=$($recTxt -match 'PROCESS_CREATE')
BOUNDARY_PROCESS_STARTED=$($recTxt -match 'PROCESS_STARTED')
BOUNDARY_STDOUT_LINE=$($recTxt -match 'STDOUT_LINE')
BOUNDARY_STDERR_LINE=$($recTxt -match 'STDERR_LINE')
BOUNDARY_PROCESS_EXIT=$($recTxt -match 'PROCESS_EXIT')
BOUNDARY_DIAGNOSTIC_PARSED=$($recTxt -match 'DIAGNOSTIC_PARSED')
BOUNDARY_PROBLEM_ADDED=$($recTxt -match 'PROBLEM_ADDED')
BOUNDARY_BUILD_RESULT=$($recTxt -match 'BUILD_RESULT')
DISMISSED_UNSAVED=$dismissed
RUNLOG=$RunLog
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
RECEIPT=$Receipt
"@
$feedBody | Set-Content -LiteralPath $IdeReceipt -Encoding UTF8

$matrix = @"
TIP005_MATRIX_CONTINUE=MEASURED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
CONTROLLING_TIP=CC79
TIP_SHA256=$sha
TIP_EXE=$TipExe
MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())
TITLE=$titleEnd
COMPILER_FEED=$(if($diag -gt 0 -and $items -gt 0){'PASS'}else{'FAIL'})
PROBLEMS_ID1312_ITEMS=$items
CLICK_TO_LINE=$clickToLine
IDE_DEBUG_UI=$dbgPass
SESSION_REAL_VIA_IDE_UI=$sessionRealUi
DEBUG_VARS_ID6043=$peak6043
DEBUG_VARS_ID1317=$peak1317
DEBUG_CMDS=$($dbgResults -join ';')
FOUR_PANEL_INTEGRATION=$four
GUI_OUTPUT_PANEL_E2E=$outPass
GUI_PROBLEMS_PANEL_E2E=$probPass
SELECT_OUTPUT_TAB0=$selOut0
SELECT_BUILD_TAB4=$selBuild
SELECT_ERRORS_TAB1=$selErr
SELECT_PANEL_OUTPUT1=$selOutPanel
SELECT_PANEL_PROBLEMS2=$selProb
SELECT_PANEL_TERMINAL0=$selTerm
SELECT_PANEL_DEBUG3=$selDbg
OUT_TABS=$outTabCount
PANEL_TABS=$panelTabCount
MAX_VISIBLE_EDIT_LEN=$visEdit
CONSOLE_RENDER_VT=$vtStatus
RAW_CSI=$rawCsi
CSI_SAMPLE=$csiSample
CMD_EXEC=$cmdExec
RESEAL_EXT_CHAT_TERM_OUTPUT_HEADLESS=NOT_RUN
RESEAL_GATE=requires feed+debug PASS (debug=$dbgPass feed_items=$items)
TIP_MOVE=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
NO_CROSS_SHA_PASS_INHERITANCE=1
RUNLOG=$RunLog
"@
$matrix | Set-Content -LiteralPath $MatrixReceipt -Encoding UTF8
Log $matrix

if (-not $p.HasExited) { try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } catch {} }
cmd.exe /c "taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1"
if ($diag -le 0 -or $items -le 0) { exit 2 }
exit 0
