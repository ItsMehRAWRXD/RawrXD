# Four-panel + Debug remasure on 27E226. Do NOT toggle panel off via 2034.
# Root cause: IDM_VIEW_PANEL=2034 toggles; prior harness hid IDC_PANEL_CONTAINER(1300).
$ErrorActionPreference = 'Continue'
$exe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_session_real_001\RawrXD-Win32IDE-Native-Ext.exe'
$expect = 'B39EFDADC8A8B990B25502D5B1D81F4A1875DA9CE5BAA25E40922727D213D432'
$broken = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp'
$debuggee = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_session_real_001\debuggee_fixture.exe'
$outDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts'
$logDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\four_panel_remeasure_b39'
New-Item -ItemType Directory -Force -Path $outDir, $logDir | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
$runlog = Join-Path $outDir ("four_panel_remeasure_b39_" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".txt")
$receipt = Join-Path $outDir 'FOUR_PANEL_DEBUG_UI_B39_RECEIPT.txt'
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}
if ($sha -ne $expect) {
  "FOUR_PANEL=NOT_RUN`nREASON=SHA_DRIFT`nTIP_SHA256=$sha`nPROMOTE=0" | Set-Content $receipt
  exit 3
}
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class FPFix {
  public const uint WM_COMMAND=0x0111; public const uint WM_NOTIFY=0x004E;
  public const uint WM_GETTEXTLENGTH=0x000E; public const uint LVM_GETITEMCOUNT=0x1004;
  public const uint TCM_SETCURSEL=0x130C; public const uint TCM_GETITEMCOUNT=0x1304;
  public const int TCN_SELCHANGE=-551; public const int NM_DBLCLK=-3;
  public const uint SMTO_NORMAL=0;
  [StructLayout(LayoutKind.Sequential)] public struct NMHDR { public IntPtr hwndFrom; public IntPtr idFrom; public int code; }
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref NMHDR l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  public static IntPtr FindMain(uint pid){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,256);
      if(sb.ToString()=="RawrXD_IDE_Window"){ f=h; return false;} return true; }, IntPtr.Zero);
    return f;
  }
  public static IntPtr FindId(IntPtr root,int id){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static int IdLen(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero); }
  public static int IdList(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero); }
  public static bool VisId(IntPtr root,int id){ IntPtr h=FindId(root,id); return h!=IntPtr.Zero && IsWindowVisible(h); }
  public static bool Cmd(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,SMTO_NORMAL,ms,out r)!=IntPtr.Zero; }
  public static bool SelectTab(IntPtr root, IntPtr tab, int idx, int idFrom){
    if(tab==IntPtr.Zero) return false;
    SendMessageW(tab,TCM_SETCURSEL,(IntPtr)idx,IntPtr.Zero);
    NMHDR nm; nm.hwndFrom=tab; nm.idFrom=(IntPtr)idFrom; nm.code=TCN_SELCHANGE;
    SendMessage(root,WM_NOTIFY,(IntPtr)idFrom,ref nm);
    return true;
  }
  public static bool DblClk(IntPtr main, IntPtr lv, int id){
    if(lv==IntPtr.Zero) return false;
    NMHDR nm; nm.hwndFrom=lv; nm.idFrom=(IntPtr)id; nm.code=NM_DBLCLK;
    SendMessage(main,WM_NOTIFY,(IntPtr)id,ref nm); return true;
  }
}
"@
$env:RAWRXD_LOG_DIR = $logDir
$env:RAWRXD_PROBLEMS_FIXTURE = $broken
if (Test-Path $debuggee) { $env:RAWRXD_DEBUGGEE = $debuggee } else { Remove-Item Env:RAWRXD_DEBUGGEE -EA SilentlyContinue }
Log "TIP_SHA256=$sha"
Log "DEBUGGEE=$debuggee EXISTS=$([int](Test-Path $debuggee))"
$p = Start-Process -FilePath $exe -ArgumentList @($broken) -WorkingDirectory 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_session_real_001' -PassThru -WindowStyle Normal
$main = [IntPtr]::Zero
for ($i=0; $i -lt 50; $i++) {
  Start-Sleep -Milliseconds 400
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode)"; break }
  $main = [FPFix]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log "MAIN=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) { exit 2 }
[void][FPFix]::ShowWindow($main, 9)
[void][FPFix]::SetForegroundWindow($main)
Start-Sleep 2

$panelPre = [int][FPFix]::VisId($main, 1300)
Log "PANEL_CONTAINER_VIS_PRE=$panelPre"
# Show-only: if hidden, post IDM_VIEW_PANEL once; if visible, do NOT toggle 2034
if ($panelPre -eq 0) {
  $ok = [FPFix]::Cmd($main, 2034, 2000)
  Log "SHOW_PANEL_2034 ok=$ok (was hidden)"
  Start-Sleep -Milliseconds 500
} else {
  Log "SKIP_2034_ALREADY_VISIBLE"
}
# Other view cmds that are NOT panel toggle
foreach ($cmd in @(2025, 2021, 2029)) {
  $ok = [FPFix]::Cmd($main, $cmd, 2000)
  Log "VIEW_CMD id=$cmd ok=$ok"
  Start-Sleep -Milliseconds 200
}
$panelAfterView = [int][FPFix]::VisId($main, 1300)
Log "PANEL_CONTAINER_VIS_AFTER_VIEW=$panelAfterView"
# If still hidden, try 2034 once more
if ($panelAfterView -eq 0) {
  [void][FPFix]::Cmd($main, 2034, 2000)
  Start-Sleep -Milliseconds 400
  $panelAfterView = [int][FPFix]::VisId($main, 1300)
  Log "PANEL_CONTAINER_VIS_AFTER_RETRY=$panelAfterView"
}

$outTabs = [FPFix]::FindId($main, 1005)
$panelTabs = [FPFix]::FindId($main, 1301)
$outCount = if ($outTabs -ne [IntPtr]::Zero) { [int][FPFix]::SendMessageW($outTabs, 0x1304, [IntPtr]::Zero, [IntPtr]::Zero) } else { -1 }
$panelCount = if ($panelTabs -ne [IntPtr]::Zero) { [int][FPFix]::SendMessageW($panelTabs, 0x1304, [IntPtr]::Zero, [IntPtr]::Zero) } else { -1 }
Log "OUT_TABS=$outCount PANEL_TABS=$panelCount"

Start-Sleep 1
$buildOk = [FPFix]::Cmd($main, 3014, 15000)
Log "BUILD ok=$buildOk"
$id1312 = -1; $id1604 = -1
for ($w=0; $w -lt 40; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { Log "EXIT t=$w code=$($p.ExitCode)"; break }
  $id1312 = [FPFix]::IdList($main, 1312)
  $id1604 = [FPFix]::IdLen($main, 1604)
  if (($w % 5) -eq 0) { Log "POLL t=$w ID1312=$id1312 ID1604=$id1604 PANEL=$([int][FPFix]::VisId($main,1300))" }
  if ($id1312 -gt 0 -and $id1604 -gt 0) { break }
  if ($id1312 -gt 0 -and $w -ge 12) { break }
}

# Select panel tabs Terminal/Output/Problems/Debug without killing IDE
$selTerm = $false; $selOut = $false; $selProb = $false; $selDbg = $false
if ($panelCount -gt 0) { $selTerm = [FPFix]::SelectTab($main, $panelTabs, 0, 1301) }
if ($panelCount -gt 1) { $selOut = [FPFix]::SelectTab($main, $panelTabs, 1, 1301) }
if ($panelCount -gt 2) { $selProb = [FPFix]::SelectTab($main, $panelTabs, 2, 1301) }
if ($panelCount -gt 3) { $selDbg = [FPFix]::SelectTab($main, $panelTabs, 3, 1301) }
Start-Sleep -Milliseconds 300
$panelContVis = [int][FPFix]::VisId($main, 1300)
$probVis = [int][FPFix]::VisId($main, 1312)
Log "TABS term=$selTerm out=$selOut prob=$selProb dbg=$selDbg PANEL_CONT=$panelContVis PROB_VIS=$probVis"

$click = 'NOT_RUN'
if ($id1312 -gt 0) {
  $lv = [FPFix]::FindId($main, 1312)
  if ([FPFix]::DblClk($main, $lv, 1312)) { $click = 'POSTED_NM_DBLCLK' } else { $click = 'LIST_HWND_MISSING' }
}

# Terminal cmds
$termClear = [FPFix]::Cmd($main, 3006, 1500)
$termCmd = [FPFix]::Cmd($main, 3002, 1500)

# Debug: activate debug view then launch path (product uses CreateProcess DEBUG_* via launchNativeDebuggee)
foreach ($act in @(1104, 6004)) { [void][FPFix]::Cmd($main, $act, 2000); Start-Sleep -Milliseconds 300 }
$varsPre = [FPFix]::IdList($main, 6043)
Log "VARS_PRE=$varsPre"
$dbgPosted = @()
foreach ($dc in @(5060, 10500, 6041, 10508, 10507, 10503, 10501, 10505)) {
  $ok = [FPFix]::Cmd($main, $dc, 2500)
  $dbgPosted += "id=$dc`:$ok"
  Start-Sleep -Milliseconds 350
}
$varsPeak = -1
$sessionReal = 0
for ($w=0; $w -lt 20; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { break }
  $v = [FPFix]::IdList($main, 6043)
  if ($v -gt $varsPeak) { $varsPeak = $v }
  if ($v -gt 0) { $sessionReal = 1; break }
}
$alive = [int](-not $p.HasExited -and [FPFix]::IsWindow($main))
$panelFinal = [int][FPFix]::VisId($main, 1300)

$outPass = if ($id1604 -gt 0) { 'PASS' } else { 'FAIL' }
$probPass = if ($id1312 -gt 0 -and $click -eq 'POSTED_NM_DBLCLK') { 'PASS' } elseif ($id1312 -gt 0) { 'PARTIAL' } else { 'FAIL' }
$termPass = if ($termClear -or $termCmd) { 'PARTIAL' } else { 'FAIL' }
$dbgResult = if ($sessionReal -eq 1) { 'PASS_SESSION_REAL' } elseif ($alive -eq 1) { 'PARTIAL_UI_HOOKS_POSTED' } else { 'FAIL' }
$four = 'FAIL_CLOSED_GAPS'
if ($panelFinal -eq 1 -and $id1312 -gt 0 -and $id1604 -gt 0 -and $selTerm -and $selOut -and $selProb -and $selDbg) {
  if ($sessionReal -eq 1) { $four = 'PASS' } else { $four = 'PARTIAL_NO_DEBUG_SESSION' }
} elseif ($panelFinal -eq 1 -and $id1312 -gt 0 -and $id1604 -gt 0) {
  $four = 'PARTIAL_PANEL_VISIBLE'
}

$a4f = (Get-FileHash 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe' -Algorithm SHA256).Hash
@(
"FOUR_PANEL_DEBUG_UI=MEASURED",
"ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))",
"TIP_SHA256=$sha",
"ROOT_CAUSE=IDM_VIEW_PANEL_2034_TOGGLE_HID_CONTAINER_WHEN_ALREADY_VISIBLE",
"PANEL_CONTAINER_VIS_PRE=$panelPre",
"PANEL_CONTAINER_VISIBLE=$panelFinal",
"PROBLEMS_ID1312_ITEMS=$id1312",
"PROBLEMS_ID1312_VISIBLE=$probVis",
"CLICK_TO_LINE=$click",
"OUTPUT_ID1604_LEN=$id1604",
"SELECT_PANEL_TERMINAL0=$selTerm",
"SELECT_PANEL_OUTPUT1=$selOut",
"SELECT_PANEL_PROBLEMS2=$selProb",
"SELECT_PANEL_DEBUG3=$selDbg",
"TERMINAL_VIEW_CMD=clear=$termClear;cmd=$termCmd",
"GUI_OUTPUT_PANEL_E2E=$outPass",
"GUI_PROBLEMS_PANEL_E2E=$probPass",
"TERMINAL_PANEL_E2E=$termPass",
"DEBUG_CMDS=$($dbgPosted -join ';')",
"DEBUG_VARS_ID6043_PEAK=$varsPeak",
"DEBUG_SESSION_REAL=$sessionReal",
"DEBUG_PRODUCT_PATH=CreateProcess_DEBUG_ONLY_THIS_PROCESS_plus_WaitForDebugEvent",
"DEBUG_ACTIVE_PROCESS_API=0_EXPECTED_NOT_USED",
"DEBUG_MISSING_HOOK=$(if($sessionReal -eq 0){'launchNativeDebuggee SESSION_REAL not observed after WM_COMMAND debug starts'}else{''})",
"IDE_DEBUG_UI=$dbgResult",
"FOUR_PANEL_INTEGRATION=$four",
"DEBUGGEE_PATH=$debuggee",
"DEBUGGEE_EXISTS=$([int](Test-Path $debuggee))",
"ALIVE=$alive",
"A4F_UNTOUCHED=$([int]($a4f -eq 'A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E'))",
"CONTROLLING_TIP=CC79",
"CC79_PROBLEMS_UI=FAIL",
"NO_CROSS_SHA_PASS_INHERITANCE=1",
"RUNLOG=$runlog",
"PROMOTE=0",
"CERTIFIED=0",
"PRODUCT_PASS=0"
) | Set-Content $receipt
Get-Content $receipt
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
