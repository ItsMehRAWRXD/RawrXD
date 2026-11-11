# Four-panel Terminal+Output+Problems+Debug on tip_cc79_integ_001. PROMOTE=0.
# Debug may stay BLOCKED/PARTIAL — never invent PASS. A4F/CC79 untouched.
param(
  [Parameter(Mandatory=$true)][string]$TipExe,
  [string]$ExpectSha = "",
  [string]$BrokenCpp = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp",
  [string]$OutDir = "F:\rawrxd\evidence\CC79_RUNTIME_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\CC79_RUNTIME_001\candidates\tip_cc79_integ_001",
  [string]$Debuggee = ""
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$sha = (Get-FileHash $TipExe -Algorithm SHA256).Hash
if ($ExpectSha -and ($sha -ne $ExpectSha)) {
  "FOUR_PANEL=NOT_RUN`nREASON=SHA_DRIFT`nTIP_SHA256=$sha`nEXPECT=$ExpectSha`nPROMOTE=0" |
    Set-Content (Join-Path $OutDir 'FOUR_PANEL_CC79_RUNTIME_RECEIPT.txt')
  exit 3
}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "four_panel_cc79_runtime_$stamp.txt"
$receipt = Join-Path $OutDir 'FOUR_PANEL_CC79_RUNTIME_RECEIPT.txt'
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class FPCc79 {
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
$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
if ($Debuggee -and (Test-Path $Debuggee)) { $env:RAWRXD_DEBUGGEE = $Debuggee }
else { Remove-Item Env:RAWRXD_DEBUGGEE -EA SilentlyContinue }
Log "TIP_SHA256=$sha"
Log "TIP_EXE=$TipExe"
Log "DEBUGGEE=$Debuggee EXISTS=$([int](!!$Debuggee -and (Test-Path $Debuggee)))"
Remove-Item "F:\rawrxd\evidence\RAWRXD_BUILD_OUTPUT_latest.log" -EA SilentlyContinue
Log "RAWRXD_DEBUGGEE=$env:RAWRXD_DEBUGGEE"
# Prefer env RAWRXD_DEBUGGEE over WorkingDirectory (WORKDIR tip-dir caused EARLY_EXIT races).
$p = Start-Process -FilePath $TipExe -ArgumentList @($BrokenCpp) -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
for ($i=0; $i -lt 90; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode) t=$i"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; Log "MAIN_VIA_PROC t=$i"; break }
  $main = [FPCc79]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { Log "MAIN_VIA_ENUM t=$i"; break }
  if (($i % 10) -eq 0) { Log "WAIT_MAIN t=$i handle=$($p.MainWindowHandle)" }
}
Log "MAIN=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) {
  "FOUR_PANEL=NOT_RUN`nREASON=main_hwnd_missing`nTIP_SHA256=$sha`nPROMOTE=0" | Set-Content $receipt
  exit 2
}
[void][FPCc79]::ShowWindow($main, 9)
[void][FPCc79]::SetForegroundWindow($main)
Start-Sleep 2

$panelPre = [int][FPCc79]::VisId($main, 1300)
Log "PANEL_CONTAINER_VIS_PRE=$panelPre"
if ($panelPre -eq 0) {
  $ok = [FPCc79]::Cmd($main, 2034, 2000)
  Log "SHOW_PANEL_2034 ok=$ok (was hidden)"
  Start-Sleep -Milliseconds 500
} else {
  Log "SKIP_2034_ALREADY_VISIBLE"
}
# Do NOT post 2025 (IDM_VIEW_OUTPUT_PANEL) — it toggles m_outputPanelVisible OFF
# and undoes ensurePanelVisible. 2021 is the same toggle family. Terminal 2029
# is optional and does not own the four-panel dock.
foreach ($cmd in @(2028)) {
  $ok = [FPCc79]::Cmd($main, $cmd, 2000)
  Log "VIEW_CMD id=$cmd ok=$ok"
  Start-Sleep -Milliseconds 200
}
$panelAfterView = [int][FPCc79]::VisId($main, 1300)
Log "PANEL_CONTAINER_VIS_AFTER_VIEW=$panelAfterView"
if ($panelAfterView -eq 0) {
  [void][FPCc79]::Cmd($main, 2034, 2000)
  Start-Sleep -Milliseconds 400
  $panelAfterView = [int][FPCc79]::VisId($main, 1300)
  Log "PANEL_CONTAINER_VIS_AFTER_RETRY=$panelAfterView"
}

$outTabs = [FPCc79]::FindId($main, 1005)
$panelTabs = [FPCc79]::FindId($main, 1301)
$outCount = if ($outTabs -ne [IntPtr]::Zero) { [int][FPCc79]::SendMessageW($outTabs, 0x1304, [IntPtr]::Zero, [IntPtr]::Zero) } else { -1 }
$panelCount = if ($panelTabs -ne [IntPtr]::Zero) { [int][FPCc79]::SendMessageW($panelTabs, 0x1304, [IntPtr]::Zero, [IntPtr]::Zero) } else { -1 }
Log "OUT_TABS=$outCount PANEL_TABS=$panelCount"

Start-Sleep 1
$buildOk = [FPCc79]::Cmd($main, 3014, 15000)
Log "BUILD ok=$buildOk"
$id1312 = -1; $id1604 = -1
for ($w=0; $w -lt 45; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { Log "EXIT t=$w code=$($p.ExitCode)"; break }
  $id1312 = [FPCc79]::IdList($main, 1312)
  $id1604 = [FPCc79]::IdLen($main, 1604)
  if (($w % 5) -eq 0) { Log "POLL t=$w ID1312=$id1312 ID1604=$id1604 PANEL=$([int][FPCc79]::VisId($main,1300))" }
  if ($id1312 -gt 0 -and $id1604 -gt 0) { break }
  if ($id1312 -gt 0 -and $w -ge 15) { break }
}

$selTerm = $false; $selOut = $false; $selProb = $false; $selDbg = $false
if ($panelCount -gt 0) { $selTerm = [FPCc79]::SelectTab($main, $panelTabs, 0, 1301) }
if ($panelCount -gt 1) { $selOut = [FPCc79]::SelectTab($main, $panelTabs, 1, 1301) }
if ($panelCount -gt 2) { $selProb = [FPCc79]::SelectTab($main, $panelTabs, 2, 1301) }
if ($panelCount -gt 3) { $selDbg = [FPCc79]::SelectTab($main, $panelTabs, 3, 1301) }
Start-Sleep -Milliseconds 300
$panelContVis = [int][FPCc79]::VisId($main, 1300)
$probVis = [int][FPCc79]::VisId($main, 1312)
Log "TABS term=$selTerm out=$selOut prob=$selProb dbg=$selDbg PANEL_CONT=$panelContVis PROB_VIS=$probVis"

$click = 'NOT_RUN'
if ($id1312 -gt 0) {
  $lv = [FPCc79]::FindId($main, 1312)
  if ([FPCc79]::DblClk($main, $lv, 1312)) { $click = 'POSTED_NM_DBLCLK' } else { $click = 'LIST_HWND_MISSING' }
}

$termClear = [FPCc79]::Cmd($main, 3006, 1500)
$termCmd = [FPCc79]::Cmd($main, 3002, 1500)

# START-only Debug path (B39 law): do not storm START/CONTINUE/STOP before vars settle.
foreach ($act in @(1104, 6004)) { [void][FPCc79]::Cmd($main, $act, 2000); Start-Sleep -Milliseconds 300 }
$varsPre = [FPCc79]::IdList($main, 6043)
Log "VARS_PRE=$varsPre DEBUGGEE_SET=$([int](!!$env:RAWRXD_DEBUGGEE))"
$startOk = [FPCc79]::Cmd($main, 5060, 20000)
$dbgPosted = @("id=5060`:$startOk")
Log "START5060=$startOk"
$varsPeak = [Math]::Max(-1, $varsPre)
$sessionReal = 0
for ($w=0; $w -lt 20; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { Log "IDE_EXIT_DURING_DEBUG w=$w"; break }
  $v = [FPCc79]::IdList($main, 6043)
  if ($v -gt $varsPeak) { $varsPeak = $v }
  $child = @(Get-Process -Name 'debuggee_fixture' -EA SilentlyContinue).Count
  if (($w % 4) -eq 0) { Log "DBG_POLL w=$w vars=$v peak=$varsPeak child=$child" }
  if ($v -gt 0) { $sessionReal = 1; break }
}
$stepOk = $false; $contOk = $false; $stopOk = $false
if ($sessionReal -eq 1) {
  $stepOk = [FPCc79]::Cmd($main, 10503, 4000); $dbgPosted += "id=10503`:$stepOk"; Start-Sleep 1
  $contOk = [FPCc79]::Cmd($main, 10508, 4000); $dbgPosted += "id=10508`:$contOk"; Start-Sleep 1
}
$stopOk = [FPCc79]::Cmd($main, 10501, 3000); $dbgPosted += "id=10501`:$stopOk"
Start-Sleep 1
Get-Process -Name 'debuggee_fixture' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
$alive = [int](-not $p.HasExited -and [FPCc79]::IsWindow($main))
$panelFinal = [int][FPCc79]::VisId($main, 1300)
# Refresh Output/Problems after Build+Debug for conjunction scoreboard.
$id1312 = [FPCc79]::IdList($main, 1312)
$id1604 = [FPCc79]::IdLen($main, 1604)
$probVis = [int][FPCc79]::VisId($main, 1312)

$outPass = if ($id1604 -gt 0) { 'PASS' } else { 'FAIL' }
$probPass = if ($id1312 -gt 0 -and $click -eq 'POSTED_NM_DBLCLK') { 'PASS' } elseif ($id1312 -gt 0) { 'PARTIAL' } else { 'FAIL' }
$termPass = if ($termClear -or $termCmd) { 'PARTIAL' } else { 'FAIL' }
$dbgResult = if ($sessionReal -eq 1) { 'PASS_SESSION_REAL' } elseif ($alive -eq 1) { 'BLOCKED_NO_SESSION_REAL' } else { 'FAIL' }
$four = 'FAIL_CLOSED_GAPS'
if ($panelFinal -eq 1 -and $id1312 -gt 0 -and $id1604 -gt 0 -and $selTerm -and $selOut -and $selProb -and $selDbg) {
  if ($sessionReal -eq 1) { $four = 'PASS' } else { $four = 'PARTIAL_PANEL_VISIBLE_DEBUG_BLOCKED' }
} elseif ($panelFinal -eq 1 -and $id1312 -gt 0 -and $id1604 -gt 0) {
  $four = 'PARTIAL_PANEL_VISIBLE'
}

$a4f = (Get-FileHash 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe' -Algorithm SHA256).Hash
$cc79 = (Get-FileHash 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe' -Algorithm SHA256).Hash
@(
"FOUR_PANEL_CC79_RUNTIME=MEASURED",
"ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))",
"TIP_SHA256=$sha",
"TIP_EXE=$TipExe",
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
"IDE_DEBUG_UI=$dbgResult",
"FOUR_PANEL_INTEGRATION=$four",
"DEBUGGEE_PATH=$Debuggee",
"DEBUGGEE_EXISTS=$([int](!!$Debuggee -and (Test-Path $Debuggee)))",
"ALIVE=$alive",
"A4F_SHA256=$a4f",
"A4F_UNTOUCHED=$([int]($a4f -eq 'A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E'))",
"CC79_SHA256=$cc79",
"CC79_UNTOUCHED=$([int]($cc79 -eq 'CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4'))",
"NO_CROSS_SHA_PASS_INHERITANCE=1",
"RUNLOG=$runlog",
"PROMOTE=0",
"CERTIFIED=0",
"PRODUCT_PASS=0"
) | Set-Content $receipt
Get-Content $receipt
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
exit 0
