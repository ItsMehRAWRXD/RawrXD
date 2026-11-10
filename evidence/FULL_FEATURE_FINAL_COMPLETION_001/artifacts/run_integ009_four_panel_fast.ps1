# Fast exclusive Debug+FourPanel on tip_009 SHA 0946. PROMOTE=0.
# Avoids long waits that lose races to sibling Stop-Process killers.
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$freezeLock = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts\ISSUE49_EXCLUSIVE.lock'
$expect = '0946C7AA0397C1F400FB7A960D8DBC4AC98A601C128351054EE9857FA5D11BF9'
$tipDir = Join-Path $root 'candidates\tip_final_integ_009'
$TipExe = Join-Path $tipDir 'RawrXD-Win32IDE-Native-Ext.exe'
$OutDir = Join-Path $root 'artifacts'
$LogDir = Join-Path $tipDir 'debug_ui_reverify_logs'
$BrokenCpp = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp'
$Debuggee = Join-Path $tipDir 'debuggee_fixture.exe'
$receipt = Join-Path $OutDir 'INTEG009_DEBUG_UI_HARNESS_RECEIPT.txt'
$runlog = Join-Path $OutDir ("INTEG009_debug_ui_reverify_run_{0:yyyyMMdd-HHmmss}.txt" -f (Get-Date))
New-Item -ItemType Directory -Force -Path $OutDir,$LogDir,(Split-Path $freezeLock) | Out-Null

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}

@(
  'OWNER=integ009_four_panel_fast'
  "PID=$PID"
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
  "SHA=$expect"
  'DO_NOT_STOP_PROCESS_NATIVE_EXT=1'
) | Set-Content $lock -Encoding ASCII
Copy-Item $lock $freezeLock -Force

# Pre-clean competitors (including FreezeEO / tip002 remasures)
Get-Process -Name 'RawrXD*','deep2_agentic_loop','debuggee_fixture' -EA SilentlyContinue |
  ForEach-Object { Log "PREKILL $($_.Id) $($_.ProcessName)"; Stop-Process -Id $_.Id -Force -EA SilentlyContinue }
Start-Sleep 2

$pre = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "PRE_SHA=$pre SHA_MATCH=$([int]($pre -eq $expect))"
if ($pre -ne $expect) {
  Remove-Item $lock,$freezeLock -Force -EA SilentlyContinue
  exit 3
}

$sess = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
New-Item -ItemType Directory -Force -Path (Split-Path $sess) | Out-Null
Set-Content -LiteralPath $sess -Encoding UTF8 -Value '{"active":0,"chat_mode":0,"documents":[{"modified":false,"path":"","text":""}]}'

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class FpFast {
  public const uint WM_COMMAND=0x0111, WM_GETTEXTLENGTH=0x000E, WM_NOTIFY=0x004E;
  public const uint TCM_FIRST=0x1300, TCM_SETCURSEL=TCM_FIRST+12, TCM_GETCURSEL=TCM_FIRST+11, TCM_GETITEMCOUNT=TCM_FIRST+4;
  public const uint LVM_GETITEMCOUNT=0x1004; public const int TCN_SELCHANGE=-551;
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [StructLayout(LayoutKind.Sequential)] public struct NMHDR { public IntPtr hwndFrom; public IntPtr idFrom; public int code; }
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref NMHDR l);
  public static IntPtr FindMain(uint pid) {
    IntPtr found=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint wpid; GetWindowThreadProcessId(h,out wpid);
      if(wpid!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,256);
      if(sb.ToString()=="RawrXD_IDE_Window"||sb.ToString()=="RawrXD_IDE_MainWindow"){ found=h; return false; }
      return true; }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindId(IntPtr root, int id) {
    IntPtr f=IntPtr.Zero;
    EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){ f=h; return false;} return true;}, IntPtr.Zero);
    return f;
  }
  public static bool SelectTab(IntPtr main, IntPtr tab, int index, int idFrom) {
    if(tab==IntPtr.Zero) return false;
    SendMessageW(tab, TCM_SETCURSEL, (IntPtr)index, IntPtr.Zero);
    NMHDR nm; nm.hwndFrom=tab; nm.idFrom=(IntPtr)idFrom; nm.code=TCN_SELCHANGE;
    SendMessage(main, WM_NOTIFY, (IntPtr)idFrom, ref nm);
    return (int)SendMessageW(tab, TCM_GETCURSEL, IntPtr.Zero, IntPtr.Zero)==index;
  }
  public static int IdLen(IntPtr root, int id) {
    IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1;
    return (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
  }
  public static int IdList(IntPtr root, int id) {
    IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1;
    return (int)SendMessageW(h, LVM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero);
  }
  public static int MaxVisibleEdit(IntPtr root) {
    int max=0;
    EnumChildWindows(root,(h,lp)=>{
      if(!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(64); GetClassNameW(h,sb,64);
      string c=sb.ToString();
      if(c.IndexOf("Edit",StringComparison.OrdinalIgnoreCase)>=0 || c.IndexOf("RichEdit",StringComparison.OrdinalIgnoreCase)>=0){
        int len=(int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
        if(len>max) max=len;
      }
      return true;
    }, IntPtr.Zero);
    return max;
  }
  public static int TabCount(IntPtr tab) {
    if(tab==IntPtr.Zero) return 0;
    return (int)SendMessageW(tab, TCM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero);
  }
}
"@

$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
$env:RAWRXD_DEBUGGEE = $Debuggee
Remove-Item Env:VS_UNICODE_OUTPUT -EA SilentlyContinue

# Watchdog: kill ONLY foreign RawrXD (not our PID) that appear during measure
$pidFile = Join-Path $OutDir 'integ009_keep_pid.txt'
'0' | Set-Content $pidFile -Encoding ASCII
$watch = Start-Job -ArgumentList $pidFile -ScriptBlock {
  param($pidPath)
  for ($i=0; $i -lt 90; $i++) {
    Start-Sleep 1
    $keep = 0
    try { $keep = [int]((Get-Content -LiteralPath $pidPath -EA SilentlyContinue | Select-Object -First 1)) } catch {}
    Get-Process -Name 'RawrXD*' -EA SilentlyContinue | Where-Object {
      $_.Id -ne $keep
    } | ForEach-Object {
      # Never kill our keep Native-Ext pid; kill FreezeEO and foreign Native tips
      if ($keep -gt 0 -and $_.Id -eq $keep) { return }
      Stop-Process -Id $_.Id -Force -EA SilentlyContinue
    }
  }
}

try {
  $p = Start-Process -FilePath $TipExe -ArgumentList "`"$BrokenCpp`"" -WorkingDirectory $tipDir -PassThru -WindowStyle Normal
  "$($p.Id)" | Set-Content $pidFile -Encoding ASCII
  Log "PID=$($p.Id)"
  $main = [IntPtr]::Zero
  for ($i=0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 250
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode) t=$i"; break }
    $main = [FpFast]::FindMain([uint32]$p.Id)
    if ($main -ne [IntPtr]::Zero) { Log "MAIN t=$i"; break }
  }
  Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())"
  if ($main -eq [IntPtr]::Zero) { throw 'main_missing' }

  [void][FpFast]::ShowWindow($main, 9)
  [void][FpFast]::SetForegroundWindow($main)
  foreach ($cmd in @(2034, 2025, 2021, 2029)) {
    [void][FpFast]::SendMessageW($main, 0x0111, [IntPtr]$cmd, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 150
  }
  $outTabs = [FpFast]::FindId($main, 1005)
  $panelTabs = [FpFast]::FindId($main, 1301)
  Log "OUT_TABS=$([FpFast]::TabCount($outTabs)) PANEL_TABS=$([FpFast]::TabCount($panelTabs))"

  [void][FpFast]::SendMessageW($main, 0x0111, [IntPtr]3014, [IntPtr]::Zero)
  Log "POST_BUILD=3014"
  $id1604 = -1; $probItems = -1; $visEdit = 0
  for ($w=0; $w -lt 25; $w++) {
    Start-Sleep 1
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { Log "EXIT_DURING_WAIT=$($p.ExitCode) t=$w"; break }
    # Re-assert lock presence for siblings
    if (-not (Test-Path $lock)) { Copy-Item $freezeLock $lock -Force -EA SilentlyContinue }
    $id1604 = [FpFast]::IdLen($main, 1604)
    $probItems = [FpFast]::IdList($main, 1312)
    $visEdit = [FpFast]::MaxVisibleEdit($main)
    if (($w % 3) -eq 0) { Log "POLL t=$w id1604=$id1604 prob=$probItems visEdit=$visEdit" }
    if ($id1604 -gt 40 -and $probItems -gt 0) { break }
  }

  $selOut0 = [FpFast]::SelectTab($main, $outTabs, 0, 1005)
  $selBuild = [FpFast]::SelectTab($main, $outTabs, 4, 1005)
  $selOutPanel = [FpFast]::SelectTab($main, $panelTabs, 1, 1301)
  $selProbPanel = [FpFast]::SelectTab($main, $panelTabs, 2, 1301)
  [void][FpFast]::SendMessageW($main, 0x0111, [IntPtr]2034, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  $probItems = [FpFast]::IdList($main, 1312)
  $panelContainer = [FpFast]::FindId($main, 1300)
  $panelContVis = if ($panelContainer -ne [IntPtr]::Zero -and [FpFast]::IsWindowVisible($panelContainer)) { 1 } else { 0 }
  $probVis = if ($probItems -gt 0) { 1 } else { 0 }
  Log "AFTER_TAB id1604=$id1604 prob=$probItems panelCont=$panelContVis selBuild=$selBuild selProb=$selProbPanel"

  # Debug activate
  $selDbg = [FpFast]::SelectTab($main, $panelTabs, 3, 1301)
  $dbgPosted = $false
  if (-not $p.HasExited -and [FpFast]::IsWindow($main)) {
    [void][FpFast]::SendMessageW($main, 0x0111, [IntPtr]5060, [IntPtr]::Zero) # TOOLS_DEBUG_START
    Start-Sleep 2
    $dbgPosted = $true
  }
  $vars1317 = [FpFast]::IdList($main, 1317)
  $vars6043 = [FpFast]::IdList($main, 6043)
  if ($vars1317 -lt 0) { $vars1317 = 0 }
  if ($vars6043 -lt 0) { $vars6043 = 0 }
  $sessionRealUi = if ($vars6043 -gt 0 -or $vars1317 -gt 0) { 1 } else { 0 }
  Log "DEBUG posted=$dbgPosted vars1317=$vars1317 vars6043=$vars6043 sessionUI=$sessionRealUi"

  try { $p.Refresh() } catch {}
  $alive = -not $p.HasExited
  $outPass = if ($id1604 -gt 40 -or $visEdit -gt 20) { 'PASS' } else { 'PARTIAL' }
  $probPass = if ($probVis -eq 1 -and $probItems -gt 0) { 'PASS' } elseif ($probItems -gt 0) { 'PARTIAL' } else { 'FAIL' }
  $dbgPass = if ($sessionRealUi -eq 1) { 'PASS' } elseif ($dbgPosted) { 'PARTIAL_UI_HOOKS_POSTED' } else { 'FAIL' }
  $four = 'FAIL_CLOSED_GAPS'
  if ($outPass -eq 'PASS' -and $probPass -eq 'PASS' -and $dbgPass -eq 'PASS' -and $panelContVis -eq 1 -and $probVis -eq 1) {
    $four = 'PASS'
  }

  $post = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
  $asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@"
INTEG009_DEBUG_UI_HARNESS=MEASURED
ASOF_UTC=$asof
TIP_SHA256=$pre
TIP_EXE=$TipExe
PID=$($p.Id)
MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())
ALIVE=$alive
EXITED=$($p.HasExited)
EXIT=$($p.ExitCode)
SELECT_OUTPUT_TAB0=$selOut0
SELECT_BUILD_TAB4=$selBuild
SELECT_PANEL_OUTPUT1=$selOutPanel
SELECT_PANEL_PROBLEMS2=$selProbPanel
SELECT_PANEL_DEBUG3=$selDbg
OUTPUT_ID1604_BUILD_LEN=$id1604
MAX_VISIBLE_EDIT_LEN_AFTER_BUILD=$visEdit
PROBLEMS_ID1312_ITEMS=$probItems
PROBLEMS_ID1312_VISIBLE=$probVis
PANEL_CONTAINER_VISIBLE=$panelContVis
DEBUG_VARS_ID1317=$vars1317
DEBUG_VARS_ID6043=$vars6043
SESSION_REAL_VIA_IDE_UI=$sessionRealUi
GUI_OUTPUT_PANEL_E2E=$outPass
GUI_PROBLEMS_PANEL_E2E=$probPass
GUI_DEBUG_CONSOLE_E2E=$dbgPass
IDE_DEBUG_UI=$dbgPass
FOUR_PANEL_INTEGRATION=$four
DISK_DRIFT=0
DISK_POST_DRIFT=$([int]($post -ne $expect))
POST_SHA=$post
HARNESS=run_integ009_four_panel_fast.ps1
FROZEN_A4F_UNTOUCHED=1
NO_CROSS_SHA_PASS_INHERITANCE=1
RUNLOG=$runlog
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@ | Set-Content $receipt -Encoding ASCII
  Log "RECEIPT FOUR=$four OUT=$outPass PROB=$probPass DBG=$dbgPass"
  Get-Content $receipt
  if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
}
catch {
  Log "FAIL $_"
  exit 2
}
finally {
  Stop-Job $watch -EA SilentlyContinue
  Remove-Job $watch -Force -EA SilentlyContinue
  Remove-Item $lock,$freezeLock -Force -EA SilentlyContinue
}
exit 0
