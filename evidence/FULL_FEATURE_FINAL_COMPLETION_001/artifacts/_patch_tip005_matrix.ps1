$src = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\tip005_full_matrix.ps1'
$c = Get-Content -LiteralPath $src -Raw
if ($c -match 'MATRIX_CONTINUE') { Write-Host 'ALREADY'; exit 0 }
$old = 'if (-not $p.HasExited) { try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } catch {} }'
$ins = @'
# --- MATRIX CONTINUE (same live HWND; no relaunch) ---
$MatrixReceipt = Join-Path $OutDir 'TIP005_MATRIX_CONTINUE_RECEIPT.txt'
$clickToLine='NOT_RUN'; $dbgPass='NOT_RUN'; $four='NOT_RUN'; $reseal='NOT_RUN'
$selOut0=$false;$selBuild=$false;$selErr=$false;$selOutPanel=$false;$selProb=$false;$selTerm=$false;$selDbg=$false
$probVis=-1;$visEdit=0;$outTabCount=-1;$panelTabCount=-1
$dbgResults=@();$peak6043=0;$peak1317=0;$sessionReal=0
$vtStatus='NOT_RUN';$rawCsi='NOT_RUN';$cmdExec='NOT_RUN';$csiSample=''
$TO=[uint32]2500
$Debuggee = Join-Path $tipDir 'debuggee_fixture.exe'
if ($main -ne [IntPtr]::Zero -and -not $p.HasExited -and $items -gt 0 -and $diag -gt 0) {
  Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class IdeCap3X {
  public const uint WM_COMMAND=0x0111; public const uint WM_NOTIFY=0x004E;
  public const uint LVM_GETITEMCOUNT=0x1004; public const uint TCM_FIRST=0x1300;
  public const uint TCM_GETITEMCOUNT=TCM_FIRST+4; public const uint TCM_SETCURSEL=TCM_FIRST+12;
  public const uint WM_GETTEXT=0x000D; public const uint WM_GETTEXTLENGTH=0x000E;
  public const int TCN_FIRST=-550; public const int TCN_SELCHANGE=TCN_FIRST-1; public const int NM_DBLCLK=-3;
  public const uint SMTO_ABORTIFHUNG=0x0002;
  [StructLayout(LayoutKind.Sequential)] public struct NMHDR { public IntPtr hwndFrom; public IntPtr idFrom; public int code; }
  public delegate bool EnumChildProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeout(IntPtr h, uint m, IntPtr w, ref NMHDR l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string t);
  public static IntPtr FindById(IntPtr root, int id){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static bool CmdSend(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,0,ms,out r)!=IntPtr.Zero; }
  public static int ListCount(IntPtr root,int id,uint ms){ IntPtr h=FindById(root,id); if(h==IntPtr.Zero) return -1; IntPtr r; if(SendMessageTimeoutW(h,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return -3; return r.ToInt32(); }
  public static int TabCount(IntPtr tab,uint ms){ if(tab==IntPtr.Zero) return -1; IntPtr r; if(SendMessageTimeoutW(tab,TCM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return -3; return r.ToInt32(); }
  public static bool SelectTab(IntPtr main,IntPtr tab,int idx,int idFrom,uint ms){ if(tab==IntPtr.Zero) return false; IntPtr r; if(SendMessageTimeoutW(tab,TCM_SETCURSEL,(IntPtr)idx,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return false; NMHDR nm; nm.hwndFrom=tab; nm.idFrom=(IntPtr)idFrom; nm.code=TCN_SELCHANGE; return SendMessageTimeout(main,WM_NOTIFY,(IntPtr)idFrom,ref nm,SMTO_ABORTIFHUNG,ms,out r)!=IntPtr.Zero; }
  public static bool PostDblClk(IntPtr main,IntPtr lv,int id,uint ms){ if(lv==IntPtr.Zero||main==IntPtr.Zero) return false; NMHDR nm; nm.hwndFrom=lv; nm.idFrom=(IntPtr)id; nm.code=NM_DBLCLK; IntPtr r; return SendMessageTimeout(main,WM_NOTIFY,(IntPtr)id,ref nm,SMTO_ABORTIFHUNG,ms,out r)!=IntPtr.Zero; }
  public static int MaxEditLen(IntPtr root,uint ms){ int max=0; EnumChildWindows(root,(h,lp)=>{ var c=new StringBuilder(64); GetClassNameW(h,c,64); string cs=c.ToString(); if((cs=="Edit"||cs.IndexOf("RichEdit",StringComparison.OrdinalIgnoreCase)>=0)&&IsWindowVisible(h)){ IntPtr r; if(SendMessageTimeoutW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)!=IntPtr.Zero){ int n=r.ToInt32(); if(n>max) max=n; }} return true; },IntPtr.Zero); return max; }
  public static string GetEditText(IntPtr h,uint ms){ if(h==IntPtr.Zero) return ""; IntPtr r; if(SendMessageTimeoutW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return ""; int n=r.ToInt32(); if(n<=0) return ""; if(n>100000) n=100000; IntPtr buf=Marshal.AllocHGlobal((n+1)*2); try { if(SendMessageTimeoutW(h,WM_GETTEXT,(IntPtr)(n+1),buf,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return ""; return Marshal.PtrToStringUni(buf)??""; } finally { Marshal.FreeHGlobal(buf);} }
}
"@
  Log "MATRIX_CONTINUE items=$items"
  foreach ($cmd in @(2034,2025,2021,2029)) { [void][IdeCap3X]::CmdSend($main,$cmd,$TO) }
  $outTabs=[IdeCap3X]::FindById($main,1005); $panelTabs=[IdeCap3X]::FindById($main,1301)
  $outTabCount=[IdeCap3X]::TabCount($outTabs,$TO); $panelTabCount=[IdeCap3X]::TabCount($panelTabs,$TO)
  $visEdit=[IdeCap3X]::MaxEditLen($main,$TO)
  if ($outTabCount -gt 0) { $selOut0=[IdeCap3X]::SelectTab($main,$outTabs,0,1005,$TO) }
  if ($outTabCount -gt 4) { $selBuild=[IdeCap3X]::SelectTab($main,$outTabs,4,1005,$TO) }
  if ($outTabCount -gt 1) { $selErr=[IdeCap3X]::SelectTab($main,$outTabs,1,1005,$TO) }
  if ($panelTabCount -gt 1) { $selOutPanel=[IdeCap3X]::SelectTab($main,$panelTabs,1,1301,$TO) }
  if ($panelTabCount -gt 2) { $selProb=[IdeCap3X]::SelectTab($main,$panelTabs,2,1301,$TO) }
  Start-Sleep -Milliseconds 400
  $items=[IdeCap3X]::ListCount($main,1312,$TO)
  $lv=[IdeCap3X]::FindById($main,1312)
  $probVis = if ($lv -ne [IntPtr]::Zero -and [IdeCap3X]::IsWindowVisible($lv)) { 1 } else { 0 }
  if ($items -gt 0) { if ([IdeCap3X]::PostDblClk($main,$lv,1312,$TO)) { $clickToLine='POSTED_NM_DBLCLK' } else { $clickToLine='LIST_HWND_MISSING' } }
  Log "CLICK_TO_LINE=$clickToLine"
  if ($panelTabCount -gt 0) { $selTerm=[IdeCap3X]::SelectTab($main,$panelTabs,0,1301,$TO) }
  if ($panelTabCount -gt 3) { $selDbg=[IdeCap3X]::SelectTab($main,$panelTabs,3,1301,$TO) }
  $env:RAWRXD_DEBUGGEE=$Debuggee
  foreach ($act in @(1104,6004)) { [void][IdeCap3X]::CmdSend($main,$act,2000); Start-Sleep -Milliseconds 300 }
  foreach ($dc in @(@{n='TOOLS_DEBUG_START_5060';id=5060},@{n='DEBUG_START_10500';id=10500},@{n='SIDEBAR_DEBUG_START_6041';id=6041},@{n='SHOW_VARS_10508';id=10508},@{n='SHOW_CALLSTACK_10507';id=10507},@{n='STEP_OVER';id=10503},@{n='CONTINUE';id=10502})) {
    if ($p.HasExited) { $dbgResults += "$($dc.n)=SKIP_EXITED"; break }
    $ok=[IdeCap3X]::CmdSend($main,$dc.id,5000); Start-Sleep -Milliseconds 700
    $v6043=[IdeCap3X]::ListCount($main,6043,$TO); $v1317=[IdeCap3X]::ListCount($main,1317,$TO)
    if ($v6043 -gt $peak6043) { $peak6043=$v6043 }; if ($v1317 -gt $peak1317) { $peak1317=$v1317 }
    $dbgResults += "$($dc.n)=$ok"; Log "DEBUG $($dc.n)=$ok vars6043=$v6043"
    if ($dc.id -in 5060,10500,6041) { for ($w=0;$w -lt 10;$w++) { Start-Sleep 1; $v6043=[IdeCap3X]::ListCount($main,6043,$TO); if ($v6043 -gt $peak6043) { $peak6043=$v6043 }; if ($v6043 -gt 0) { break } } }
  }
  $dbgResults += "STOP=$([IdeCap3X]::CmdSend($main,10501,5000))"
  if ($peak6043 -gt 0 -or $peak1317 -gt 0) { $sessionReal=1 }
  $dbgPass = if ($sessionReal -eq 1) { 'PASS' } elseif (($dbgResults -join ';') -match '=True') { 'PARTIAL_UI_HOOKS_POSTED' } else { 'FAIL' }
  if (-not $p.HasExited) {
    if ($panelTabCount -gt 0) { [void][IdeCap3X]::SelectTab($main,$panelTabs,0,1301,$TO) }
    foreach ($psCmd in @(2029,3002)) { [void][IdeCap3X]::CmdSend($main,$psCmd,$TO) }
    $psIn=[IdeCap3X]::FindById($main,1202); $psOut=[IdeCap3X]::FindById($main,1201)
    if ($psOut -eq [IntPtr]::Zero) { $psOut=[IdeCap3X]::FindById($main,1012) }
    $marker="TIP005_VT_$([DateTime]::UtcNow.ToString('HHmmss'))"
    if ($psIn -ne [IntPtr]::Zero) {
      [void][IdeCap3X]::SetWindowTextW($psIn, "Write-Host `"$marker`" -ForegroundColor Green")
      Start-Sleep -Milliseconds 200; [void][IdeCap3X]::CmdSend($main,3002,3000); $cmdExec='POSTED'; Start-Sleep 4
      $txtOut = if ($psOut -ne [IntPtr]::Zero) { [IdeCap3X]::GetEditText($psOut,3000) } else { '' }
      if ($txtOut -match [regex]::Escape($marker)) { $cmdExec='VERIFIED' } elseif ($cmdExec -eq 'POSTED') { $cmdExec='POSTED_NO_CAPTURE' }
      if ($txtOut -match [char]27 + '\[') { $vtStatus='FAIL_RAW_CSI'; $rawCsi='PRESENT'; $csiSample=($txtOut.Substring(0,[Math]::Min(180,$txtOut.Length)) -replace "`r|`n",' ') }
      else { $vtStatus='PASS_NO_RAW_CSI'; $rawCsi='ABSENT' }
      Log "CMD_EXEC=$cmdExec VT=$vtStatus OUT_LEN=$($txtOut.Length)"
    } else { $cmdExec='INPUT_HWND_MISSING'; $vtStatus='NOT_RUN_NO_PS_INPUT' }
  }
  $outPass = if ($visEdit -gt 20) { 'PASS' } else { 'PARTIAL' }
  $probPass = if ($probVis -eq 1 -and $items -gt 0) { 'PASS' } elseif ($items -gt 0) { 'PARTIAL' } else { 'FAIL' }
  $four = if ($outPass -eq 'PASS' -and $probPass -eq 'PASS' -and $dbgPass -eq 'PASS') { 'PASS' } else { 'FAIL_CLOSED_GAPS' }
  $reseal = if ($dbgPass -eq 'PASS') { 'ELIGIBLE_BUT_NOT_RUN_THIS_HARNESS' } else { 'HELD_DEBUG_NOT_PASS' }
} else {
  Log "MATRIX_SKIPPED items=$items diag=$diag exited=$($p.HasExited)"
  $reseal='HELD_FEED_INCOMPLETE'
}

'@
if ($c.IndexOf($old) -lt 0) { Write-Host 'ANCHOR_MISSING'; exit 2 }
$c2 = $c.Replace($old, $ins + "`r`n" + $old)
# Also append matrix receipt write before final exit 0
$exitAnchor = @'
$body | Set-Content -LiteralPath $IdeReceipt -Encoding UTF8
Log $body
if ($diag -le 0) { exit 2 }
exit 0
'@
$exitIns = @'
$body | Set-Content -LiteralPath $IdeReceipt -Encoding UTF8
Log $body
$matrix = @"
TIP005_MATRIX_CONTINUE=MEASURED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
CONTROLLING_TIP=CC79
TIP_SHA256=$sha
PROBLEMS_ID1312_ITEMS=$items
CLICK_TO_LINE=$clickToLine
IDE_DEBUG_UI=$dbgPass
SESSION_REAL_VIA_IDE_UI=$sessionReal
DEBUG_VARS_ID6043=$peak6043
DEBUG_VARS_ID1317=$peak1317
DEBUG_CMDS=$($dbgResults -join ';')
FOUR_PANEL_INTEGRATION=$four
GUI_OUTPUT_PANEL_E2E=$(if($visEdit -gt 20){'PASS'}elseif($items -gt 0){'PARTIAL'}else{'FAIL'})
GUI_PROBLEMS_PANEL_E2E=$(if($probVis -eq 1 -and $items -gt 0){'PASS'}elseif($items -gt 0){'PARTIAL'}else{'FAIL'})
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
RESEAL_EXT_CHAT_TERM_OUTPUT_HEADLESS=$reseal
TIP_MOVE=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
NO_CROSS_SHA_PASS_INHERITANCE=1
RUNLOG=$RunLog
"@
$matrix | Set-Content -LiteralPath $MatrixReceipt -Encoding UTF8
Log $matrix
if ($diag -le 0) { exit 2 }
exit 0
'@
if ($c2.IndexOf($exitAnchor) -lt 0) { Write-Host 'EXIT_ANCHOR_MISSING'; Set-Content -LiteralPath $src -Value $c2 -Encoding UTF8; exit 3 }
$c3 = $c2.Replace($exitAnchor, $exitIns)
Set-Content -LiteralPath $src -Value $c3 -Encoding UTF8
Write-Host 'PATCHED_OK'
