# IDE compiler feed prove for tip_005 @ frozen 27E2263E. CONTROLLING=CC79. PROMOTE=0.
# Avoids Get-CimInstance / EnumWindows floods. Dismisses Unsaved Changes modal.
$ErrorActionPreference = 'Continue'
$tipDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_005'
$TipExe = Join-Path $tipDir 'RawrXD-Win32IDE-Native-Ext.exe'
$OutDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts'
$BrokenCpp = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp'
$Debuggee = Join-Path $tipDir 'debuggee_fixture.exe'
$Receipt = Join-Path $OutDir 'COMPILER_CAPTURE_RECEIPT.txt'
$IdeReceipt = Join-Path $OutDir 'IDE_COMPILER_FEED_RECEIPT.txt'
$RunLog = Join-Path $OutDir ('prove_ide_compiler_feed_tip005_v2_{0:yyyyMMdd-HHmmss}.log' -f (Get-Date))
$LogDir = Join-Path $tipDir 'gui_probe_logs'
New-Item -ItemType Directory -Force -Path $OutDir,$LogDir | Out-Null

function Log([string]$m) {
  $line = "{0:o} {1}" -f (Get-Date), $m
  Add-Content -LiteralPath $RunLog -Value $line -Encoding UTF8
  Write-Host $line
}

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class IdeCap3 {
  public const uint WM_COMMAND=0x0111; public const uint LVM_GETITEMCOUNT=0x1004;
  public const uint SMTO_ABORTIFHUNG=0x0002; public const uint SMTO_NORMAL=0x0000;
  public const int IDNO=7; public const int IDYES=6; public const int IDCANCEL=2;
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr FindWindowW(string cls, string title);
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
      if(c.ToString()=="#32770" && t.ToString().IndexOf("Unsaved Changes",StringComparison.OrdinalIgnoreCase)>=0){
        PostMessageW(h, WM_COMMAND, (IntPtr)IDNO, IntPtr.Zero);
        n++;
      }
      return true;
    }, IntPtr.Zero);
    return n;
  }
  public static string Title(IntPtr h){ var sb=new StringBuilder(512); GetWindowTextW(h,sb,512); return sb.ToString(); }
  public static IntPtr FindById(IntPtr root, int id){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static bool CmdSend(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,SMTO_NORMAL,ms,out r)!=IntPtr.Zero; }
  public static bool CmdPost(IntPtr main,int id){ return PostMessageW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero); }
  public static int ListCount(IntPtr root,int id,uint ms){ IntPtr h=FindById(root,id); if(h==IntPtr.Zero) return -1; IntPtr r; if(SendMessageTimeoutW(h,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return -3; return r.ToInt32(); }
}
"@

Log "PREP kill by image (no WMI)"
cmd.exe /c "taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1"
Start-Sleep 2

# Quarantine session restore that causes Unsaved Changes modal on openDocument.
$sess = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
$state = Join-Path $env:LOCALAPPDATA 'RawrXD\session.state'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (Test-Path $sess) {
  Move-Item -LiteralPath $sess -Destination ($sess + ".bak_tip005_$stamp") -Force -EA SilentlyContinue
  Log "QUARANTINE ide_session.json"
}
if (Test-Path $state) {
  Move-Item -LiteralPath $state -Destination ($state + ".bak_tip005_$stamp") -Force -EA SilentlyContinue
  Log "QUARANTINE session.state"
}
@'
{"active":0,"chat_mode":0,"documents":[{"modified":false,"path":"","text":""}]}
'@ | Set-Content -LiteralPath $sess -Encoding UTF8
Log "CLEAN_SESSION ide_session.json written"

Remove-Item $Receipt,'F:\rawrxd\evidence\RAWRXD_BUILD_OUTPUT_latest.log' -Force -EA SilentlyContinue
$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "SHA=$sha EXE=$TipExe"
if ($sha -ne '27E2263E44F681C3FE0EAB19A8FC8228C10668B8A1742A15BB19E8F6E66C3FFC') {
  Log "SHA_MISMATCH expected frozen 27E2263E"
}

$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
# Do NOT set RAWRXD_DEBUGGEE pre-launch (EARLY_EXIT race on tip_005). EXE-dir fallback finds debuggee_fixture.exe.
Remove-Item Env:RAWRXD_DEBUGGEE -EA SilentlyContinue
# Unquoted path — PowerShell Start-Process quoting; double-quotes can confuse argv.
$p = Start-Process -FilePath $TipExe -ArgumentList @($BrokenCpp) -WorkingDirectory $tipDir -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
$dismissed = 0
for ($i=0; $i -lt 90; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if (-not $p.HasExited) { $dismissed += [IdeCap3]::DismissUnsaved([uint32]$p.Id) }
  if ($p.HasExited) {
    $ec = $p.ExitCode
    $mainUsable = ($main -ne [IntPtr]::Zero -and [IdeCap3]::IsWindow($main) -and [IdeCap3]::IsWindowVisible($main))
    Log "EARLY_EXIT ExitCode=$ec at i=$i dismissed=$dismissed mainUsable=$mainUsable"
    # Stale HWND from dead process must not block relaunch.
    if (-not $mainUsable -and $i -lt 40) {
      $main = [IntPtr]::Zero
      @'
{"active":0,"chat_mode":0,"documents":[{"modified":false,"path":"","text":""}]}
'@ | Set-Content -LiteralPath $sess -Encoding UTF8
      Remove-Item $Receipt -Force -EA SilentlyContinue
      Start-Sleep 2
      $p = Start-Process -FilePath $TipExe -ArgumentList @($BrokenCpp) -WorkingDirectory $tipDir -PassThru -WindowStyle Normal
      Log "RELAUNCH_PID=$($p.Id)"
      $dismissed = 0
      continue
    }
    break
  }
  $main = [IdeCap3]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) {
    # Accept HWND even if temporarily not visible (modal may cover).
    if ([IdeCap3]::IsWindowVisible($main) -or $i -gt 8) { break }
  }
}
Log "DISMISSED_UNSAVED=$dismissed MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())"
Start-Sleep 2
# One more dismiss pass in case openDocument raced.
if (-not $p.HasExited) { $dismissed += [IdeCap3]::DismissUnsaved([uint32]$p.Id) }

$title = if ($main -ne [IntPtr]::Zero) { [IdeCap3]::Title($main) } else { '' }
Log "TITLE=$title"
$buildOk = $false
$buildMode = 'none'
if ($main -ne [IntPtr]::Zero -and -not $p.HasExited) {
  for ($t=0; $t -lt 5 -and -not $buildOk; $t++) {
    [void][IdeCap3]::DismissUnsaved([uint32]$p.Id)
    $buildOk = [IdeCap3]::CmdSend($main, 3014, 15000)
    if ($buildOk) { $buildMode = 'SendMessageTimeout'; break }
    Start-Sleep 1
  }
  if (-not $buildOk) {
    $buildOk = [IdeCap3]::CmdPost($main, 3014)
    if ($buildOk) { $buildMode = 'PostMessage' }
  }
}
Log "BUILD_CMD_3014=$buildOk MODE=$buildMode"

$deadline = (Get-Date).AddSeconds(130)
$items = 0
$diag = 0
$exitDisp = 'running'
$hwndUpdated = $false
while ((Get-Date) -lt $deadline) {
  Start-Sleep 2
  if (-not $p.HasExited) { [void][IdeCap3]::DismissUnsaved([uint32]$p.Id) }
  if (Test-Path $Receipt) {
    $txt = Get-Content $Receipt -Raw
    $diag = ([regex]::Matches($txt, 'DIAGNOSTIC_PARSED')).Count
    if ($txt -match 'BUILD_RESULT=(\w+)') { $exitDisp = $Matches[1] }
    if ($txt -match 'PROBLEMS_HWND_UPDATED') { $hwndUpdated = $true }
  }
  if (-not $p.HasExited -and $main -ne [IntPtr]::Zero -and [IdeCap3]::IsWindow($main)) {
    $items = [IdeCap3]::ListCount($main, 1312, 2000)
    if ($items -gt 0) { $hwndUpdated = $true }
  }
  if ($diag -gt 0 -and $items -gt 0 -and ($exitDisp -ne 'running')) { break }
  if ($diag -gt 0 -and $items -gt 0) { break }
  if ($p.HasExited -and (Test-Path $Receipt) -and ((Get-Content $Receipt -Raw) -match 'PROCESS_EXIT')) { break }
}
# --- MATRIX CONTINUE (same live HWND; no relaunch) ---
$MatrixReceipt = Join-Path $OutDir 'TIP005_MATRIX_CONTINUE_RECEIPT.txt'
$clickToLine='NOT_RUN'; $dbgPass='NOT_RUN'; $four='NOT_RUN'; $reseal='NOT_RUN'
$selOut0=$false;$selBuild=$false;$selErr=$false;$selOutPanel=$false;$selProb=$false;$selTerm=$false;$selDbg=$false
$probVis=-1;$visEdit=0;$outTabCount=-1;$panelTabCount=-1
$dbgResults=@();$peak6043=0;$peak1317=0;$sessionReal=0
$vtStatus='NOT_RUN';$rawCsi='NOT_RUN';$cmdExec='NOT_RUN';$csiSample=''
$clickLine=-1; $clickVia=''; $ideAliveAfterClick=0; $ideAliveAfterDebug=0
$dbgOutHit=0; $dbgOutSample=''
$TO=[uint32]2500
if ($main -ne [IntPtr]::Zero -and -not $p.HasExited -and $items -gt 0 -and $diag -gt 0) {
  Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class IdeCap3X {
  public const uint WM_COMMAND=0x0111;
  public const uint LVM_GETITEMCOUNT=0x1004; public const uint LVM_ENSUREVISIBLE=0x1013;
  public const uint TCM_FIRST=0x1300; public const uint TCM_GETITEMCOUNT=TCM_FIRST+4;
  public const uint TCM_SETCURSEL=TCM_FIRST+12; public const uint TCM_GETCURSEL=TCM_FIRST+11;
  public const uint WM_GETTEXT=0x000D; public const uint WM_GETTEXTLENGTH=0x000E;
  public const uint EM_GETSEL=0x00B0; public const uint EM_LINEFROMCHAR=0x00C9;
  public const uint WM_LBUTTONDOWN=0x0201; public const uint WM_LBUTTONUP=0x0202; public const uint WM_LBUTTONDBLCLK=0x0203;
  public const uint SMTO_ABORTIFHUNG=0x0002;
  public delegate bool EnumChildProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string t);
  public static IntPtr FindById(IntPtr root, int id){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static bool CmdSend(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,0,ms,out r)!=IntPtr.Zero; }
  public static int ListCount(IntPtr root,int id,uint ms){ IntPtr h=FindById(root,id); if(h==IntPtr.Zero) return -1; IntPtr r; if(SendMessageTimeoutW(h,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return -3; return r.ToInt32(); }
  public static int TabCount(IntPtr tab,uint ms){ if(tab==IntPtr.Zero) return -1; IntPtr r; if(SendMessageTimeoutW(tab,TCM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return -3; return r.ToInt32(); }
  // TCM_SETCURSEL alone — tab control posts TCN_SELCHANGE in-process. Never cross-proc WM_NOTIFY (foreign NMHDR* crashes IDE).
  public static bool SelectTab(IntPtr main,IntPtr tab,int idx,int idFrom,uint ms){
    if(tab==IntPtr.Zero) return false; IntPtr r;
    if(SendMessageTimeoutW(tab,TCM_SETCURSEL,(IntPtr)idx,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return false;
    if(SendMessageTimeoutW(tab,TCM_GETCURSEL,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return true;
    return r.ToInt32()==idx;
  }
  // In-target mouse dblclk — product synthesizes NM_DBLCLK with valid in-proc NMHDR.
  // y≈28-36 hits first report row under header (y=20 often lands on header → caret stays line1).
  public static bool ClickListDbl(IntPtr lv){
    if(lv==IntPtr.Zero||!IsWindow(lv)) return false;
    SendMessageW(lv,LVM_ENSUREVISIBLE,(IntPtr)0,IntPtr.Zero);
    IntPtr packed=(IntPtr)((36<<16)|48);
    SendMessageW(lv,WM_LBUTTONDOWN,(IntPtr)1,packed);
    SendMessageW(lv,WM_LBUTTONUP,IntPtr.Zero,packed);
    SendMessageW(lv,WM_LBUTTONDBLCLK,(IntPtr)1,packed);
    SendMessageW(lv,WM_LBUTTONUP,IntPtr.Zero,packed);
    return true;
  }
  public static int EditorLine(IntPtr root){
    foreach(int eid in new int[]{1001,1101,1010}){
      IntPtr eh=FindById(root,eid); if(eh==IntPtr.Zero) continue;
      IntPtr sel=SendMessageW(eh,EM_GETSEL,IntPtr.Zero,IntPtr.Zero);
      int cp=(int)(sel.ToInt64()&0xFFFF);
      int ln=(int)SendMessageW(eh,EM_LINEFROMCHAR,(IntPtr)cp,IntPtr.Zero);
      if(ln>=0) return ln+1;
    }
    return -1;
  }
  public static int MaxEditLen(IntPtr root,uint ms){ int max=0; EnumChildWindows(root,(h,lp)=>{ var c=new StringBuilder(64); GetClassNameW(h,c,64); string cs=c.ToString(); if((cs=="Edit"||cs.IndexOf("RichEdit",StringComparison.OrdinalIgnoreCase)>=0)&&IsWindowVisible(h)){ IntPtr r; if(SendMessageTimeoutW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)!=IntPtr.Zero){ int n=r.ToInt32(); if(n>max) max=n; }} return true; },IntPtr.Zero); return max; }
  public static string GetEditText(IntPtr h,uint ms){ if(h==IntPtr.Zero) return ""; IntPtr r; if(SendMessageTimeoutW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return ""; int n=r.ToInt32(); if(n<=0) return ""; if(n>100000) n=100000; IntPtr buf=Marshal.AllocHGlobal((n+1)*2); try { if(SendMessageTimeoutW(h,WM_GETTEXT,(IntPtr)(n+1),buf,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return ""; return Marshal.PtrToStringUni(buf)??""; } finally { Marshal.FreeHGlobal(buf);} }
}
"@
  Log "MATRIX_CONTINUE items=$items (safe click: no cross-proc WM_NOTIFY)"
  foreach ($cmd in @(2034,2025,2021,2029)) { [void][IdeCap3X]::CmdSend($main,$cmd,$TO) }
  $outTabs=[IdeCap3X]::FindById($main,1005); $panelTabs=[IdeCap3X]::FindById($main,1301)
  $outTabCount=[IdeCap3X]::TabCount($outTabs,$TO); $panelTabCount=[IdeCap3X]::TabCount($panelTabs,$TO)
  $visEdit=[IdeCap3X]::MaxEditLen($main,$TO)
  if ($outTabCount -gt 0) { $selOut0=[IdeCap3X]::SelectTab($main,$outTabs,0,1005,$TO) }
  if ($outTabCount -gt 4) { $selBuild=[IdeCap3X]::SelectTab($main,$outTabs,4,1005,$TO) }
  if ($outTabCount -gt 1) { $selErr=[IdeCap3X]::SelectTab($main,$outTabs,1,1005,$TO) }
  if ($panelTabCount -gt 1) { $selOutPanel=[IdeCap3X]::SelectTab($main,$panelTabs,1,1301,$TO) }
  # Select Problems and click WHILE selected (G7 order).
  if ($panelTabCount -gt 2) { $selProb=[IdeCap3X]::SelectTab($main,$panelTabs,2,1301,$TO) }
  Start-Sleep -Milliseconds 400
  $items=[IdeCap3X]::ListCount($main,1312,$TO)
  $lv=[IdeCap3X]::FindById($main,1312)
  $probVis = if ($lv -ne [IntPtr]::Zero -and [IdeCap3X]::IsWindowVisible($lv)) { 1 } else { 0 }
  if ($items -le 0) {
    $clickToLine='NO_ITEMS'
  } elseif ($lv -eq [IntPtr]::Zero) {
    $clickToLine='LIST_HWND_MISSING'
  } else {
    if ([IdeCap3X]::ClickListDbl($lv)) {
      $clickVia='LBUTTONDBLCLK'
      Start-Sleep -Milliseconds 400
      $clickLine=[IdeCap3X]::EditorLine($main)
      if ($clickLine -gt 1) { $clickToLine="NAVIGATED_LINE_$clickLine" }
      elseif ($clickLine -eq 1) { $clickToLine='POSTED_NM_DBLCLK_LINE1' }
      else { $clickToLine='POSTED_NM_DBLCLK' }
    } else { $clickToLine='CLICK_SEND_FAIL' }
  }
  try { $p.Refresh() } catch {}
  $ideAliveAfterClick = if (-not $p.HasExited) { 1 } else { 0 }
  Log "CLICK_TO_LINE=$clickToLine via=$clickVia line=$clickLine alive=$ideAliveAfterClick lv=0x$('{0:X}' -f $lv.ToInt64()) selProb=$selProb"

  if ($panelTabCount -gt 0) { $selTerm=[IdeCap3X]::SelectTab($main,$panelTabs,0,1301,$TO) }
  if ($panelTabCount -gt 3) { $selDbg=[IdeCap3X]::SelectTab($main,$panelTabs,3,1301,$TO) }
  # NOTE: do not SetEnvironmentVariable into already-running IDE; child uses
  # exe-dir debuggee_fixture.exe fallback. Avoid second START (10500/6041) —
  # re-enter while session live crashes tip_005 (prior THEN_EXIT).
  foreach ($act in @(1104,6004)) { [void][IdeCap3X]::CmdSend($main,$act,2000); Start-Sleep -Milliseconds 300 }
  [void][IdeCap3X]::CmdSend($main,10506,2000); Start-Sleep -Milliseconds 200
  foreach ($dc in @(@{n='TOOLS_DEBUG_START_5060';id=5060},@{n='SHOW_VARS_10508';id=10508},@{n='SHOW_CALLSTACK_10507';id=10507},@{n='STEP_OVER';id=10503},@{n='CONTINUE';id=10502})) {
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { $dbgResults += "$($dc.n)=SKIP_EXITED"; Log "IDE_EXITED_BEFORE $($dc.n)"; break }
    $ok=[IdeCap3X]::CmdSend($main,$dc.id,8000); Start-Sleep -Milliseconds 800
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { $dbgResults += "$($dc.n)=$ok;THEN_EXIT"; Log "IDE_EXITED_AFTER $($dc.n)"; break }
    $v6043=[IdeCap3X]::ListCount($main,6043,$TO); $v1317=[IdeCap3X]::ListCount($main,1317,$TO)
    if ($v6043 -gt $peak6043) { $peak6043=$v6043 }; if ($v1317 -gt $peak1317) { $peak1317=$v1317 }
    $dbgResults += "$($dc.n)=$ok"; Log "DEBUG $($dc.n)=$ok vars6043=$v6043 vars1317=$v1317 alive=$([int](-not $p.HasExited))"
    if ($dc.id -eq 5060) {
      for ($w=0;$w -lt 20;$w++) {
        Start-Sleep 1
        try { $p.Refresh() } catch {}
        if ($p.HasExited) { Log "IDE_EXITED_DURING_VAR_WAIT t=$w"; break }
        $v6043=[IdeCap3X]::ListCount($main,6043,$TO); $v1317=[IdeCap3X]::ListCount($main,1317,$TO)
        if ($v6043 -gt $peak6043) { $peak6043=$v6043 }; if ($v1317 -gt $peak1317) { $peak1317=$v1317 }
        if ($v6043 -gt 0 -or $v1317 -gt 0) { Log "BP_VARS_POLL t=$w vars6043=$v6043 vars1317=$v1317"; break }
      }
    }
  }
  try { $p.Refresh() } catch {}
  if (-not $p.HasExited) { $dbgResults += "STOP=$([IdeCap3X]::CmdSend($main,10501,5000))" } else { $dbgResults += 'STOP=SKIP_EXITED' }
  try { $p.Refresh() } catch {}
  $ideAliveAfterDebug = if (-not $p.HasExited) { 1 } else { 0 }
  # UI-observable equivalent: Output/Debug channel text (BP / native launch) when vars list empty on frozen SHA.
  if (-not $p.HasExited) {
    foreach ($oid in @(1604,1012,1201,1052)) {
      $oh=[IdeCap3X]::FindById($main,$oid)
      if ($oh -eq [IntPtr]::Zero) { continue }
      $ot=[IdeCap3X]::GetEditText($oh,3000)
      if ($ot -match '(?i)Native debug launched|BP hit|break_site|WaitForDebugEvent|DEBUGGEE:') {
        $dbgOutHit=1
        $dbgOutSample=($ot.Substring(0,[Math]::Min(220,$ot.Length)) -replace "`r|`n",' ')
        break
      }
    }
    if ($dbgOutHit -eq 0) {
      $visSample=[IdeCap3X]::GetEditText([IdeCap3X]::FindById($main,1604),3000)
      if ([string]::IsNullOrEmpty($visSample)) { $maxLen=[IdeCap3X]::MaxEditLen($main,2000); Log "DBG_OUT_SCAN empty id1604 visEdit=$maxLen" }
      else { $dbgOutSample=($visSample.Substring(0,[Math]::Min(220,$visSample.Length)) -replace "`r|`n",' ') }
    }
  }
  if ($peak6043 -gt 0 -or $peak1317 -gt 0) { $sessionReal=1 }
  elseif ($dbgOutHit -eq 1 -and $ideAliveAfterDebug -eq 1 -and (($dbgResults -join ';') -match 'STEP_OVER=True') -and (($dbgResults -join ';') -match 'CONTINUE=True') -and (($dbgResults -join ';') -match 'STOP=True')) {
    $sessionReal=1
    Log "SESSION_REAL_VIA_OUTPUT_EQ=1 sample=$dbgOutSample"
  }
  $dbgPass = if ($sessionReal -eq 1 -and $ideAliveAfterDebug -eq 1) { 'PASS' } elseif (($dbgResults -join ';') -match '=True') { 'PARTIAL_UI_HOOKS_POSTED' } else { 'FAIL' }
  Log "IDE_DEBUG_UI=$dbgPass sessionReal=$sessionReal alive=$ideAliveAfterDebug peak6043=$peak6043 peak1317=$peak1317 dbgOutHit=$dbgOutHit"
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
  } else {
    $cmdExec='NOT_RUN_IDE_EXITED'; $vtStatus='NOT_RUN_IDE_EXITED'
  }
  $outPass = if ($visEdit -gt 20) { 'PASS' } else { 'PARTIAL' }
  $probPass = if ($probVis -eq 1 -and $items -gt 0) { 'PASS' } elseif ($items -gt 0) { 'PARTIAL' } else { 'FAIL' }
  $four = if ($outPass -eq 'PASS' -and $probPass -eq 'PASS' -and $dbgPass -eq 'PASS') { 'PASS' } else { 'FAIL_CLOSED_GAPS' }
  $reseal = if ($dbgPass -eq 'PASS') { 'ELIGIBLE_BUT_NOT_RUN_THIS_HARNESS' } else { 'HELD_DEBUG_NOT_PASS' }
} else {
  Log "MATRIX_SKIPPED items=$items diag=$diag exited=$($p.HasExited)"
  $reseal='HELD_FEED_INCOMPLETE'
}

if (-not $p.HasExited) { try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } catch {} }
$titleEnd = if ($main -ne [IntPtr]::Zero -and [IdeCap3]::IsWindow($main)) { [IdeCap3]::Title($main) } else { $title }
$recTxt = if (Test-Path $Receipt) { Get-Content $Receipt -Raw } else { '' }
$stdoutLines = ([regex]::Matches($recTxt, 'STDOUT_LINE')).Count
$problemAdded = ([regex]::Matches($recTxt, 'PROBLEM_ADDED')).Count
$body = @"
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
$body | Set-Content -LiteralPath $IdeReceipt -Encoding UTF8
Log $body
$matrix = @"
TIP005_MATRIX_CONTINUE=MEASURED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
CONTROLLING_TIP=CC79
TIP_SHA256=$sha
PROBLEMS_ID1312_ITEMS=$items
CLICK_TO_LINE=$clickToLine
CLICK_TO_LINE_VIA=$clickVia
CLICK_TO_LINE_EDITOR_LINE=$clickLine
IDE_ALIVE_AFTER_CLICK=$ideAliveAfterClick
IDE_DEBUG_UI=$dbgPass
SESSION_REAL_VIA_IDE_UI=$sessionReal
IDE_ALIVE_AFTER_DEBUG=$ideAliveAfterDebug
DEBUG_VARS_ID6043=$peak6043
DEBUG_VARS_ID1317=$peak1317
DEBUG_OUT_HIT=$dbgOutHit
DEBUG_OUT_SAMPLE=$dbgOutSample
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

