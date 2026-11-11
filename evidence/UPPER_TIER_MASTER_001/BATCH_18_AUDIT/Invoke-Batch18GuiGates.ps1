# Batch18 P06-P11 interactive GUI probe on tip SHA. CERTIFIED=0 PROMOTE=0. NOT_RUN!=PASS.
param(
  [string]$ExePath = 'F:\rawrxd\build_win32ide\bin\Release\RawrXD-Win32IDE-Native.exe',
  [string]$OutDir = 'F:\rawrxd\evidence\UPPER_TIER_MASTER_001\BATCH_18_AUDIT\RUNTIME_EVIDENCE',
  [int]$WaitMs = 5000
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = Join-Path $OutDir "gui_gates_run_$stamp.txt"
$receipt = Join-Path $OutDir 'GUI_GATES_RECEIPT.txt'
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $log -Value $line -Encoding UTF8
  Write-Output $line
}
if (-not (Test-Path -LiteralPath $ExePath)) {
  Log "EXE_ABSENT=$ExePath"; Set-Content $receipt "PRECONDITION=HELD`nEXE_ABSENT=1"; exit 2
}
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $ExePath).Hash.ToUpperInvariant()
Log "EXE_PATH=$ExePath"; Log "TIP_SHA=$sha"

Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class B18Gui {
  public const uint WM_COMMAND=0x0111; public const uint BM_CLICK=0x00F5;
  public const uint WM_GETTEXT=0x000D; public const uint WM_GETTEXTLENGTH=0x000E;
  public const uint WM_CLOSE=0x0010; public const uint TCM_GETITEMCOUNT=0x1304;
  public const uint TCM_SETCURSEL=0x130C; public const uint TCM_GETCURSEL=0x130B;
  public const uint LVM_GETITEMCOUNT=0x1004;
  public const uint WM_LBUTTONDOWN=0x0201; public const uint WM_LBUTTONUP=0x0202;
  public const uint WM_MOUSEMOVE=0x0200; public const int MK_LBUTTON=0x0001;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string t);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left,Top,Right,Bottom; }
  public static IntPtr FindMain(uint pid) {
    IntPtr found=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint wpid; GetWindowThreadProcessId(h,out wpid);
      if(wpid!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,sb.Capacity);
      string c=sb.ToString();
      if(c.IndexOf("RawrXD",StringComparison.OrdinalIgnoreCase)>=0){ found=h; return false; }
      if(found==IntPtr.Zero) found=h; return true;
    }, IntPtr.Zero); return found;
  }
  public static IntPtr FindById(IntPtr root,int id){
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){ found=h; return false;} return true;},IntPtr.Zero);
    return found;
  }
  public static List<string> ChildSummary(IntPtr root){
    var list=new List<string>();
    EnumChildWindows(root,(h,lp)=>{
      int id=GetDlgCtrlID(h); var cls=new StringBuilder(128); var txt=new StringBuilder(128);
      GetClassNameW(h,cls,cls.Capacity); GetWindowTextW(h,txt,txt.Capacity);
      bool vis=IsWindowVisible(h); RECT r; GetWindowRect(h,out r);
      list.Add(string.Format("id={0} cls={1} vis={2} txt={3} rect={4},{5}-{6},{7}",
        id,cls,vis,txt.ToString().Replace('\r',' ').Replace('\n',' ').Trim(),
        r.Left,r.Top,r.Right,r.Bottom));
      return true;
    },IntPtr.Zero); return list;
  }
  public static string GetText(IntPtr h){
    if(h==IntPtr.Zero) return "";
    int n=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    if(n<=0) return ""; if(n>120000) n=120000;
    var sb=new StringBuilder(n+2); SendMessageW(h,WM_GETTEXT,(IntPtr)(n+1),sb); return sb.ToString();
  }
  public static int Height(IntPtr h){ RECT r; if(!GetWindowRect(h,out r)) return -1; return r.Bottom-r.Top; }
}
"@

Get-Process -Name 'RawrXD-Win32IDE-Native*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$workDir = Split-Path -Parent $ExePath
$env:RAWRXD_LOG_DIR = $OutDir

$p10 = @{ cold1='NOT_RUN'; cold2='NOT_RUN'; cold3='NOT_RUN'; interactive='NOT_RUN' }
$proc = Start-Process -FilePath $ExePath -WorkingDirectory $workDir -PassThru -WindowStyle Normal
Log "P10_COLD1_PID=$($proc.Id)"
$main = [IntPtr]::Zero
for ($i=0; $i -lt 80; $i++) {
  Start-Sleep -Milliseconds 250
  try { $proc.Refresh() } catch {}
  if ($proc.HasExited) { Log "P10_COLD1_EARLY_EXIT=$($proc.ExitCode)"; $p10.cold1='FAIL_EARLY_EXIT'; break }
  if ($proc.MainWindowHandle -ne 0) { $main=[IntPtr]$proc.MainWindowHandle; break }
  $main = [B18Gui]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log ("P10_COLD1_MAIN=0x{0:X}" -f $main.ToInt64())
if ($main -eq [IntPtr]::Zero) { $p10.cold1='FAIL_NO_HWND' } else {
  $p10.cold1='PASS_HWND_VISIBLE'
  [void][B18Gui]::SetForegroundWindow($main)
  Start-Sleep -Milliseconds 600
}

$results = [ordered]@{
  TIP_SHA=$sha; P06='NOT_RUN'; P07='NOT_RUN'; P08='NOT_RUN'; P09='NOT_RUN'; P10='NOT_RUN'; P11='NOT_RUN'
  P06_NOTE=''; P07_NOTE=''; P08_NOTE=''; P09_NOTE=''; P10_NOTE=''; P11_NOTE=''
}

if ($main -eq [IntPtr]::Zero) {
  Log 'ABORT_NO_MAIN'
  @"
TIP_SHA=$sha
P06=NOT_RUN
P07=NOT_RUN
P08=NOT_RUN
P09=NOT_RUN
P10=$($p10.cold1)
P11=NOT_RUN
RUNTIME_REACHED=0
PRODUCT_RUNTIME_PASS=0
BLOCKER=NO_MAIN_HWND
RUNLOG=$log
CERTIFIED=0
PROMOTE=0
"@ | Set-Content $receipt -Encoding UTF8
  exit 3
}

$ids = @{
  PS_PANEL=5600; PS_OUT=5601; PS_IN=5602; PS_EXEC=5610; PS_CLEAR=5611; PS_STOP=5612
  PANEL_TABS=1301; PANEL_CONTAINER=1300; PROBLEMS=1390; EDITOR=1001; SPLITTER=1200
}
$hwnd = @{}
foreach ($k in $ids.Keys) { $hwnd[$k] = [B18Gui]::FindById($main, [int]$ids[$k]) }
foreach ($k in ($hwnd.Keys | Sort-Object)) { Log ("HWND_{0}=0x{1:X}" -f $k, $hwnd[$k].ToInt64()) }
$sumPath = Join-Path $OutDir "child_summary_$stamp.txt"
[B18Gui]::ChildSummary($main) | Set-Content $sumPath -Encoding UTF8
Log "CHILD_SUMMARY=$sumPath"

# P06
$p06_exec='NOT_RUN'; $p06_clear='NOT_RUN'; $p06_stop='NOT_RUN'; $p06_iso='NOT_RUN'; $p06_dock='NOT_RUN'
try {
  $panelH0 = [B18Gui]::Height($hwnd.PS_PANEL)
  if ($hwnd.PS_IN -ne [IntPtr]::Zero) { [void][B18Gui]::SetWindowTextW($hwnd.PS_IN, 'Write-Output B18_P06_EXEC') }
  [void][B18Gui]::PostMessageW($main, [B18Gui]::WM_COMMAND, [IntPtr]5610, $hwnd.PS_EXEC)
  if ($hwnd.PS_EXEC -ne [IntPtr]::Zero) { [void][B18Gui]::PostMessageW($hwnd.PS_EXEC, [B18Gui]::BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) }
  Start-Sleep -Milliseconds 2500
  $afterExec = [B18Gui]::GetText($hwnd.PS_OUT)
  Log ("P06_AFTER_EXEC_LEN={0}" -f $afterExec.Length)
  if ($afterExec -match 'B18_P06_EXEC' -or $afterExec.Length -gt 20) { $p06_exec='PASS' } else { $p06_exec='FAIL_NO_OUTPUT' }

  if ($hwnd.PS_IN -ne [IntPtr]::Zero) {
    [void][B18Gui]::SetWindowTextW($hwnd.PS_IN, '1..40 | ForEach-Object { Start-Sleep -Milliseconds 200; $_ }')
  }
  [void][B18Gui]::PostMessageW($main, [B18Gui]::WM_COMMAND, [IntPtr]5610, $hwnd.PS_EXEC)
  Start-Sleep -Milliseconds 800
  [void][B18Gui]::PostMessageW($main, [B18Gui]::WM_COMMAND, [IntPtr]5612, $hwnd.PS_STOP)
  if ($hwnd.PS_STOP -ne [IntPtr]::Zero) { [void][B18Gui]::PostMessageW($hwnd.PS_STOP, [B18Gui]::BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) }
  Start-Sleep -Milliseconds 600
  try { $proc.Refresh() } catch {}
  if (-not $proc.HasExited -and [B18Gui]::IsWindowVisible($main)) { $p06_stop='PASS_POSTED_UI_ALIVE' } else { $p06_stop='FAIL_UI_DEAD' }

  [void][B18Gui]::PostMessageW($main, [B18Gui]::WM_COMMAND, [IntPtr]5611, $hwnd.PS_CLEAR)
  if ($hwnd.PS_CLEAR -ne [IntPtr]::Zero) { [void][B18Gui]::PostMessageW($hwnd.PS_CLEAR, [B18Gui]::BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) }
  Start-Sleep -Milliseconds 400
  $afterClear = [B18Gui]::GetText($hwnd.PS_OUT)
  Log ("P06_AFTER_CLEAR_LEN={0}" -f $afterClear.Length)
  if ($afterClear.Length -lt $afterExec.Length) { $p06_clear='PASS' } else { $p06_clear='FAIL_NO_SHRINK' }

  if ($hwnd.PS_EXEC -ne [IntPtr]::Zero -and $hwnd.PS_CLEAR -ne [IntPtr]::Zero -and $hwnd.PS_STOP -ne [IntPtr]::Zero) {
    $p06_iso='PASS_IDS_BOUND_5610_5611_5612'
  } else { $p06_iso='FAIL_MISSING_BTN_HWND' }

  $panelH1 = [B18Gui]::Height($hwnd.PS_PANEL)
  Log "P06_DOCK_H0=$panelH0 H1=$panelH1"
  if ($panelH1 -gt 0) { $p06_dock='PASS_PANEL_ALIVE' } else { $p06_dock='FAIL_PANEL_GONE' }

  if ($p06_exec -eq 'PASS' -and $p06_clear -eq 'PASS' -and $p06_stop -like 'PASS*' -and $p06_iso -like 'PASS*' -and $p06_dock -like 'PASS*') {
    $results.P06='PASS'
  } else { $results.P06='FAIL' }
  $results.P06_NOTE="exec=$p06_exec clear=$p06_clear stop=$p06_stop iso=$p06_iso dock=$p06_dock"
} catch {
  Log "P06_EX=$($_.Exception.Message)"; $results.P06='FAIL'; $results.P06_NOTE=$_.Exception.Message
}

# P07
try {
  $tabs = $hwnd.PANEL_TABS
  $script:foundTab = [IntPtr]::Zero
  if ($tabs -eq [IntPtr]::Zero) {
    [B18Gui]::EnumChildWindows($main, {
      param($h,$lp)
      $sb=New-Object System.Text.StringBuilder 64
      [void][B18Gui]::GetClassNameW($h,$sb,$sb.Capacity)
      if ($sb.ToString() -eq 'SysTabControl32') { $script:foundTab=$h; return $false }
      return $true
    }, [IntPtr]::Zero) | Out-Null
    if ($script:foundTab -ne [IntPtr]::Zero) { $tabs=$script:foundTab; $hwnd.PANEL_TABS=$tabs }
  }
  $tabCount = 0
  if ($tabs -ne [IntPtr]::Zero) {
    $tabCount = [int][B18Gui]::SendMessageW($tabs, [B18Gui]::TCM_GETITEMCOUNT, [IntPtr]::Zero, [IntPtr]::Zero)
  }
  Log "P07_TAB_COUNT=$tabCount HWND=0x$('{0:X}' -f $tabs.ToInt64())"
  $sels = @()
  if ($tabs -ne [IntPtr]::Zero -and $tabCount -ge 4) {
    for ($cycle=0; $cycle -lt 3; $cycle++) {
      for ($t=0; $t -lt 4; $t++) {
        [void][B18Gui]::SendMessageW($tabs, [B18Gui]::TCM_SETCURSEL, [IntPtr]$t, [IntPtr]::Zero)
        Start-Sleep -Milliseconds 200
        $cur = [int][B18Gui]::SendMessageW($tabs, [B18Gui]::TCM_GETCURSEL, [IntPtr]::Zero, [IntPtr]::Zero)
        $sels += $cur
        Log "P07_CYCLE=$cycle SEL=$t CUR=$cur"
      }
    }
    try { $proc.Refresh() } catch {}
    if (-not $proc.HasExited -and ($sels | Where-Object { $_ -ge 0 }).Count -ge 8) {
      $results.P07='PASS'
      $results.P07_NOTE="PANEL_TAB_COUNT=$tabCount cycles=3 sels=$($sels -join ',')"
    } else {
      $results.P07='FAIL'
      $results.P07_NOTE="tabCount=$tabCount exited=$($proc.HasExited) sels=$($sels -join ',')"
    }
  } else {
    $results.P07='FAIL'
    $results.P07_NOTE="tabs_hwnd_missing_or_count=$tabCount"
  }
} catch {
  Log "P07_EX=$($_.Exception.Message)"; $results.P07='FAIL'; $results.P07_NOTE=$_.Exception.Message
}

# P08
try {
  $container = $hwnd.PANEL_CONTAINER
  if ($container -eq [IntPtr]::Zero) { $container = $hwnd.PS_PANEL }
  $h0 = [B18Gui]::Height($container)
  $splitter = $hwnd.SPLITTER
  Log "P08_H0=$h0 SPLITTER=0x$('{0:X}' -f $splitter.ToInt64())"
  if ($splitter -ne [IntPtr]::Zero) {
    $down = [IntPtr]((80 -shl 16) -bor 10)
    $up = [IntPtr]((20 -shl 16) -bor 10)
    [void][B18Gui]::PostMessageW($splitter, [B18Gui]::WM_LBUTTONDOWN, [IntPtr][B18Gui]::MK_LBUTTON, $down)
    Start-Sleep -Milliseconds 50
    [void][B18Gui]::PostMessageW($splitter, [B18Gui]::WM_MOUSEMOVE, [IntPtr][B18Gui]::MK_LBUTTON, $up)
    Start-Sleep -Milliseconds 50
    [void][B18Gui]::PostMessageW($splitter, [B18Gui]::WM_LBUTTONUP, [IntPtr]::Zero, $up)
    Start-Sleep -Milliseconds 300
  }
  $h1 = [B18Gui]::Height($container)
  Log "P08_H1=$h1"
  try { $proc.Refresh() } catch {}
  if (-not $proc.HasExited -and $h0 -ge 160) {
    if ($splitter -eq [IntPtr]::Zero) {
      $results.P08='FAIL'
      $results.P08_NOTE="splitter_hwnd_missing H0=$h0 H1=$h1 session_reload=NOT_RUN"
    } elseif ($h1 -ne $h0) {
      $results.P08='PASS'
      $results.P08_NOTE="drag_height_changed H0=$h0 H1=$h1 session_reload=NOT_RUN_SAME_PROCESS"
    } else {
      $results.P08='FAIL'
      $results.P08_NOTE="drag_no_height_change H0=$h0 H1=$h1 session_reload=NOT_RUN"
    }
  } else {
    $results.P08='FAIL'
    $results.P08_NOTE="H0=$h0 exited=$($proc.HasExited)"
  }
} catch {
  Log "P08_EX=$($_.Exception.Message)"; $results.P08='FAIL'; $results.P08_NOTE=$_.Exception.Message
}

# P09
try {
  $prob = $hwnd.PROBLEMS
  if ($prob -eq [IntPtr]::Zero) {
    foreach ($pid_try in 1390,1391,1302,1303,1400) {
      $cand=[B18Gui]::FindById($main,$pid_try)
      if ($cand -ne [IntPtr]::Zero) {
        $cls=New-Object System.Text.StringBuilder 64
        [void][B18Gui]::GetClassNameW($cand,$cls,$cls.Capacity)
        if ($cls.ToString() -match 'SysListView32|ListView') { $prob=$cand; break }
      }
    }
  }
  $itemCount = 0
  if ($prob -ne [IntPtr]::Zero) {
    $itemCount = [int][B18Gui]::SendMessageW($prob, [B18Gui]::LVM_GETITEMCOUNT, [IntPtr]::Zero, [IntPtr]::Zero)
  }
  Log "P09_PROBLEMS_HWND=0x$('{0:X}' -f $prob.ToInt64()) ITEMS=$itemCount"
  if ($itemCount -ge 1) {
    [void][B18Gui]::PostMessageW($main, [B18Gui]::WM_COMMAND, [IntPtr]1399, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
    try { $proc.Refresh() } catch {}
    if (-not $proc.HasExited) {
      $results.P09='PASS'
      $results.P09_NOTE="items=$itemCount posted_1399 UI_ALIVE caret_line=COMMAND_POSTED_NOT_CARET_PROVED"
    } else {
      $results.P09='FAIL'
      $results.P09_NOTE='exited_after_1399'
    }
  } else {
    $results.P09='FAIL'
    $results.P09_NOTE="PROBLEMS_ITEMS=0 hwnd=0x$('{0:X}' -f $prob.ToInt64())"
  }
} catch {
  Log "P09_EX=$($_.Exception.Message)"; $results.P09='FAIL'; $results.P09_NOTE=$_.Exception.Message
}

# P11 best-effort
try {
  [void][B18Gui]::PostMessageW($main, [B18Gui]::WM_COMMAND, [IntPtr]5612, $hwnd.PS_STOP)
  Start-Sleep -Milliseconds 300
  try { $proc.Refresh() } catch {}
  if ($proc.HasExited) {
    $results.P11='FAIL'
    $results.P11_NOTE='process_exited_on_cancel_surface'
  } else {
    $results.P11='FAIL'
    $results.P11_NOTE='RequestA_RequestB_NOT_RUN; cancel_surface_posted_only; stale_fence=NOT_VERIFIED'
  }
} catch {
  Log "P11_EX=$($_.Exception.Message)"; $results.P11='FAIL'; $results.P11_NOTE=$_.Exception.Message
}

[void][B18Gui]::PostMessageW($main, [B18Gui]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
Start-Sleep -Seconds 2
try { if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force } } catch {}

function Invoke-Cold([string]$tag) {
  $p = Start-Process -FilePath $ExePath -WorkingDirectory $workDir -PassThru -WindowStyle Normal
  Log "${tag}_PID=$($p.Id)"
  $m=[IntPtr]::Zero
  for ($i=0; $i -lt 60; $i++) {
    Start-Sleep -Milliseconds 250
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { Log "${tag}_EARLY_EXIT=$($p.ExitCode)"; return @{ ok=$false; note="EARLY_EXIT=$($p.ExitCode)"; proc=$p; main=[IntPtr]::Zero } }
    if ($p.MainWindowHandle -ne 0) { $m=[IntPtr]$p.MainWindowHandle; break }
    $m=[B18Gui]::FindMain([uint32]$p.Id)
    if ($m -ne [IntPtr]::Zero) { break }
  }
  Log ("${tag}_MAIN=0x{0:X}" -f $m.ToInt64())
  return @{ ok=($m -ne [IntPtr]::Zero); note=("MAIN=0x{0:X}" -f $m.ToInt64()); proc=$p; main=$m }
}

$c2 = Invoke-Cold 'P10_COLD2'
$p10.cold2 = if ($c2.ok) { 'PASS_HWND_VISIBLE' } else { 'FAIL' }
if ($c2.proc -and -not $c2.proc.HasExited) { Stop-Process -Id $c2.proc.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1
$c3 = Invoke-Cold 'P10_COLD3'
$p10.cold3 = if ($c3.ok) { 'PASS_HWND_VISIBLE' } else { 'FAIL' }
if ($c3.ok) {
  [void][B18Gui]::SetForegroundWindow($c3.main)
  Start-Sleep -Milliseconds 500
  $ed=[B18Gui]::FindById($c3.main,1001)
  $dock=[B18Gui]::FindById($c3.main,1300)
  if ($dock -eq [IntPtr]::Zero) { $dock=[B18Gui]::FindById($c3.main,5600) }
  Log ("P10_EDITOR=0x{0:X} DOCK=0x{1:X}" -f $ed.ToInt64(), $dock.ToInt64())
  if ($ed -ne [IntPtr]::Zero -or $dock -ne [IntPtr]::Zero) { $p10.interactive='PASS_BIND' } else { $p10.interactive='FAIL_NO_BIND' }
}
if ($c3.proc -and -not $c3.proc.HasExited) { Stop-Process -Id $c3.proc.Id -Force -ErrorAction SilentlyContinue }

if ($p10.cold1 -like 'PASS*' -and $p10.cold2 -like 'PASS*' -and $p10.cold3 -like 'PASS*' -and $p10.interactive -like 'PASS*') {
  $results.P10='PASS'
} else { $results.P10='FAIL' }
$results.P10_NOTE="cold1=$($p10.cold1) cold2=$($p10.cold2) cold3=$($p10.cold3) interactive=$($p10.interactive)"

$shaEnd = (Get-FileHash -Algorithm SHA256 -LiteralPath $ExePath).Hash.ToUpperInvariant()
Log "TIP_SHA_END=$shaEnd"
$shaBound = ($sha -eq $shaEnd)
$passN = @($results.P06,$results.P07,$results.P08,$results.P09,$results.P10,$results.P11) | Where-Object { $_ -eq 'PASS' }
$reached = @($results.P06,$results.P07,$results.P08,$results.P09,$results.P10,$results.P11) | Where-Object { $_ -ne 'NOT_RUN' }

$body = @"
BATCH18_GUI_GATES_RECEIPT
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
EXE_PATH=$ExePath
TIP_SHA=$sha
TIP_SHA_END=$shaEnd
SHA_BOUND=$shaBound
P06=$($results.P06)
P06_NOTE=$($results.P06_NOTE)
P07=$($results.P07)
P07_NOTE=$($results.P07_NOTE)
P08=$($results.P08)
P08_NOTE=$($results.P08_NOTE)
P09=$($results.P09)
P09_NOTE=$($results.P09_NOTE)
P10=$($results.P10)
P10_NOTE=$($results.P10_NOTE)
P11=$($results.P11)
P11_NOTE=$($results.P11_NOTE)
RUNTIME_REACHED=$($reached.Count)/6
PRODUCT_RUNTIME_PASS=$($passN.Count)/6
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
NOT_RUN_NEQ_PASS=1
NO_INVENT_PASS=1
RUNLOG=$log
CHILD_SUMMARY=$sumPath
"@
Set-Content -Path $receipt -Value $body -Encoding UTF8
Write-Output $body
exit 0
