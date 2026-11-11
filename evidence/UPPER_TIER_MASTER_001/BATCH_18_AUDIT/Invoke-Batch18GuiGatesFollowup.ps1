# Batch18 follow-up: P07 HWND vis, P08 splitter 1016, P09 fixture+1312, P11 chat Send/Stop.
# CERTIFIED=0 PROMOTE=0. NOT_RUN!=PASS.
param(
  [string]$ExePath = 'F:\rawrxd\build_win32ide\bin\Release\RawrXD-Win32IDE-Native.exe',
  [string]$OutDir = 'F:\rawrxd\evidence\UPPER_TIER_MASTER_001\BATCH_18_AUDIT\RUNTIME_EVIDENCE',
  [string]$Fixture = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp',
  [string]$ExpectedTip = 'B53884F5E41530708054D4E110260D503AF8A27FDCF6BCF55324E15F687FA3A5'
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = Join-Path $OutDir "gui_followup_$stamp.txt"
$receipt = Join-Path $OutDir 'GUI_FOLLOWUP_RECEIPT.txt'
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $log -Value $line -Encoding UTF8
  Write-Output $line
}
if (-not (Test-Path -LiteralPath $ExePath)) { Log "EXE_ABSENT"; exit 2 }
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $ExePath).Hash.ToUpperInvariant()
Log "TIP_SHA=$sha EXPECTED=$ExpectedTip MATCH=$($sha -eq $ExpectedTip)"
if ($sha -ne $ExpectedTip) {
  Set-Content $receipt "P07=FAIL`nP07_NOTE=TIP_SHA_MISMATCH live=$sha expected=$ExpectedTip`nTIP_SHA=$sha`nCERTIFIED=0`nPROMOTE=0`nTIP_CLIMB=HOLD" -Encoding UTF8
  Log "TIP_SHA_MISMATCH abort"
  exit 4
}

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class B18F {
  public const uint WM_COMMAND=0x0111; public const uint WM_NOTIFY=0x004E;
  public const uint BM_CLICK=0x00F5; public const uint WM_SETTEXT=0x000C;
  public const uint WM_GETTEXT=0x000D; public const uint WM_GETTEXTLENGTH=0x000E;
  public const uint WM_CLOSE=0x0010; public const uint TCM_GETITEMCOUNT=0x1304;
  public const uint TCM_SETCURSEL=0x130C; public const uint TCM_GETCURSEL=0x130B;
  public const uint LVM_GETITEMCOUNT=0x1004; public const int TCN_SELCHANGE=-551;
  public const uint WM_LBUTTONDOWN=0x0201; public const uint WM_LBUTTONUP=0x0202;
  public const uint WM_MOUSEMOVE=0x0200; public const int MK_LBUTTON=0x0001;
  public const uint EM_GETSEL=0x00B0; public const uint EM_LINEFROMCHAR=0x00C9;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string t);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint x, uint y, uint d, UIntPtr e);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left,Top,Right,Bottom; }
  [StructLayout(LayoutKind.Sequential)] public struct NMHDR {
    public IntPtr hwndFrom; public IntPtr idFrom; public int code;
  }
  public static IntPtr FindMain(uint pid) {
    IntPtr found=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint wpid; GetWindowThreadProcessId(h,out wpid);
      if(wpid!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,sb.Capacity);
      if(sb.ToString().IndexOf("RawrXD",StringComparison.OrdinalIgnoreCase)>=0){ found=h; return false; }
      if(found==IntPtr.Zero) found=h; return true;
    }, IntPtr.Zero); return found;
  }
  public static IntPtr FindById(IntPtr root,int id){
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){ found=h; return false;} return true;},IntPtr.Zero);
    return found;
  }
  public static string GetText(IntPtr h){
    if(h==IntPtr.Zero) return "";
    int n=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    if(n<=0) return ""; if(n>80000) n=80000;
    var sb=new StringBuilder(n+2); SendMessageW(h,WM_GETTEXT,(IntPtr)(n+1),sb); return sb.ToString();
  }
  public static int Height(IntPtr h){ RECT r; if(!GetWindowRect(h,out r)) return -1; return r.Bottom-r.Top; }
  public static bool Vis(IntPtr h){ return h!=IntPtr.Zero && IsWindowVisible(h); }
  public static void NotifyTabSel(IntPtr main, IntPtr tabs, int id){
    // Allocate NMHDR in unmanaged memory for SendMessage lParam
    IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NMHDR)));
    try {
      NMHDR nm; nm.hwndFrom=tabs; nm.idFrom=(IntPtr)id; nm.code=TCN_SELCHANGE;
      Marshal.StructureToPtr(nm, p, false);
      SendMessageW(main, WM_NOTIFY, (IntPtr)id, p);
    } finally { Marshal.FreeHGlobal(p); }
  }
  public static void RealDragY(IntPtr splitter, int deltaY){
    RECT r; GetWindowRect(splitter, out r);
    int x = (r.Left + r.Right)/2; int y = (r.Top + r.Bottom)/2;
    SetCursorPos(x,y);
    mouse_event(0x0002,0,0,0,UIntPtr.Zero); // LEFTDOWN
    System.Threading.Thread.Sleep(40);
    SetCursorPos(x, y + deltaY);
    mouse_event(0x0001,0,0,0,UIntPtr.Zero); // MOVE
    System.Threading.Thread.Sleep(40);
    mouse_event(0x0004,0,0,0,UIntPtr.Zero); // LEFTUP
  }
}
"@

Get-Process -Name 'RawrXD-Win32IDE-Native*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$env:RAWRXD_PROBLEMS_FIXTURE = $Fixture
$env:RAWRXD_LOG_DIR = $OutDir
$workDir = Split-Path -Parent $ExePath
$proc = Start-Process -FilePath $ExePath -WorkingDirectory $workDir -PassThru -WindowStyle Normal
Log "PID=$($proc.Id) FIXTURE=$Fixture"
$main=[IntPtr]::Zero
for ($i=0; $i -lt 80; $i++) {
  Start-Sleep -Milliseconds 250
  try { $proc.Refresh() } catch {}
  if ($proc.HasExited) { Log "EARLY_EXIT=$($proc.ExitCode)"; break }
  if ($proc.MainWindowHandle -ne 0) { $main=[IntPtr]$proc.MainWindowHandle; break }
  $main=[B18F]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log ("MAIN=0x{0:X}" -f $main.ToInt64())
if ($main -eq [IntPtr]::Zero) { Set-Content $receipt "P07=NOT_RUN`nBLOCKER=NO_MAIN"; exit 3 }
[void][B18F]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 800

$h = @{
  tabs=[B18F]::FindById($main,1301)
  container=[B18F]::FindById($main,1300)
  terminal=[B18F]::FindById($main,1302)
  output=[B18F]::FindById($main,1303)
  problems=[B18F]::FindById($main,1312)
  debug=[B18F]::FindById($main,1305)
  splitter=[B18F]::FindById($main,1016)
  editor=[B18F]::FindById($main,1001)
  maximize=[B18F]::FindById($main,1310)
  chatIn=[B18F]::FindById($main,1202)
  chatSend=[B18F]::FindById($main,1204)
  chatStop=[B18F]::FindById($main,1210)
  psIn=[B18F]::FindById($main,5602)
  psOut=[B18F]::FindById($main,5601)
}
foreach ($k in ($h.Keys | Sort-Object)) { Log ("HWND_{0}=0x{1:X} vis={2}" -f $k, $h[$k].ToInt64(), [B18F]::Vis($h[$k])) }

# Force show dock
if ($h.container -ne [IntPtr]::Zero) { [void][B18F]::ShowWindow($h.container, 5) } # SW_SHOW
if ($h.tabs -ne [IntPtr]::Zero) { [void][B18F]::ShowWindow($h.tabs, 5) }
if ($h.maximize -ne [IntPtr]::Zero) {
  [void][B18F]::PostMessageW($main, [B18F]::WM_COMMAND, [IntPtr]1310, $h.maximize)
  [void][B18F]::PostMessageW($h.maximize, [B18F]::BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero)
}
Start-Sleep -Milliseconds 400
Log ("CONTAINER_VIS_AFTER_SHOW={0} H={1}" -f [B18F]::Vis($h.container), [B18F]::Height($h.container))

# --- P07 with real TCN_SELCHANGE + visibility ---
$p07='FAIL'; $p07note=''
$visMap = @()
if ($h.tabs -ne [IntPtr]::Zero) {
  $tabCount=[int][B18F]::SendMessageW($h.tabs,[B18F]::TCM_GETITEMCOUNT,[IntPtr]::Zero,[IntPtr]::Zero)
  Log "TAB_COUNT=$tabCount"
  for ($t=0; $t -lt 4; $t++) {
    [void][B18F]::SendMessageW($h.tabs,[B18F]::TCM_SETCURSEL,[IntPtr]$t,[IntPtr]::Zero)
    [B18F]::NotifyTabSel($main, $h.tabs, 1301)
    # Product also owns WM_COMMAND 1301 → switchPanelTab(GetCurSel)
    [void][B18F]::SendMessageW($main, [B18F]::WM_COMMAND, [IntPtr]1301, $h.tabs)
    Start-Sleep -Milliseconds 350
    # Re-resolve pane bodies after createPanel/ensurePanelTabBodies + switchPanelTab
    $h.terminal=[B18F]::FindById($main,1302)
    $h.output=[B18F]::FindById($main,1303)
    $h.problems=[B18F]::FindById($main,1312)
    $h.debug=[B18F]::FindById($main,1305)
    $tev=[B18F]::Vis($h.terminal); $ov=[B18F]::Vis($h.output)
    $pv=[B18F]::Vis($h.problems); $dv=[B18F]::Vis($h.debug)
    $cv=[B18F]::Vis($h.container); $tv=[B18F]::Vis($h.tabs)
    $cur=[int][B18F]::SendMessageW($h.tabs,[B18F]::TCM_GETCURSEL,[IntPtr]::Zero,[IntPtr]::Zero)
    $line=("tab=$t cur=$cur container=$cv tabs=$tv terminal=$tev(0x{0:X}) output=$ov(0x{1:X}) problems=$pv(0x{2:X}) debug=$dv(0x{3:X})" -f $h.terminal.ToInt64(),$h.output.ToInt64(),$h.problems.ToInt64(),$h.debug.ToInt64())
    $visMap += $line
    Log "P07_$line"
  }
  # cycle twice more quickly
  for ($c=0; $c -lt 2; $c++) {
    for ($t=0; $t -lt 4; $t++) {
      [void][B18F]::SendMessageW($h.tabs,[B18F]::TCM_SETCURSEL,[IntPtr]$t,[IntPtr]::Zero)
      [B18F]::NotifyTabSel($main, $h.tabs, 1301)
      Start-Sleep -Milliseconds 150
    }
  }
  try { $proc.Refresh() } catch {}
  $anyPaneVis = ($visMap | Where-Object { $_ -match 'terminal=True|output=True|problems=True|debug=True' }).Count -gt 0
  $allPresent = ($h.terminal -ne [IntPtr]::Zero -and $h.output -ne [IntPtr]::Zero -and $h.problems -ne [IntPtr]::Zero -and $h.debug -ne [IntPtr]::Zero)
  $containerShown = ($visMap | Where-Object { $_ -match 'container=True' }).Count -gt 0
  # Product P07 requires observed per-tab body visibility after real switch, not sel-only
  $tab0ok = ($visMap | Where-Object { $_ -match '^tab=0 ' -and $_ -match 'terminal=True' }).Count -gt 0
  $tab1ok = ($visMap | Where-Object { $_ -match '^tab=1 ' -and $_ -match 'output=True' }).Count -gt 0
  $tab2ok = ($visMap | Where-Object { $_ -match '^tab=2 ' -and $_ -match 'problems=True' }).Count -gt 0
  $tab3ok = ($visMap | Where-Object { $_ -match '^tab=3 ' -and $_ -match 'debug=True' }).Count -gt 0
  if (-not $proc.HasExited -and $tabCount -eq 4 -and $containerShown -and $allPresent -and $tab0ok -and $tab1ok -and $tab2ok -and $tab3ok) {
    $p07='PASS'
    $p07note="TAB_COUNT=4 notify_TCN_SELCHANGE panes_vis_observed bodies=1302/1303/1312/1305 cycles=3 maps=$($visMap -join ' | ')"
  } elseif (-not $proc.HasExited -and $tabCount -eq 4) {
    $p07='FAIL'
    $p07note="TAB_COUNT=4 sel_ok HWND_VIS allPresent=$allPresent anyPaneVis=$anyPaneVis t0=$tab0ok t1=$tab1ok t2=$tab2ok t3=$tab3ok containerShown=$containerShown maps=$($visMap -join ' | ')"
  } else {
    $p07='FAIL'
    $p07note="tabCount=$tabCount exited=$($proc.HasExited)"
  }
} else { $p07note='tabs_missing' }

# --- P08 real splitter drag + maximize/restore + session note ---
$p08='FAIL'; $p08note=''
$h0=[B18F]::Height($h.container)
if ($h0 -lt 0) { $h0=[B18F]::Height($h.splitter) }
Log "P08_H0_CONTAINER=$h0 SPLITTER_H=$([B18F]::Height($h.splitter))"
if ($h.splitter -ne [IntPtr]::Zero) {
  [void][B18F]::SetForegroundWindow($main)
  Start-Sleep -Milliseconds 200
  # If dock already at clamp (420), drag DOWN first so UP can prove delta.
  if ($h0 -ge 400) {
    [B18F]::RealDragY($h.splitter, 100)
    Start-Sleep -Milliseconds 400
    $h0=[B18F]::Height($h.container)
    Log "P08_H0_AFTER_SHRINK=$h0"
  }
  [B18F]::RealDragY($h.splitter, -80)
  Start-Sleep -Milliseconds 400
  $h1=[B18F]::Height($h.container)
  Log "P08_H1_AFTER_DRAG_UP=$h1"
  [B18F]::RealDragY($h.splitter, 40)
  Start-Sleep -Milliseconds 300
  $h2=[B18F]::Height($h.container)
  Log "P08_H2_AFTER_DRAG_DOWN=$h2"
  # maximize / restore via 1310
  if ($h.maximize -ne [IntPtr]::Zero) {
    [void][B18F]::PostMessageW($main,[B18F]::WM_COMMAND,[IntPtr]1310,$h.maximize)
    Start-Sleep -Milliseconds 300
    $hMax=[B18F]::Height($h.container)
    [void][B18F]::PostMessageW($main,[B18F]::WM_COMMAND,[IntPtr]1310,$h.maximize)
    Start-Sleep -Milliseconds 300
    $hRest=[B18F]::Height($h.container)
    Log "P08_HMAX=$hMax HREST=$hRest"
  } else { $hMax=-1; $hRest=-1 }
  try { $proc.Refresh() } catch {}
  if (-not $proc.HasExited -and (($h1 -ne $h0) -or ($h2 -ne $h1) -or ($hMax -gt 0 -and $hMax -ne $h0))) {
    # Session reload still required for full checklist P08.4-5
    $p08='FAIL'
    $p08note="drag_or_max_observed H0=$h0 H1=$h1 H2=$h2 HMax=$hMax HRest=$hRest session_reload=NOT_RUN (required for PASS)"
  } else {
    $p08='FAIL'
    $p08note="no_height_change H0=$h0 H1=$h1 H2=$h2 session_reload=NOT_RUN"
  }
} else { $p08note='splitter_1016_missing' }

# --- P09: IDM_TOOLS_BUILD_PROJECT=3014 runs RAWRXD_PROBLEMS_FIXTURE → ingest → 1312 ---
$p09='FAIL'; $p09note=''
$buildIds = @(3014,40001,40002,40010,40100,41001,5001,5002,2001,2002,1701,1702)
# Prefer sole Tools Build (fixture compile); avoid blasting every ID first.
[void][B18F]::PostMessageW($main,[B18F]::WM_COMMAND,[IntPtr]3014,[IntPtr]::Zero)
if ($h.tabs -ne [IntPtr]::Zero) {
  [void][B18F]::SendMessageW($h.tabs,[B18F]::TCM_SETCURSEL,[IntPtr]2,[IntPtr]::Zero)
  [B18F]::NotifyTabSel($main, $h.tabs, 1301)
}
$items=0
$h.problems=[IntPtr]::Zero
for ($w=0; $w -lt 24; $w++) {
  Start-Sleep -Milliseconds 500
  try { $proc.Refresh() } catch {}
  if ($proc.HasExited) { Log "P09_EXIT_DURING_WAIT"; break }
  $h.problems=[B18F]::FindById($main,1312)
  if ($h.problems -ne [IntPtr]::Zero) {
    $items=[int][B18F]::SendMessageW($h.problems,[B18F]::LVM_GETITEMCOUNT,[IntPtr]::Zero,[IntPtr]::Zero)
  }
  if ($items -ge 1) { break }
  if ($w -eq 8) {
    foreach ($bid in $buildIds) {
      [void][B18F]::PostMessageW($main,[B18F]::WM_COMMAND,[IntPtr]$bid,[IntPtr]::Zero)
    }
  }
}
Log "P09_ITEMS=$items vis=$([B18F]::Vis($h.problems))"
if ($items -ge 1) {
  [void][B18F]::PostMessageW($main,[B18F]::WM_COMMAND,[IntPtr]1399,[IntPtr]::Zero)
  Start-Sleep -Milliseconds 500
  $sel=[B18F]::SendMessageW($h.editor,[B18F]::EM_GETSEL,[IntPtr]::Zero,[IntPtr]::Zero)
  $line=[int][B18F]::SendMessageW($h.editor,[B18F]::EM_LINEFROMCHAR,[IntPtr]($sel.ToInt64() -band 0xFFFF),[IntPtr]::Zero)
  Log "P09_CARET_LINE=$line SEL=$sel"
  try { $proc.Refresh() } catch {}
  if (-not $proc.HasExited) {
    $p09='PASS'
    $p09note="items=$items posted_1399 caret_line=$line"
  } else { $p09note='exited_after_navigate' }
} else {
  $p09note="PROBLEMS_ITEMS=0 fixture=$Fixture (Build/populate not reached on tip)"
}

# --- P11 chat Request A Stop Request B ---
$p11='FAIL'; $p11note=''
try { $proc.Refresh() } catch {}
if (-not $proc.HasExited -and $h.chatIn -ne [IntPtr]::Zero -and $h.chatSend -ne [IntPtr]::Zero) {
  [void][B18F]::SetWindowTextW($h.chatIn, 'B18_P11_REQUEST_A ping')
  [void][B18F]::PostMessageW($main,[B18F]::WM_COMMAND,[IntPtr]1204,$h.chatSend)
  if ($h.chatSend -ne [IntPtr]::Zero) { [void][B18F]::PostMessageW($h.chatSend,[B18F]::BM_CLICK,[IntPtr]::Zero,[IntPtr]::Zero) }
  Start-Sleep -Milliseconds 800
  if ($h.chatStop -ne [IntPtr]::Zero) {
    [void][B18F]::PostMessageW($main,[B18F]::WM_COMMAND,[IntPtr]1210,$h.chatStop)
    [void][B18F]::PostMessageW($h.chatStop,[B18F]::BM_CLICK,[IntPtr]::Zero,[IntPtr]::Zero)
  }
  Start-Sleep -Milliseconds 600
  try { $proc.Refresh() } catch {}
  if ($proc.HasExited) {
    $p11='FAIL'; $p11note='CRASH_ON_CANCEL'
  } else {
    [void][B18F]::SetWindowTextW($h.chatIn, 'B18_P11_REQUEST_B recover')
    [void][B18F]::PostMessageW($main,[B18F]::WM_COMMAND,[IntPtr]1204,$h.chatSend)
    [void][B18F]::PostMessageW($h.chatSend,[B18F]::BM_CLICK,[IntPtr]::Zero,[IntPtr]::Zero)
    Start-Sleep -Milliseconds 1200
    try { $proc.Refresh() } catch {}
    if ($proc.HasExited) {
      $p11='FAIL'; $p11note='CRASH_ON_REQUEST_B'
    } else {
      # Without inference backend proof of completion/stale fence, cannot PASS
      $p11='FAIL'
      $p11note='UI_ALIVE_AFTER_A_STOP_B but inference_completion_and_stale_fence=NOT_VERIFIED (no token/response proof)'
    }
  }
} else {
  $p11note="chat_controls_missing exited=$($proc.HasExited)"
}

# Session reload attempt for P08 (save distinctive height then relaunch)
$sessionReload='NOT_RUN'
if (-not $proc.HasExited -and $h.splitter -ne [IntPtr]::Zero) {
  [B18F]::RealDragY($h.splitter, -120)
  Start-Sleep -Milliseconds 300
  $hSave=[B18F]::Height($h.container)
  Log "P08_HSAVE=$hSave"
  [void][B18F]::PostMessageW($main,[B18F]::WM_CLOSE,[IntPtr]::Zero,[IntPtr]::Zero)
  Start-Sleep -Seconds 2
  try { if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force } } catch {}
  Start-Sleep -Seconds 1
  # clear fixture for clean relaunch measure
  $proc2 = Start-Process -FilePath $ExePath -WorkingDirectory $workDir -PassThru -WindowStyle Normal
  $main2=[IntPtr]::Zero
  for ($i=0; $i -lt 60; $i++) {
    Start-Sleep -Milliseconds 250
    try { $proc2.Refresh() } catch {}
    if ($proc2.HasExited) { break }
    if ($proc2.MainWindowHandle -ne 0) { $main2=[IntPtr]$proc2.MainWindowHandle; break }
    $main2=[B18F]::FindMain([uint32]$proc2.Id)
    if ($main2 -ne [IntPtr]::Zero) { break }
  }
  if ($main2 -ne [IntPtr]::Zero) {
    # Wait for finishSession loadIdeSession + layoutBottomDock (800ms raced
    # createPanel default H=250 before panel.height restore applied).
    Start-Sleep -Milliseconds 2500
    $c2=[B18F]::FindById($main2,1300)
    if ($c2 -eq [IntPtr]::Zero) { Start-Sleep -Milliseconds 1000; $c2=[B18F]::FindById($main2,1300) }
    $hLoad=[B18F]::Height($c2)
    # One more settle if still default 250 while session claimed a taller dock
    if ($hLoad -eq 250 -and $hSave -gt 250) {
      Start-Sleep -Milliseconds 1500
      $c2=[B18F]::FindById($main2,1300)
      $hLoad=[B18F]::Height($c2)
    }
    Log "P08_HLOAD=$hLoad HSAVE=$hSave"
    if ($hSave -gt 0 -and $hLoad -eq $hSave) {
      $sessionReload='PASS_HEIGHT_MATCH'
      if (($h1 -ne $h0) -or ($h2 -ne $h1)) { $p08='PASS'; $p08note="drag_observed+session_reload_match H0=$h0 H1=$h1 H2=$h2 HSave=$hSave HLoad=$hLoad" }
      else { $p08note="session_match but drag_unproven H0=$h0 HSave=$hSave HLoad=$hLoad" }
    } else {
      $sessionReload="FAIL_OR_MISMATCH HSave=$hSave HLoad=$hLoad"
      $p08note="drag_partial H0=$h0 H1=$h1 H2=$h2 session=$sessionReload"
    }
  } else { $sessionReload='FAIL_RELAUNCH_NO_HWND' }
  try { if (-not $proc2.HasExited) { Stop-Process -Id $proc2.Id -Force } } catch {}
} else {
  try { if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force } } catch {}
}

$shaEnd=(Get-FileHash -Algorithm SHA256 -LiteralPath $ExePath).Hash.ToUpperInvariant()
$body = @"
BATCH18_GUI_FOLLOWUP_RECEIPT
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
TIP_SHA=$sha
TIP_SHA_END=$shaEnd
SHA_BOUND=$($sha -eq $shaEnd)
P07=$p07
P07_NOTE=$p07note
P08=$p08
P08_NOTE=$p08note
P08_SESSION_RELOAD=$sessionReload
P09=$p09
P09_NOTE=$p09note
P11=$p11
P11_NOTE=$p11note
CERTIFIED=0
PROMOTE=0
RUNLOG=$log
"@
Set-Content $receipt $body -Encoding UTF8
Write-Output $body
exit 0
