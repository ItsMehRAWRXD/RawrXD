# Batch18 first GUI smokes (P07 tab switch + P10 cold-start observe) on tip SHA.
# P06 cited from BATCH_17 PS smoke — do not invent PRODUCT_PASS.
# CERTIFIED=0 PROMOTE=0. NOT_RUN != PASS. Fail-closed.
param(
  [string]$ExePath = 'F:\rawrxd\build_win32ide\bin\Release\RawrXD-Win32IDE-Native.exe',
  [string]$ExpectedSha = '16D85B1CF7651CA6F43FBC60B99F352A96BBB6C7C00C85ED777F941C8911CE4B',
  [string]$OutDir = 'F:\rawrxd\evidence\UPPER_TIER_MASTER_001\BATCH_18_AUDIT',
  [int]$WaitMs = 6000,
  [switch]$AllowLaunch
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runLog = Join-Path $OutDir "gui_first_smoke_run_$stamp.txt"
$receipt = Join-Path $OutDir 'GUI_FIRST_SMOKE_RECEIPT.txt'

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $runLog -Value $line -Encoding UTF8
  Write-Output $line
}

if (-not (Test-Path -LiteralPath $ExePath)) {
  Log "EXE_ABSENT=$ExePath"
  Set-Content -Path $receipt -Value @"
B18_GUI_FIRST_SMOKE=NOT_RUN
EXE_ABSENT=1
TIP_SHA=
P06=NOT_RUN
P07=NOT_RUN
P08=NOT_RUN
P09=NOT_RUN
P10=NOT_RUN
P11=NOT_RUN
RUNTIME_REACHED=0/6
PRODUCT_RUNTIME_PASS=0/6
CERTIFIED=0
PROMOTE=0
RUNLOG=$runLog
"@ -Encoding UTF8
  exit 2
}

$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $ExePath).Hash.ToUpperInvariant()
Log "EXE_PATH=$ExePath"
Log "SHA256=$sha"
if ($ExpectedSha -and ($sha -ne $ExpectedSha.ToUpperInvariant())) {
  Log "SHA_MISMATCH expected=$ExpectedSha"
  Set-Content -Path $receipt -Value @"
B18_GUI_FIRST_SMOKE=HELD_SHA_MISMATCH
EXE_ABSENT=0
TIP_SHA=$sha
EXPECTED_SHA=$ExpectedSha
P06=NOT_RUN
P07=NOT_RUN
P10=NOT_RUN
RUNTIME_REACHED=0/6
PRODUCT_RUNTIME_PASS=0/6
CERTIFIED=0
PROMOTE=0
RUNLOG=$runLog
"@ -Encoding UTF8
  exit 4
}

if (-not $AllowLaunch) {
  Log 'LAUNCH=HELD_NO_ALLOWLAUNCH'
  Set-Content -Path $receipt -Value @"
B18_GUI_FIRST_SMOKE=PREPARED_HELD
EXE_ABSENT=0
TIP_SHA=$sha
LAUNCH=HELD_NO_ALLOWLAUNCH
P07=NOT_RUN
P10=NOT_RUN
PRODUCT_RUNTIME_PASS=0/6
CERTIFIED=0
PROMOTE=0
RUNLOG=$runLog
"@ -Encoding UTF8
  exit 0
}

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class B18GuiSmoke {
  public const uint WM_COMMAND = 0x0111;
  public const uint TCM_FIRST = 0x1300;
  public const uint TCM_GETITEMCOUNT = TCM_FIRST + 4;
  public const uint TCM_GETCURSEL = TCM_FIRST + 11;
  public const uint TCM_SETCURSEL = TCM_FIRST + 12;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint wpid; GetWindowThreadProcessId(h, out wpid);
      if (wpid != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c.IndexOf("RawrXD", StringComparison.OrdinalIgnoreCase) >= 0) { found = h; return false; }
      if (found == IntPtr.Zero) found = h;
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindById(IntPtr root, int id) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(root, (h, lp) => {
      if (GetDlgCtrlID(h) == id) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static string Vis(IntPtr h) {
    if (h == IntPtr.Zero) return "ABSENT";
    return IsWindowVisible(h) ? "VISIBLE" : "HIDDEN";
  }
}
"@

Get-Process -Name 'RawrXD-Win32IDE-Native*' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

$workDir = Split-Path -Parent $ExePath
$env:RAWRXD_LOG_DIR = $OutDir
$sw = [Diagnostics.Stopwatch]::StartNew()
$proc = Start-Process -FilePath $ExePath -WorkingDirectory $workDir -PassThru -WindowStyle Normal
Log "PID=$($proc.Id)"

$main = [IntPtr]::Zero
$earlyExit = $false
$exitCode = ''
for ($i = 0; $i -lt 80; $i++) {
  Start-Sleep -Milliseconds 250
  try { $proc.Refresh() } catch {}
  if ($proc.HasExited) {
    $earlyExit = $true
    $exitCode = "$($proc.ExitCode)"
    Log "EARLY_EXIT code=$exitCode after_ms=$($sw.ElapsedMilliseconds)"
    break
  }
  if ($proc.MainWindowHandle -ne 0) { $main = [IntPtr]$proc.MainWindowHandle; break }
  $main = [B18GuiSmoke]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log ("MAIN_HWND=0x{0:X} startup_ms={1}" -f $main.ToInt64(), $sw.ElapsedMilliseconds)

$p10 = 'NOT_RUN'
if ($earlyExit) { $p10 = 'FAIL_EARLY_EXIT' }
elseif ($main -eq [IntPtr]::Zero) { $p10 = 'HELD_NO_MAIN_HWND' }
else { $p10 = 'RUNTIME_REACHED_COLD_START_HWND' }

$p07 = 'NOT_RUN'
$tabCount = -1
$stall = 0
if ($main -ne [IntPtr]::Zero -and -not $earlyExit) {
  [void][B18GuiSmoke]::SetForegroundWindow($main)
  Start-Sleep -Milliseconds 1000
  $tabs = [B18GuiSmoke]::FindById($main, 1301)
  Log ("PANEL_TABS=0x{0:X}" -f $tabs.ToInt64())
  if ($tabs -eq [IntPtr]::Zero) {
    $p07 = 'HELD_NO_TABCTRL'
  } else {
    $tabCount = [int][B18GuiSmoke]::SendMessageW($tabs, [B18GuiSmoke]::TCM_GETITEMCOUNT, [IntPtr]::Zero, [IntPtr]::Zero)
    Log "PANEL_TAB_COUNT=$tabCount"
    $ids = @(1302, 1303, 1312, 1305)
    $names = @('Terminal', 'Output', 'ProblemsList', 'DebugConsole')
    $maxIdx = [Math]::Min(3, [Math]::Max(0, $tabCount - 1))
    for ($cycle = 0; $cycle -lt 3; $cycle++) {
      for ($idx = 0; $idx -le $maxIdx; $idx++) {
        $t0 = [Diagnostics.Stopwatch]::StartNew()
        [void][B18GuiSmoke]::SendMessageW($tabs, [B18GuiSmoke]::TCM_SETCURSEL, [IntPtr]$idx, [IntPtr]::Zero)
        [void][B18GuiSmoke]::PostMessageW($main, [B18GuiSmoke]::WM_COMMAND, [IntPtr]1301, $tabs)
        Start-Sleep -Milliseconds 350
        $t0.Stop()
        if ($t0.ElapsedMilliseconds -gt 5000) { $stall++ }
        $cur = [int][B18GuiSmoke]::SendMessageW($tabs, [B18GuiSmoke]::TCM_GETCURSEL, [IntPtr]::Zero, [IntPtr]::Zero)
        $visParts = @()
        for ($j = 0; $j -lt $ids.Count; $j++) {
          $h = [B18GuiSmoke]::FindById($main, $ids[$j])
          $visParts += ("{0}={1}" -f $names[$j], [B18GuiSmoke]::Vis($h))
        }
        Log "cycle=$cycle sel=$idx cur=$cur ms=$($t0.ElapsedMilliseconds) $($visParts -join ' ')"
        try { $proc.Refresh() } catch {}
        if ($proc.HasExited) {
          $earlyExit = $true
          $p07 = 'FAIL_EXIT_DURING_TAB_SWITCH'
          $exitCode = "$($proc.ExitCode)"
          break
        }
      }
      if ($earlyExit) { break }
    }
    if (-not $earlyExit) {
      if ($tabCount -lt 4) { $p07 = "RUNTIME_REACHED_TAB_COUNT_$tabCount" }
      elseif ($stall -gt 0) { $p07 = "RUNTIME_REACHED_WITH_STALL_COUNT_$stall" }
      else { $p07 = 'RUNTIME_REACHED_4TAB_CYCLE' }
    }
  }
}

$p08 = 'NOT_RUN'
if ($main -ne [IntPtr]::Zero -and -not $earlyExit) {
  $maxBtn = [B18GuiSmoke]::FindById($main, 1310)
  if ($maxBtn -eq [IntPtr]::Zero) {
    $p08 = 'HELD_NO_MAXIMIZE_CTRL'
  } else {
    [void][B18GuiSmoke]::PostMessageW($main, [B18GuiSmoke]::WM_COMMAND, [IntPtr]1310, $maxBtn)
    Start-Sleep -Milliseconds 400
    $p08 = 'RUNTIME_REACHED_MAXIMIZE_POSTED'
    Log ("MAXIMIZE_BTN=0x{0:X} POSTED" -f $maxBtn.ToInt64())
  }
}

$p06Cite = 'F:\rawrxd\evidence\UPPER_TIER_MASTER_001\BATCH_17\PS_SMOKE_HARNESS\PS_SMOKE_RECEIPT.txt'
$p06 = 'NOT_RUN'
$p06Note = 'missing_receipt'
if (Test-Path $p06Cite) {
  $body = Get-Content $p06Cite -Raw
  if ($body -match 'SHA256=16D85B1CF7651CA6F43FBC60B99F352A96BBB6C7C00C85ED777F941C8911CE4B' -and
      $body -match 'RUNTIME_EXERCISED_UNPROMOTED') {
    $p06 = 'RUNTIME_REACHED_UNPROMOTED'
    $p06Note = 'cite_BATCH_17_PS_SMOKE;PRODUCT_PASS=0'
  } else {
    $p06 = 'HELD_CITE_SHA_OR_STATUS_MISMATCH'
    $p06Note = 'receipt_present_but_not_matching_tip'
  }
}

try { if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force } } catch {}

$reached = 0
foreach ($v in @($p06, $p07, $p08, $p10)) {
  if ($v -like 'RUNTIME_REACHED*') { $reached++ }
}
$p09 = 'NOT_RUN'
$p11 = 'NOT_RUN'

Set-Content -Path $receipt -Value @"
B18_GUI_FIRST_SMOKE=RUNTIME_EXERCISED_UNPROMOTED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
EXE_ABSENT=0
EXE_PATH=$ExePath
TIP_SHA=$sha
MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())
EARLY_EXIT=$earlyExit
EXIT_CODE=$exitCode
PANEL_TAB_COUNT=$tabCount
STALL_COUNT=$stall
P06=$p06
P06_NOTE=$p06Note
P06_CITE=$p06Cite
P07=$p07
P08=$p08
P09=$p09
P10=$p10
P11=$p11
RUNTIME_REACHED=$reached/6
PRODUCT_RUNTIME_PASS=0/6
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
UPPER_TIER=0
NO_INVENT_PASS=1
NOT_RUN_NEQ_PASS=1
RUNLOG=$runLog
"@ -Encoding UTF8
Get-Content $receipt
exit 0
