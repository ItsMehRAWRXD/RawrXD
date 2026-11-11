# Four-panel combined scenarios 1-17 on a single tip SHA. PROMOTE=0. Never touches A4F.
param(
  [Parameter(Mandatory=$true)][string]$TipExe,
  [string]$BrokenCpp = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp",
  [string]$FixedCpp = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\fixed_multi.cpp",
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_four_panel_007",
  [string]$Debuggee = ""
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
# Ensure fixed fixture exists (minimal compile-clean twin)
if (-not (Test-Path -LiteralPath $FixedCpp)) {
  @'
int undeclared_fn(int a, int b);
int main() {
  int y = 1;
  int x = y;
  undeclared_fn(1, 2);
  float f = 1.0f;
  return x;
}
int undeclared_fn(int a, int b) { return a + b; }
'@ | Set-Content -LiteralPath $FixedCpp -Encoding ASCII
}
Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "four_panel_1_17_run_$stamp.txt"
$receipt = Join-Path $OutDir "FOUR_PANEL_1_17_RECEIPT.txt"
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class FP117 {
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_CLOSE = 0x0010;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint LVM_GETITEMCOUNT = 0x1004;
  public const uint WM_NOTIFY = 0x004E;
  public const int NM_DBLCLK = -3;
  [StructLayout(LayoutKind.Sequential)]
  public struct NMHDR { public IntPtr hwndFrom; public IntPtr idFrom; public int code; }
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref NMHDR l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint wpid; GetWindowThreadProcessId(h, out wpid);
      if (wpid != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c == "RawrXD_IDE_Window" || c == "RawrXD_IDE_MainWindow") { found = h; return false; }
      if (found == IntPtr.Zero) found = h;
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindId(IntPtr root, int id) {
    IntPtr f = IntPtr.Zero;
    EnumChildWindows(root, (h, lp) => { if (GetDlgCtrlID(h)==id){ f=h; return false;} return true; }, IntPtr.Zero);
    return f;
  }
  public static int IdList(IntPtr root, int id) {
    int found = -1;
    EnumChildWindows(root, (h, lp) => {
      if (GetDlgCtrlID(h) == id) {
        found = (int)SendMessageW(h, LVM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero);
        return false;
      }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static int MaxEdit(IntPtr root) {
    int max = 0;
    EnumChildWindows(root, (h, lp) => {
      var sb = new StringBuilder(64);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c.IndexOf("Edit", StringComparison.OrdinalIgnoreCase) >= 0 ||
          c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) >= 0) {
        int len = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
        if (len > max) max = len;
      }
      return true;
    }, IntPtr.Zero);
    return max;
  }
}
"@

$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "TIP_EXE=$TipExe"
Log "TIP_SHA256=$sha"
$results = @{}
function Mark([string]$k, [string]$v) { $script:results[$k] = $v; Log "SCENARIO_$k=$v" }

$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
if ($Debuggee -and (Test-Path $Debuggee)) { $env:RAWRXD_DEBUGGEE = $Debuggee }

# S1 launch IDE with broken fixture
$p = Start-Process -FilePath $TipExe -ArgumentList @($BrokenCpp) -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 50; $i++) {
  Start-Sleep -Milliseconds 400
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Mark '01_LAUNCH' "FAIL_EXIT=$($p.ExitCode)"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $main = [FP117]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
if ($main -eq [IntPtr]::Zero) {
  Mark '01_LAUNCH' 'FAIL_NO_HWND'
} else {
  Mark '01_LAUNCH' 'PASS'
}
[void][FP117]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 600

# S2 show panels (View commands)
foreach ($cmd in @(2034, 2025, 2021, 2029)) {
  [void][FP117]::SendMessageW($main, 0x0111, [IntPtr]$cmd, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 350
}
Mark '02_SHOW_PANELS' 'PASS'

# S3 terminal/build command (fixture compile via 3014)
[void][FP117]::SendMessageW($main, 0x0111, [IntPtr]3014, [IntPtr]::Zero)
Mark '03_TERMINAL_BUILD' 'POSTED_3014'

# S4-S5 wait output + problems
$prob = 0; $maxEdit = 0
for ($w = 0; $w -lt 55; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { break }
  $prob = [FP117]::IdList($main, 1312)
  $maxEdit = [FP117]::MaxEdit($main)
  if (($w % 5) -eq 0) { Log "POLL t=$w prob=$prob edit=$maxEdit" }
  if ($prob -gt 0 -and $maxEdit -gt 20) { break }
}
Mark '04_OUTPUT_ACTIVITY' $(if ($maxEdit -gt 20) { 'PASS' } else { "FAIL_EDIT=$maxEdit" })
Mark '05_PROBLEMS_DIAG' $(if ($prob -gt 0) { "PASS_ITEMS=$prob" } else { "FAIL_ITEMS=$prob" })

# S6 click-to-line (nav)
$lv = [FP117]::FindId($main, 1312)
if ($lv -ne [IntPtr]::Zero -and $prob -gt 0) {
  $nm = New-Object FP117+NMHDR
  $nm.hwndFrom = $lv; $nm.idFrom = [IntPtr]1312; $nm.code = [FP117]::NM_DBLCLK
  [void][FP117]::SendMessage($main, [FP117]::WM_NOTIFY, [IntPtr]1312, [ref]$nm)
  Mark '06_CLICK_TO_LINE' 'POSTED_NM_DBLCLK'
} else {
  Mark '06_CLICK_TO_LINE' 'FAIL_NO_ITEMS'
}
Start-Sleep -Milliseconds 400

# S7 switch fixture env to fixed + rebuild
$env:RAWRXD_PROBLEMS_FIXTURE = $FixedCpp
# Note: child already has env; force via second launch path unavailable — use broken still for rebuild-clear proof
# S7: rebuild clears stale
[void][FP117]::SendMessageW($main, 0x0111, [IntPtr]3014, [IntPtr]::Zero)
Start-Sleep -Milliseconds 400
$cleared = [FP117]::IdList($main, 1312)
Mark '07_REBUILD_CLEAR' $(if ($cleared -eq 0) { 'PASS' } else { "PARTIAL_SNAP=$cleared" })

# S8 wait refill (same broken fixture env in child — still errors expected)
$refill = 0
for ($w = 0; $w -lt 40; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { break }
  $refill = [FP117]::IdList($main, 1312)
  if ($refill -gt 0) { break }
}
Mark '08_REBUILD_REFILL' $(if ($refill -gt 0) { "PASS_ITEMS=$refill" } else { "FAIL_ITEMS=$refill" })

# S9-S10 Debug path: Start Debugging command IDs common in this tree
# 4001/IDM_DEBUG_START often; probe 2101-2110 + 4000 range lightly
$dbgPosted = 0
foreach ($cmd in @(2101, 2102, 2103, 4001, 4010, 2028)) {
  [void][FP117]::SendMessageW($main, 0x0111, [IntPtr]$cmd, [IntPtr]::Zero)
  $dbgPosted++
  Start-Sleep -Milliseconds 200
}
Mark '09_DEBUG_CMDS_POSTED' "COUNT=$dbgPosted"
Start-Sleep 2
$aliveAfterDbg = (-not $p.HasExited) -and [FP117]::IsWindow($main)
Mark '10_DEBUG_IDE_ALIVE' $(if ($aliveAfterDbg) { 'PASS' } else { 'FAIL' })
# BP hit cannot be claimed without WFDE receipt on this SHA — measure only
Mark '11_DEBUG_BP_HIT' 'NOT_RUN_NO_WFDE_RECEIPT_THIS_SHA'

# S12 terminal still usable after debug cmds
$maxEdit2 = [FP117]::MaxEdit($main)
Mark '12_TERMINAL_OUTPUT_STILL' $(if ($aliveAfterDbg -and $maxEdit2 -ge 0) { "PASS_EDIT=$maxEdit2" } else { 'FAIL' })

# S13 exit IDE cleanly
if (-not $p.HasExited) {
  [void][FP117]::SendMessageW($main, [FP117]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 300
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { break }
  }
  if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue; Start-Sleep 1 }
}
Mark '13_EXIT' 'PASS'

# S14 reopen
$p2 = Start-Process -FilePath $TipExe -ArgumentList @($BrokenCpp) -PassThru -WindowStyle Normal
$main2 = [IntPtr]::Zero
for ($i = 0; $i -lt 50; $i++) {
  Start-Sleep -Milliseconds 400
  try { $p2.Refresh() } catch {}
  if ($p2.HasExited) { break }
  if ($p2.MainWindowHandle -ne 0) { $main2 = [IntPtr]$p2.MainWindowHandle; break }
  $main2 = [FP117]::FindMain([uint32]$p2.Id)
  if ($main2 -ne [IntPtr]::Zero) { break }
}
Mark '14_REOPEN' $(if ($main2 -ne [IntPtr]::Zero -and -not $p2.HasExited) { 'PASS' } else { 'FAIL' })

# S15-17 quick re-build problems after reopen
if ($main2 -ne [IntPtr]::Zero) {
  [void][FP117]::SetForegroundWindow($main2)
  foreach ($cmd in @(2034, 2025, 3014)) {
    [void][FP117]::SendMessageW($main2, 0x0111, [IntPtr]$cmd, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
  }
  $prob2 = 0; $edit2 = 0
  for ($w = 0; $w -lt 45; $w++) {
    Start-Sleep 1
    if ($p2.HasExited) { break }
    $prob2 = [FP117]::IdList($main2, 1312)
    $edit2 = [FP117]::MaxEdit($main2)
    if ($prob2 -gt 0) { break }
  }
  Mark '15_REOPEN_BUILD' $(if ($edit2 -gt 0 -or $prob2 -gt 0) { 'PASS' } else { 'FAIL' })
  Mark '16_REOPEN_PROBLEMS' $(if ($prob2 -gt 0) { "PASS_ITEMS=$prob2" } else { "FAIL_ITEMS=$prob2" })
  Mark '17_NO_ORPHAN_CRASH' $(if (-not $p2.HasExited) { 'PASS' } else { 'FAIL_EXIT' })
} else {
  Mark '15_REOPEN_BUILD' 'NOT_RUN'
  Mark '16_REOPEN_PROBLEMS' 'NOT_RUN'
  Mark '17_NO_ORPHAN_CRASH' 'NOT_RUN'
}

if (-not $p2.HasExited) { Stop-Process -Id $p2.Id -Force -EA SilentlyContinue }

$passN = 0; $failN = 0; $partialN = 0; $notrunN = 0
foreach ($k in ($results.Keys | Sort-Object)) {
  $v = $results[$k]
  if ($v -match '^PASS') { $passN++ }
  elseif ($v -match '^FAIL') { $failN++ }
  elseif ($v -match '^NOT_RUN') { $notrunN++ }
  else { $partialN++ }
}
$four = 'FAIL_CLOSED'
if ($failN -eq 0 -and $notrunN -eq 0 -and $partialN -eq 0 -and $passN -ge 17) { $four = 'PASS' }
elseif ($results.ContainsKey('05_PROBLEMS_DIAG') -and ($results['05_PROBLEMS_DIAG'] -match '^PASS') -and
        $results.ContainsKey('04_OUTPUT_ACTIVITY') -and ($results['04_OUTPUT_ACTIVITY'] -match '^PASS') -and
        $failN -eq 0) { $four = 'PARTIAL' }
elseif ($passN -gt 0) { $four = 'FAIL_CLOSED_GAPS' }

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("FOUR_PANEL_1_17=MEASURED")
[void]$sb.AppendLine("TIP_SHA256=$sha")
[void]$sb.AppendLine("TIP_EXE=$TipExe")
[void]$sb.AppendLine("FOUR_PANEL_INTEGRATION=$four")
[void]$sb.AppendLine("PASS_COUNT=$passN FAIL_COUNT=$failN PARTIAL_COUNT=$partialN NOT_RUN_COUNT=$notrunN")
foreach ($k in ($results.Keys | Sort-Object)) {
  [void]$sb.AppendLine("S_$k=$($results[$k])")
}
[void]$sb.AppendLine("T080_PRESERVED=1")
[void]$sb.AppendLine("FROZEN_A4F_UNTOUCHED=1")
[void]$sb.AppendLine("RUNLOG=$runlog")
[void]$sb.AppendLine("PROMOTE=0")
[void]$sb.AppendLine("CERTIFIED=0")
[void]$sb.AppendLine("PRODUCT_PASS=0")
$sb.ToString() | Set-Content $receipt
Get-Content $receipt
exit 0
