# BATCH_17 P06 PowerShell Execute/Clear/Stop smoke (5610/5611/5612).
# Cite: POWERSHELL_ROUTING_REPAIR_001 + Win32IDE_lifecycle.cpp tip routing
#   (WM_COMMAND 5610/5611/5612 before legacy 7100 decoder).
# Fail-closed: missing exe => NO launch. CERTIFIED=0 PROMOTE=0.
# NOT_RUN != PASS. RUNTIME_SMOKE remains HELD until a real tip-SHA run.
param(
  [Parameter(Mandatory = $false)]
  [string]$ExePath = 'F:\rawrxd\build_win32ide\Release\RawrXD-Win32IDE-Native.exe',
  [string]$OutDir = 'F:\rawrxd\evidence\UPPER_TIER_MASTER_001\BATCH_17\PS_SMOKE_HARNESS',
  [int]$WaitMs = 8000,
  [switch]$AllowLaunch
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runLog = Join-Path $OutDir "ps_smoke_run_$stamp.txt"
$receipt = Join-Path $OutDir 'PS_SMOKE_RECEIPT.txt'
$dispPath = Join-Path $OutDir 'DISPOSITION.json'

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $runLog -Value $line -Encoding UTF8
  Write-Output $line
}

function Write-HeldDisposition([hashtable]$extra) {
  $obj = [ordered]@{
    disposition_id   = 'BATCH_17_PS_SMOKE_HARNESS'
    cite             = @(
      'POWERSHELL_ROUTING_REPAIR_001',
      'Win32IDE_lifecycle.cpp WM_COMMAND 5610/5611/5612 before 7100'
    )
    acceptance       = @('5610_Execute', '5611_Clear', '5612_Stop', 'legacy_7100_isolation')
    RUNTIME_SMOKE    = 'HELD'
    CERTIFIED        = 0
    PROMOTE          = 0
    TIP_CLIMB        = 'HOLD'
    laws             = @{
      SOURCE_PATCH_NE_RUNTIME_PASS = $true
      NOT_RUN_NE_PASS              = $true
      EXE_ABSENT_NE_LAUNCH         = $true
    }
    updated_at       = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  }
  foreach ($k in $extra.Keys) { $obj[$k] = $extra[$k] }
  ($obj | ConvertTo-Json -Depth 6) | Set-Content -Path $dispPath -Encoding UTF8
}

function Write-Receipt([string]$body) {
  Set-Content -Path $receipt -Value $body -Encoding UTF8
  Get-Content $receipt
}

# --- Fail-closed gate: never launch when exe absent ---
if (-not (Test-Path -LiteralPath $ExePath)) {
  Log "EXE_ABSENT=$ExePath"
  Log 'LAUNCH=SKIPPED'
  Log 'RUNTIME_SMOKE=HELD'
  Write-HeldDisposition @{
    EXE_ABSENT     = 1
    ExePath        = $ExePath
    LAUNCH         = 'SKIPPED'
    RESULT         = 'NOT_RUN_EXE_ABSENT'
    PRODUCT_PASS   = 0
  }
  Write-Receipt @"
PS_SMOKE=NOT_RUN
EXE_ABSENT=1
EXE_PATH=$ExePath
LAUNCH=SKIPPED
SHA256=
5610_Execute=NOT_RUN
5611_Clear=NOT_RUN
5612_Stop=NOT_RUN
RUNTIME_SMOKE=HELD
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
PRODUCT_PASS=0
CITE=POWERSHELL_ROUTING_REPAIR_001;Win32IDE_lifecycle_5610
NOT_RUN_NE_PASS=1
RUNLOG=$runLog
"@
  exit 2
}

$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $ExePath).Hash.ToUpperInvariant()
Log "EXE_PATH=$ExePath"
Log "SHA256=$sha"

# Prep-only / held mode: require explicit -AllowLaunch to start the IDE.
if (-not $AllowLaunch) {
  Log 'LAUNCH=HELD_NO_ALLOWLAUNCH'
  Log 'RUNTIME_SMOKE=HELD'
  Write-HeldDisposition @{
    EXE_ABSENT   = 0
    ExePath      = $ExePath
    SHA256       = $sha
    LAUNCH       = 'HELD_NO_ALLOWLAUNCH'
    RESULT       = 'PREPARED_AWAITING_ALLOWLAUNCH'
    PRODUCT_PASS = 0
  }
  Write-Receipt @"
PS_SMOKE=PREPARED_HELD
EXE_ABSENT=0
EXE_PATH=$ExePath
SHA256=$sha
LAUNCH=HELD_NO_ALLOWLAUNCH
5610_Execute=NOT_RUN
5611_Clear=NOT_RUN
5612_Stop=NOT_RUN
RUNTIME_SMOKE=HELD
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
PRODUCT_PASS=0
CITE=POWERSHELL_ROUTING_REPAIR_001;Win32IDE_lifecycle_5610
NOT_RUN_NE_PASS=1
NOTE=Re-run with -AllowLaunch after tip exe is the intended Batch-17 binary.
RUNLOG=$runLog
"@
  exit 0
}

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class B17PsSmoke {
  public const uint WM_COMMAND = 0x0111;
  public const uint BM_CLICK = 0x00F5;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const int IDC_PS_PANEL = 5600;
  public const int IDC_PS_OUTPUT = 5601;
  public const int IDC_PS_INPUT = 5602;
  public const int IDC_PS_EXECUTE = 5610;
  public const int IDC_PS_CLEAR = 5611;
  public const int IDC_PS_STOP = 5612;
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
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint wpid; GetWindowThreadProcessId(h, out wpid);
      if (wpid != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c == "RawrXD_IDE_Window" || c == "RawrXD_IDE_MainWindow" ||
          c.IndexOf("RawrXD", StringComparison.OrdinalIgnoreCase) >= 0) {
        found = h; return false;
      }
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
  public static string GetText(IntPtr h) {
    if (h == IntPtr.Zero) return "";
    int n = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    if (n <= 0) return "";
    if (n > 120000) n = 120000;
    var sb = new StringBuilder(n + 2);
    SendMessageW(h, WM_GETTEXT, (IntPtr)(n + 1), sb);
    return sb.ToString();
  }
}
"@

$workDir = Split-Path -Parent $ExePath
$env:RAWRXD_LOG_DIR = $OutDir
Get-Process -Name 'RawrXD-Win32IDE-Native*' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

$proc = Start-Process -FilePath $ExePath -WorkingDirectory $workDir -PassThru -WindowStyle Normal
Log "PID=$($proc.Id)"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 250
  try { $proc.Refresh() } catch {}
  if ($proc.HasExited) { Log "EARLY_EXIT code=$($proc.ExitCode)"; break }
  if ($proc.MainWindowHandle -ne 0) { $main = [IntPtr]$proc.MainWindowHandle; break }
  $main = [B17PsSmoke]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log ("MAIN_HWND=0x{0:X}" -f $main.ToInt64())

if ($main -eq [IntPtr]::Zero) {
  try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
  Write-HeldDisposition @{
    EXE_ABSENT = 0; ExePath = $ExePath; SHA256 = $sha
    LAUNCH = 'ATTEMPTED'; RESULT = 'NOT_RUN_NO_MAIN_HWND'; PRODUCT_PASS = 0
  }
  Write-Receipt @"
PS_SMOKE=NOT_RUN
EXE_ABSENT=0
EXE_PATH=$ExePath
SHA256=$sha
MAIN_HWND=0
5610_Execute=NOT_RUN
5611_Clear=NOT_RUN
5612_Stop=NOT_RUN
RUNTIME_SMOKE=HELD
CERTIFIED=0
PROMOTE=0
PRODUCT_PASS=0
RUNLOG=$runLog
"@
  exit 3
}

[void][B17PsSmoke]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 800

$psPanel = [B17PsSmoke]::FindById($main, 5600)
$psOut   = [B17PsSmoke]::FindById($main, 5601)
$psIn    = [B17PsSmoke]::FindById($main, 5602)
$psExec  = [B17PsSmoke]::FindById($main, 5610)
$psClear = [B17PsSmoke]::FindById($main, 5611)
$psStop  = [B17PsSmoke]::FindById($main, 5612)
Log ("PS_PANEL=0x{0:X} EXEC=0x{1:X} CLEAR=0x{2:X} STOP=0x{3:X}" -f `
  $psPanel.ToInt64(), $psExec.ToInt64(), $psClear.ToInt64(), $psStop.ToInt64())

# Tip routing: frame WM_COMMAND 5610/5611/5612 (lifecycle before 7100).
$r5610 = 'ATTEMPTED'
$r5611 = 'ATTEMPTED'
$r5612 = 'ATTEMPTED'
try {
  if ($psIn -ne [IntPtr]::Zero) {
    [void][B17PsSmoke]::SetWindowTextW($psIn, 'Write-Output B17_PS_SMOKE')
    Start-Sleep -Milliseconds 150
  }
  # Prefer main-frame tip path (POWERSHELL_ROUTING_REPAIR_001).
  [void][B17PsSmoke]::PostMessageW($main, [B17PsSmoke]::WM_COMMAND, [IntPtr]5610, $psExec)
  Log 'EXEC_PATH=POST_WM_COMMAND_MAIN_5610'
  if ($psExec -ne [IntPtr]::Zero) {
    [void][B17PsSmoke]::PostMessageW($psExec, [B17PsSmoke]::BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero)
    Log 'EXEC_PATH=BM_CLICK_5610'
  }
  Start-Sleep -Milliseconds ([Math]::Min($WaitMs, 4000))
  $afterExec = [B17PsSmoke]::GetText($psOut)
  Log ("PS_AFTER_EXEC_LEN={0}" -f $afterExec.Length)

  [void][B17PsSmoke]::PostMessageW($main, [B17PsSmoke]::WM_COMMAND, [IntPtr]5612, $psStop)
  Log 'STOP_PATH=POST_WM_COMMAND_MAIN_5612'
  Start-Sleep -Milliseconds 400

  [void][B17PsSmoke]::PostMessageW($main, [B17PsSmoke]::WM_COMMAND, [IntPtr]5611, $psClear)
  Log 'CLEAR_PATH=POST_WM_COMMAND_MAIN_5611'
  Start-Sleep -Milliseconds 400
  $afterClear = [B17PsSmoke]::GetText($psOut)
  Log ("PS_AFTER_CLEAR_LEN={0}" -f $afterClear.Length)

  # Observation only — never auto-PASS; seal remains fail-closed for promote.
  if ($afterExec.Length -gt 0) { $r5610 = 'OBSERVED_OUTPUT' } else { $r5610 = 'NO_OUTPUT_OBSERVED' }
  $r5612 = 'POSTED'
  $r5611 = if ($afterClear.Length -lt $afterExec.Length) { 'OBSERVED_SHRINK' } else { 'POSTED' }
} catch {
  Log "SMOKE_EXCEPTION=$($_.Exception.Message)"
  $r5610 = 'ERROR'; $r5611 = 'ERROR'; $r5612 = 'ERROR'
}

try { if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force } } catch {}

# Fail-closed seal: runtime exercise != CERTIFIED/PROMOTE.
Write-HeldDisposition @{
  EXE_ABSENT   = 0
  ExePath      = $ExePath
  SHA256       = $sha
  LAUNCH       = 'ATTEMPTED'
  RESULT       = 'RUNTIME_EXERCISED_UNPROMOTED'
  '5610'       = $r5610
  '5611'       = $r5611
  '5612'       = $r5612
  PRODUCT_PASS = 0
}
Write-Receipt @"
PS_SMOKE=RUNTIME_EXERCISED_UNPROMOTED
EXE_ABSENT=0
EXE_PATH=$ExePath
SHA256=$sha
MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())
5610_Execute=$r5610
5611_Clear=$r5611
5612_Stop=$r5612
RUNTIME_SMOKE=HELD
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
PRODUCT_PASS=0
CITE=POWERSHELL_ROUTING_REPAIR_001;Win32IDE_lifecycle_5610
SOURCE_PATCH_NE_RUNTIME_PASS=1
NOT_RUN_NE_PASS=1
RUNLOG=$runLog
"@
exit 0
