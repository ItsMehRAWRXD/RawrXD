# Reproduce E2E fail path: File.New then wait for delayed 0xC000041D.
# Retain FIRST_CHANCE LAST_MSG + stack. Do not delete FIRST_CHANCE mid-wait.
function FmtExit([int]$ec) {
  $bytes = [BitConverter]::GetBytes($ec)
  return ('0x{0:X8}' -f [BitConverter]::ToUInt32($bytes, 0))
}
$ErrorActionPreference = 'Stop'
Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$bin = "F:\~dev\rawrxd\build-ninja\bin"
$ide = Join-Path $bin "RawrXD-Win32IDE.exe"
$repoEv = "F:\~dev\rawrxd\evidence\P1_UI_MENU_E2E_001"
$crumbDir = Join-Path $bin "evidence\P1_UI_MENU_E2E_001"
$out = Join-Path $repoEv "E2E_FAIL_LOCALIZE.txt"
New-Item -ItemType Directory -Force -Path $crumbDir,$repoEv | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue `
  "$crumbDir\CMD_BREADCRUMB.txt","$crumbDir\FIRST_CHANCE_WM_COMMAND.txt",`
  "$crumbDir\FIRST_CHANCE_JOURNAL.txt","$crumbDir\CMD_DIAG_ARMED.txt",$out

$sha = (Get-FileHash $ide -Algorithm SHA256).Hash
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $ide
$psi.WorkingDirectory = $bin
$psi.UseShellExecute = $false
$psi.EnvironmentVariables["RAWRXD_P1_CMD_DIAG"] = "1"
$psi.EnvironmentVariables["RAWRXD_P1_UI_MENU_E2E"] = "1"

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public class E2eFailLoc {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var sb = new StringBuilder(256);
      GetClassName(h, sb, 256);
      if (sb.ToString() == "RawrXD_IDE_MainWindow" && IsWindowVisible(h)) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@

$proc = [System.Diagnostics.Process]::Start($psi)
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("P1_UI_MENU_E2E_001 E2E_FAIL_LOCALIZE")
$lines.Add("SHA256=$sha")
$lines.Add("PID=$($proc.Id)")
$lines.Add("MODE=E2E=1 CMD_DIAG=1 settle20s File.New(1001) wait45s NO_RELAUNCH")
$lines.Add("TEARDOWN_EXONERATED=NO FAULT_OWNER=UNKNOWN REPAIR=NOT_STARTED")

$main = [IntPtr]::Zero
for ($i = 0; $i -lt 120; $i++) {
  Start-Sleep -Seconds 1
  if ($proc.HasExited) { $lines.Add("EXIT_BEFORE_MAIN=$(FmtExit $proc.ExitCode)"); break }
  $main = [E2eFailLoc]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { $lines.Add("MAIN=$main at_sec=$i"); break }
}
if ($main -eq [IntPtr]::Zero -and -not $proc.HasExited) { throw "NO_MAIN" }

if (-not $proc.HasExited) {
  $lines.Add("SETTLE_20S")
  for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 1
    if ($proc.HasExited) {
      $lines.Add("DIED_SETTLE_SEC=$i EXIT=$(FmtExit $proc.ExitCode)")
      break
    }
  }
}

if (-not $proc.HasExited) {
  # Do NOT wipe FIRST_CHANCE here — retain originating fault for delayed death.
  $lines.Add("INVOKE File.New id=1001 lParam=0")
  [void][E2eFailLoc]::SendMessageW($main, 0x0111, [IntPtr]1001, [IntPtr]::Zero)
  $lines.Add("AFTER_FILENEW_ALIVE=$(-not $proc.HasExited)")
  if ($proc.HasExited) {
    $lines.Add("EXIT_IMMEDIATE_AFTER_FILENEW=$(FmtExit $proc.ExitCode)")
  } else {
    $lines.Add("WAIT_DELAYED_45S")
    for ($i = 0; $i -lt 45; $i++) {
      Start-Sleep -Seconds 1
      if ($proc.HasExited) {
        $lines.Add("DIED_AFTER_FILENEW_SEC=$i EXIT=$(FmtExit $proc.ExitCode)")
        break
      }
    }
    if (-not $proc.HasExited) {
      $lines.Add("STILL_ALIVE_AFTER_45S")
      # Attempt leaf #2 like E2E ladder (File.Open) — prior cert died before this
      $lines.Add("INVOKE File.Open id=1002")
      [void][E2eFailLoc]::SendMessageW($main, 0x0111, [IntPtr]1002, [IntPtr]::Zero)
      Start-Sleep -Seconds 5
      if ($proc.HasExited) {
        $lines.Add("DIED_AFTER_FILEOPEN EXIT=$(FmtExit $proc.ExitCode)")
      } else {
        $lines.Add("ALIVE_AFTER_FILEOPEN")
        $proc.Kill()
        $proc.WaitForExit(10000) | Out-Null
        $lines.Add("KILLED_CLEANUP EXIT=$(FmtExit $proc.ExitCode)")
      }
    }
  }
}

$bc = Join-Path $crumbDir "CMD_BREADCRUMB.txt"
$fc = Join-Path $crumbDir "FIRST_CHANCE_WM_COMMAND.txt"
$fj = Join-Path $crumbDir "FIRST_CHANCE_JOURNAL.txt"
$lines.Add("FIRST_CHANCE=$(Test-Path $fc)")
$lines.Add("JOURNAL=$(Test-Path $fj)")

if (Test-Path $fc) {
  $lines.Add("==== FIRST_CHANCE (retained) ====")
  $lines.AddRange([string[]](Get-Content $fc))
  Copy-Item $fc (Join-Path $repoEv "FIRST_CHANCE_WM_COMMAND.txt") -Force
}
if (Test-Path $fj) {
  $lines.Add("==== JOURNAL (LAST_MSG / codes) ====")
  $lines.AddRange([string[]](Select-String -Path $fj -Pattern "KIND=|EXCEPTION_CODE=|LAST_MSG=|EXCEPTION_ADDR=|TID=|FRAME\[" | ForEach-Object { $_.Line } | Select-Object -Last 80))
  Copy-Item $fj (Join-Path $repoEv "FIRST_CHANCE_JOURNAL.txt") -Force
}
if (Test-Path $bc) {
  $lines.Add("==== CRUMBS File.New / fault ====")
  $filt = @(Get-Content $bc | Where-Object {
    $_ -match 'id=1001|id=1002|SEH|CXX|VEH|DESTROY|NCDESTROY|WINDOWPOS|0x0046|FLIGHT|newFile|route'
  })
  if ($filt.Count -gt 0) { $lines.AddRange([string[]]$filt) }
  $lines.Add("==== BREADCRUMB_TAIL ====")
  $lines.AddRange([string[]](Get-Content $bc | Select-Object -Last 40))
  Copy-Item $bc (Join-Path $repoEv "CMD_BREADCRUMB.txt") -Force
}

$lines | Set-Content $out -Encoding UTF8
$lines | ForEach-Object { Write-Host $_ }
Write-Host "WROTE $out"
