# Settle-only first-chance capture (no intentional menu invoke).
# Localizes 0xC000041D / 0xC0000374 that previously killed the process during settle.
$ErrorActionPreference = 'Stop'

function FmtExit([int]$ec) {
  $bytes = [BitConverter]::GetBytes($ec)
  return ('0x{0:X8}' -f [BitConverter]::ToUInt32($bytes, 0))
}' -f $u)
}

Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$bin = "F:\~dev\rawrxd\build-ninja\bin"
$ide = Join-Path $bin "RawrXD-Win32IDE.exe"
$crumbDir = Join-Path $bin "evidence\P1_UI_MENU_E2E_001"
$repoEv = "F:\~dev\rawrxd\evidence\P1_UI_MENU_E2E_001"
$out = Join-Path $repoEv "SETTLE_FIRST_CHANCE.txt"
New-Item -ItemType Directory -Force -Path $crumbDir,$repoEv | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue `
  "$crumbDir\CMD_BREADCRUMB.txt","$crumbDir\FIRST_CHANCE_WM_COMMAND.txt",`
  "$crumbDir\COMMAND_FLIGHT.jsonl","$crumbDir\CMD_DIAG_ARMED.txt",`
  "$crumbDir\IDE_GETTEXT_INFLIGHT.txt",$out

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $ide
$psi.WorkingDirectory = $bin
$psi.UseShellExecute = $false
$psi.EnvironmentVariables["RAWRXD_P1_CMD_DIAG"] = "1"

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public class SettleProbe {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
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

$sha = (Get-FileHash $ide -Algorithm SHA256).Hash
$proc = [System.Diagnostics.Process]::Start($psi)
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("P1_UI_MENU_E2E_001 SETTLE_FIRST_CHANCE")
$lines.Add("PID=$($proc.Id)")
$lines.Add("SHA256=$sha")
$lines.Add("MODE=settle_only_no_invoke")

$main = [IntPtr]::Zero
$mainAt = -1
for ($i = 0; $i -lt 120; $i++) {
  Start-Sleep -Seconds 1
  if ($proc.HasExited) {
    $lines.Add("EXIT_BEFORE_MAIN=$(FmtExit $proc.ExitCode)")
    break
  }
  $main = [SettleProbe]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { $mainAt = $i; break }
}
$lines.Add("MAIN=$main at_sec=$mainAt")

$died = $false
if (-not $proc.HasExited -and $main -ne [IntPtr]::Zero) {
  for ($i = 0; $i -lt 45; $i++) {
    Start-Sleep -Seconds 1
    if ($proc.HasExited) {
      $died = $true
      $lines.Add("DIED_DURING_SETTLE_AT_SEC=$i EXIT=$(FmtExit $proc.ExitCode)")
      break
    }
  }
}
if (-not $proc.HasExited) {
  $lines.Add("SETTLE_ALIVE_AFTER_45S=1")
  $proc.Kill()
  $proc.WaitForExit(5000) | Out-Null
  $lines.Add("KILLED_AFTER_CAPTURE EXIT=$(FmtExit $proc.ExitCode)")
} elseif (-not $died) {
  $lines.Add("EXIT=$(FmtExit $proc.ExitCode)")
}

$fc = Join-Path $crumbDir "FIRST_CHANCE_WM_COMMAND.txt"
$bc = Join-Path $crumbDir "CMD_BREADCRUMB.txt"
$armed = Join-Path $crumbDir "CMD_DIAG_ARMED.txt"
$ideInf = Join-Path $crumbDir "IDE_GETTEXT_INFLIGHT.txt"
$lines.Add("ARMED=$(Test-Path $armed)")
$lines.Add("FIRST_CHANCE_PRESENT=$(Test-Path $fc)")
$lines.Add("IDE_GETTEXT_INFLIGHT_PRESENT=$(Test-Path $ideInf)")
if (Test-Path $ideInf) {
  $lines.Add("---- IDE_GETTEXT_INFLIGHT ----")
  $lines.AddRange([string[]](Get-Content $ideInf))
}
if (Test-Path $armed) {
  $lines.Add("---- CMD_DIAG_ARMED ----")
  $lines.AddRange([string[]](Get-Content $armed))
}
if (Test-Path $fc) {
  $lines.Add("---- FIRST_CHANCE_WM_COMMAND ----")
  $lines.AddRange([string[]](Get-Content $fc))
  Copy-Item $fc (Join-Path $repoEv "FIRST_CHANCE_WM_COMMAND.txt") -Force
} else {
  $lines.Add("DISPOSITION=NON-AUTHORITY OBSERVATION (FIRST_CHANCE_NOT_RETAINED)")
}
if (Test-Path $bc) {
  $lines.Add("---- CMD_BREADCRUMB_TAIL ----")
  $lines.AddRange([string[]](Get-Content $bc | Select-Object -Last 40))
  Copy-Item $bc (Join-Path $repoEv "CMD_BREADCRUMB.txt") -Force
}
$lines | Set-Content -Path $out -Encoding UTF8
$lines | ForEach-Object { Write-Host $_ }
Write-Host "WROTE $out"
if (-not (Test-Path $fc)) { exit 2 }
exit 0
