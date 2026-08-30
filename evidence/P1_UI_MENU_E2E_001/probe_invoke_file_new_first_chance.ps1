# Deterministic File→New invoke + first-chance capture (no relaunch loop).
$ErrorActionPreference = 'Stop'
Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$bin = "F:\~dev\rawrxd\build-ninja\bin"
$ide = Join-Path $bin "RawrXD-Win32IDE.exe"
$crumbDir = Join-Path $bin "evidence\P1_UI_MENU_E2E_001"
$repoEv = "F:\~dev\rawrxd\evidence\P1_UI_MENU_E2E_001"
$out = Join-Path $repoEv "INVOKE_FILE_NEW_FIRST_CHANCE.txt"
New-Item -ItemType Directory -Force -Path $crumbDir,$repoEv | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue `
  "$crumbDir\CMD_BREADCRUMB.txt","$crumbDir\FIRST_CHANCE_WM_COMMAND.txt",`
  "$crumbDir\COMMAND_FLIGHT.jsonl","$crumbDir\CMD_DIAG_ARMED.txt",$out

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $ide
$psi.WorkingDirectory = $bin
$psi.UseShellExecute = $false
$psi.EnvironmentVariables["RAWRXD_P1_CMD_DIAG"] = "1"

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public class InvProbe {
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

$sha = (Get-FileHash $ide -Algorithm SHA256).Hash
$proc = [System.Diagnostics.Process]::Start($psi)
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("P1_UI_MENU_E2E_001 INVOKE_FILE_NEW_FIRST_CHANCE")
$lines.Add("PID=$($proc.Id)")
$lines.Add("SHA256=$sha")
$lines.Add("CMD=1001 FileNew lParam=0")

$main = [IntPtr]::Zero
for ($i = 0; $i -lt 120; $i++) {
  Start-Sleep -Seconds 1
  if ($proc.HasExited) {
    $lines.Add("EXIT_BEFORE_MAIN=0x{0:X8}" -f ([uint32]$proc.ExitCode))
    break
  }
  $main = [InvProbe]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { $lines.Add("MAIN=$main at_sec=$i"); break }
}
if ($main -eq [IntPtr]::Zero -and -not $proc.HasExited) {
  $lines.Add("NO_MAIN")
  $proc.Kill()
} elseif (-not $proc.HasExited) {
  $lines.Add("SETTLE_12S")
  for ($i = 0; $i -lt 12; $i++) {
    Start-Sleep -Seconds 1
    if ($proc.HasExited) {
      $lines.Add("DIED_SETTLE_SEC=$i EXIT=0x{0:X8}" -f ([uint32]$proc.ExitCode))
      break
    }
  }
  if (-not $proc.HasExited) {
    # Clear crumbs so post-invoke trail is clean; keep FIRST_CHANCE if settle fault already wrote.
    Remove-Item -Force -ErrorAction SilentlyContinue "$crumbDir\CMD_BREADCRUMB.txt"
    $lines.Add("INVOKE_SENDMESSAGE_1001")
    [void][InvProbe]::SendMessageW($main, 0x0111, [IntPtr]1001, [IntPtr]::Zero)
    Start-Sleep -Seconds 5
    if ($proc.HasExited) {
      $lines.Add("DIED_AFTER_INVOKE EXIT=0x{0:X8}" -f ([uint32]$proc.ExitCode))
    } else {
      $lines.Add("ALIVE_AFTER_INVOKE=1")
      $proc.Kill()
      $proc.WaitForExit(5000) | Out-Null
    }
  }
}

$fc = Join-Path $crumbDir "FIRST_CHANCE_WM_COMMAND.txt"
$bc = Join-Path $crumbDir "CMD_BREADCRUMB.txt"
$armed = Join-Path $crumbDir "CMD_DIAG_ARMED.txt"
$lines.Add("ARMED=$(Test-Path $armed)")
$lines.Add("FIRST_CHANCE_PRESENT=$(Test-Path $fc)")
if (Test-Path $armed) {
  $lines.Add("---- ARMED ----")
  $lines.AddRange([string[]](Get-Content $armed))
}
if (Test-Path $fc) {
  $lines.Add("---- FIRST_CHANCE ----")
  $lines.AddRange([string[]](Get-Content $fc))
  Copy-Item $fc (Join-Path $repoEv "FIRST_CHANCE_WM_COMMAND.txt") -Force
} else {
  $lines.Add("---- FIRST_CHANCE ----")
  $lines.Add("(none)")
}
if (Test-Path $bc) {
  $lines.Add("---- BREADCRUMB ----")
  $lines.AddRange([string[]](Get-Content $bc))
  Copy-Item $bc (Join-Path $repoEv "CMD_BREADCRUMB.txt") -Force
}
$lines | Set-Content -Path $out -Encoding UTF8
$lines | ForEach-Object { Write-Host $_ }
Write-Host "WROTE $out"
