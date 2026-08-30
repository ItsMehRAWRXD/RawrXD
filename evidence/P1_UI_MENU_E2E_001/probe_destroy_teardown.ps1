function FmtExit([int]$ec) {
  $bytes = [BitConverter]::GetBytes($ec)
  return ('0x{0:X8}' -f [BitConverter]::ToUInt32($bytes, 0))
}
$ErrorActionPreference = 'Stop'
Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
$bin = "F:\~dev\rawrxd\build-ninja\bin"
$ide = Join-Path $bin "RawrXD-Win32IDE.exe"
$crumbDir = Join-Path $bin "evidence\P1_UI_MENU_E2E_001"
$repoEv = "F:\~dev\rawrxd\evidence\P1_UI_MENU_E2E_001"
$out = Join-Path $repoEv "DESTROY_TEARDOWN.txt"
New-Item -ItemType Directory -Force -Path $crumbDir,$repoEv | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue `
  "$crumbDir\CMD_BREADCRUMB.txt","$crumbDir\FIRST_CHANCE_WM_COMMAND.txt",`
  "$crumbDir\FIRST_CHANCE_JOURNAL.txt","$crumbDir\CMD_DIAG_ARMED.txt",$out
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $ide
$psi.WorkingDirectory = $bin
$psi.UseShellExecute = $false
$psi.EnvironmentVariables["RAWRXD_P1_CMD_DIAG"] = "1"
$psi.EnvironmentVariables["RAWRXD_P1_UI_MENU_E2E"] = "1"
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public class DestroyProbe {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
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
$lines.Add("P1_UI_MENU_E2E_001 DESTROY_TEARDOWN")
$lines.Add("SHA256=$sha")
$lines.Add("PID=$($proc.Id)")
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 120; $i++) {
  Start-Sleep -Seconds 1
  if ($proc.HasExited) { $lines.Add("EXIT_BEFORE_MAIN=$(FmtExit $proc.ExitCode)"); break }
  $main = [DestroyProbe]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { $lines.Add("MAIN=$main at_sec=$i"); break }
}
if ($main -eq [IntPtr]::Zero -and -not $proc.HasExited) { throw "NO_MAIN" }
if (-not $proc.HasExited) {
  $lines.Add("SETTLE_10S")
  Start-Sleep -Seconds 10
  if ($proc.HasExited) {
    $lines.Add("DIED_DURING_SETTLE EXIT=$(FmtExit $proc.ExitCode)")
  } else {
    $lines.Add("INVOKE WM_CLOSE")
    [void][DestroyProbe]::PostMessageW($main, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($proc.WaitForExit(30000)) {
      $lines.Add("EXIT_AFTER_CLOSE=$(FmtExit $proc.ExitCode)")
    } else {
      $lines.Add("CLOSE_TIMEOUT_KILL")
      $proc.Kill()
      $proc.WaitForExit(5000) | Out-Null
      $lines.Add("EXIT_AFTER_KILL=$(FmtExit $proc.ExitCode)")
    }
  }
}
$bc = Join-Path $crumbDir "CMD_BREADCRUMB.txt"
$fc = Join-Path $crumbDir "FIRST_CHANCE_WM_COMMAND.txt"
$fj = Join-Path $crumbDir "FIRST_CHANCE_JOURNAL.txt"
$lines.Add("FIRST_CHANCE=$(Test-Path $fc)")
$lines.Add("JOURNAL=$(Test-Path $fj)")
if (Test-Path $fc) { $lines.Add("---- FIRST_CHANCE ----"); $lines.AddRange([string[]](Get-Content $fc)) }
if (Test-Path $fj) { $lines.Add("---- JOURNAL_TAIL ----"); $lines.AddRange([string[]](Get-Content $fj | Select-Object -Last 40)) }
if (Test-Path $bc) {
  $lines.Add("---- BREADCRUMB_DESTROY ----")
  $filt = @(Get-Content $bc | Where-Object { $_ -match 'CLOSE|Destroy|ext_teardown|js_hosts|ExtensionLoader|WM_DESTROY|SEH|CXX|VEH' })
  if ($filt.Count -gt 0) { $lines.AddRange([string[]]$filt) }
  $lines.Add("---- BREADCRUMB_TAIL ----")
  $lines.AddRange([string[]](Get-Content $bc | Select-Object -Last 25))
  Copy-Item $bc (Join-Path $repoEv "CMD_BREADCRUMB.txt") -Force
}
$lines | Set-Content -Path $out -Encoding UTF8
$lines | ForEach-Object { Write-Host $_ }
Write-Host "WROTE $out"
