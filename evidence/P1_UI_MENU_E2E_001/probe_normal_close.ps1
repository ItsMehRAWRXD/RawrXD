# Prove normal close: WM_CLOSE → process exit without 0xC0000005 / 0xC000041D
$ErrorActionPreference = 'Stop'
Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$bin = "F:\~dev\rawrxd\build-ninja\bin"
$ide = Join-Path $bin "RawrXD-Win32IDE.exe"
$repoEv = "F:\~dev\rawrxd\evidence\P1_UI_MENU_E2E_001"
$out = Join-Path $repoEv "NORMAL_CLOSE_PROOF.txt"
New-Item -ItemType Directory -Force -Path $repoEv | Out-Null

$crumbDir = Join-Path $bin "evidence\P1_UI_MENU_E2E_001"
Remove-Item -Force -ErrorAction SilentlyContinue `
  "$crumbDir\CMD_BREADCRUMB.txt","$crumbDir\FIRST_CHANCE_WM_COMMAND.txt",`
  "$crumbDir\FIRST_CHANCE_JOURNAL.txt","$crumbDir\CMD_DIAG_ARMED.txt"

$sha = (Get-FileHash $ide -Algorithm SHA256).Hash
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $ide
$psi.WorkingDirectory = $bin
$psi.UseShellExecute = $false
$psi.EnvironmentVariables["RAWRXD_P1_UI_MENU_E2E"] = "1"
$psi.EnvironmentVariables["RAWRXD_P1_CMD_DIAG"] = "1"

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public class CloseProbe {
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

$proc = [System.Diagnostics.Process]::Start($psi)
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("P1_UI_MENU_E2E_001 NORMAL_CLOSE_PROOF")
$lines.Add("SHA256=$sha")
$lines.Add("PID=$($proc.Id)")
$lines.Add("MODE=WM_CLOSE after settle E2E=1 CMD_DIAG=1")

$main = [IntPtr]::Zero
for ($i = 0; $i -lt 120; $i++) {
  Start-Sleep -Seconds 1
  if ($proc.HasExited) {
    $lines.Add("EXIT_BEFORE_MAIN=0x{0:X8}" -f ([uint32]$proc.ExitCode))
    break
  }
  $main = [CloseProbe]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { $lines.Add("MAIN=$main at_sec=$i"); break }
}
if ($main -eq [IntPtr]::Zero -and -not $proc.HasExited) {
  $lines.Add("NO_MAIN")
  $proc.Kill()
} elseif (-not $proc.HasExited) {
  for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 1
    if ($proc.HasExited) {
      $lines.Add("DIED_SETTLE_SEC=$i EXIT=0x{0:X8}" -f [uint32]([int]$proc.ExitCode))
      break
    }
  }
  if (-not $proc.HasExited) {
    $lines.Add("POST_WM_CLOSE")
    [void][CloseProbe]::PostMessageW($main, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) # WM_CLOSE
    $ok = $proc.WaitForExit(60000)
    if (-not $ok -and -not $proc.HasExited) {
      $lines.Add("CLOSE_TIMEOUT_KILL")
      $proc.Kill()
      $proc.WaitForExit(10000) | Out-Null
    }
    $raw = [int64]$proc.ExitCode
    $hex = ([Convert]::ToString(($raw -band [int64]0xFFFFFFFF), 16)).ToUpper()
    if ($hex.Length -gt 8) { $hex = $hex.Substring($hex.Length - 8) }
    $hex = $hex.PadLeft(8, '0')
    $lines.Add("EXIT=0x$hex")
    $bad = @('C0000005','C000041D','C0000409') -contains $hex
    $nc = ($lines -match 'WM_NCDESTROY_AFTER_onDestroy').Count -gt 0
    $lines.Add("NO_AV_OR_CALLBACK_FATAL=$(-not $bad)")
    $lines.Add("NCDESTROY_COMPLETE=$nc")
    $lines.Add("NORMAL_CLOSE_PASS=$(-not $bad -and $nc)")
  }
}

$crumb = Join-Path $bin "evidence\P1_UI_MENU_E2E_001\CMD_BREADCRUMB.txt"
$fc = Join-Path $bin "evidence\P1_UI_MENU_E2E_001\FIRST_CHANCE_WM_COMMAND.txt"
if (Test-Path $crumb) {
  $destroy = @(Get-Content $crumb | Where-Object { $_ -match "WM_DESTROY|WM_NCDESTROY|onDestroy|ext_teardown" } | ForEach-Object { [string]$_ })
  $lines.Add("DESTROY_CRUMBS=$($destroy.Count)")
  foreach ($d in $destroy) { $lines.Add($d) }
}
if (Test-Path $fc) {
  $lines.Add("---- FIRST_CHANCE ----")
  foreach ($x in @(Get-Content $fc | Select-Object -First 20 | ForEach-Object { [string]$_ })) { $lines.Add($x) }
} else {
  $lines.Add("FIRST_CHANCE=absent")
}
$lines | Set-Content $out -Encoding UTF8
$lines | ForEach-Object { Write-Host $_ }
Write-Host "WROTE $out"
