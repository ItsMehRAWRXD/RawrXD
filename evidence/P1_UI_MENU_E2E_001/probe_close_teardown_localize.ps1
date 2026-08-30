# Localize delayed fatal after WM_CLOSE (CLOSE_TEARDOWN FAIL / REOPENED).
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
$out = Join-Path $repoEv "CLOSE_TEARDOWN_LOCALIZE.txt"
New-Item -ItemType Directory -Force -Path $crumbDir,$repoEv | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue `
  "$crumbDir\CMD_BREADCRUMB.txt","$crumbDir\FIRST_CHANCE_WM_COMMAND.txt",`
  "$crumbDir\FIRST_CHANCE_JOURNAL.txt","$crumbDir\CMD_DIAG_ARMED.txt",$out

$sha = (Get-FileHash $ide -Algorithm SHA256).Hash
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $ide
$psi.WorkingDirectory = $bin
$psi.UseShellExecute = $false
$psi.EnvironmentVariables["RAWRXD_P1_UI_MENU_E2E"] = "1"
$psi.EnvironmentVariables["RAWRXD_P1_CMD_DIAG"] = "1"

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public class CloseLoc {
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
$lines.Add("P1_UI_MENU_E2E_001 CLOSE_TEARDOWN_LOCALIZE")
$lines.Add("SHA256=$sha")
$lines.Add("PID=$($proc.Id)")
$lines.Add("MODE=settle15s then WM_CLOSE; E2E=1 CMD_DIAG=1")
$lines.Add("TEARDOWN_EXONERATED=NO")

$main = [IntPtr]::Zero
for ($i = 0; $i -lt 120; $i++) {
  Start-Sleep -Seconds 1
  if ($proc.HasExited) {
    $lines.Add("EXIT_BEFORE_MAIN=$(FmtExit $proc.ExitCode)")
    break
  }
  $main = [CloseLoc]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { $lines.Add("MAIN=$main at_sec=$i"); break }
}
if ($main -eq [IntPtr]::Zero -and -not $proc.HasExited) { throw "NO_MAIN" }

if (-not $proc.HasExited) {
  $lines.Add("SETTLE_15S")
  for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 1
    if ($proc.HasExited) {
      $lines.Add("DIED_SETTLE_SEC=$i EXIT=$(FmtExit $proc.ExitCode)")
      break
    }
  }
}

if (-not $proc.HasExited) {
  $lines.Add("POST_WM_CLOSE")
  [void][CloseLoc]::PostMessageW($main, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
  if (-not $proc.WaitForExit(90000)) {
    $lines.Add("CLOSE_TIMEOUT_KILL")
    $proc.Kill()
    $proc.WaitForExit(15000) | Out-Null
  }
  $lines.Add("EXIT_AFTER_CLOSE=$(FmtExit $proc.ExitCode)")
}

$bc = Join-Path $crumbDir "CMD_BREADCRUMB.txt"
$fc = Join-Path $crumbDir "FIRST_CHANCE_WM_COMMAND.txt"
$fj = Join-Path $crumbDir "FIRST_CHANCE_JOURNAL.txt"
$lines.Add("FIRST_CHANCE=$(Test-Path $fc)")
$lines.Add("JOURNAL=$(Test-Path $fj)")

if (Test-Path $fc) {
  $lines.Add("---- FIRST_CHANCE ----")
  $lines.AddRange([string[]](Get-Content $fc))
}
if (Test-Path $fj) {
  $lines.Add("---- JOURNAL_LAST_MSG_CODES ----")
  $lines.AddRange([string[]](Select-String -Path $fj -Pattern "KIND=|EXCEPTION_CODE=|LAST_MSG=|TID=" | ForEach-Object { $_.Line } | Select-Object -Last 40))
}
if (Test-Path $bc) {
  $filt = @(Get-Content $bc | Where-Object {
    $_ -match 'CLOSE|DESTROY|NCDESTROY|onDestroy|ext_teardown|js_detach|webview|terminal|neutralize|agentic|VEH|SEH|winmain'
  })
  $lines.Add("---- CLOSE_PATH_CRUMBS ($($filt.Count)) ----")
  if ($filt.Count -gt 0) { $lines.AddRange([string[]]$filt) }
  $lines.Add("---- BREADCRUMB_TAIL ----")
  $lines.AddRange([string[]](Get-Content $bc | Select-Object -Last 30))
  Copy-Item $bc (Join-Path $repoEv "CMD_BREADCRUMB.txt") -Force
}
$ncd = $false
if (Test-Path $bc) { $ncd = (Select-String -Path $bc -Pattern "WM_NCDESTROY_AFTER_onDestroy" -Quiet) }
$lines.Add("NCDESTROY_COMPLETE=$ncd")
$hex = if ($lines[-1] -match 'EXIT.*=(0x[0-9A-Fa-f]+)') { $Matches[1] } else { "" }
# Prefer EXIT_AFTER_CLOSE line
foreach ($L in $lines) { if ($L -match 'EXIT_AFTER_CLOSE=(0x[0-9A-Fa-f]+)') { $hex = $Matches[1] } }
$bad = @('0xC0000005','0xC000041D','0xC0000409','0xC0000374') -contains $hex.ToUpper()
$lines.Add("CLOSE_TEARDOWN_PASS=$(-not $bad -and $ncd)")

$lines | Set-Content $out -Encoding UTF8
$lines | ForEach-Object { Write-Host $_ }
Write-Host "WROTE $out"
