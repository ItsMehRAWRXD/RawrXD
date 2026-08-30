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
New-Item -ItemType Directory -Force -Path $crumbDir,$repoEv | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue `
  "$crumbDir\CMD_BREADCRUMB.txt","$crumbDir\FIRST_CHANCE_WM_COMMAND.txt",`
  "$crumbDir\COMMAND_FLIGHT.jsonl","$crumbDir\CMD_DIAG_ARMED.txt",`
  "$crumbDir\IDE_GETTEXT_INFLIGHT.txt"

# UseShellExecute=false so EnvironmentVariables are applied (Start-Process default can drop them).
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $ide
$psi.WorkingDirectory = $bin
$psi.UseShellExecute = $false
$psi.EnvironmentVariables["RAWRXD_P1_CMD_DIAG"] = "1"
$psi.EnvironmentVariables["RAWRXD_P1_UI_MENU_E2E"] = "1"

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public class CmdProbe2 {
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
Write-Host "PID=$($proc.Id) SHA=$sha"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 120; $i++) {
  Start-Sleep -Seconds 1
  if ($proc.HasExited) { throw "exit early $(FmtExit $proc.ExitCode)" }
  $main = [CmdProbe2]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
if ($main -eq [IntPtr]::Zero) { throw "NO_MAIN" }
Write-Host "MAIN=$main settle 10s"
Start-Sleep -Seconds 10

$armed = Join-Path $crumbDir "CMD_DIAG_ARMED.txt"
if (Test-Path $armed) {
  Write-Host "==== ARMED ===="
  Get-Content $armed
} else {
  Write-Host "NO_ARMED (diag env not seen by EXE or path write failed)"
}

Remove-Item -Force -ErrorAction SilentlyContinue "$crumbDir\CMD_BREADCRUMB.txt"
Write-Host "INVOKE WM_COMMAND id=1001 lParam=0"
[void][CmdProbe2]::SendMessageW($main, 0x0111, [IntPtr]1001, [IntPtr]::Zero)
Start-Sleep -Seconds 5

$alive = -not $proc.HasExited
Write-Host "PROCESS_ALIVE=$alive"
if (-not $alive) { Write-Host "EXIT=$(FmtExit $proc.ExitCode)" }

$bc = Join-Path $crumbDir "CMD_BREADCRUMB.txt"
$fc = Join-Path $crumbDir "FIRST_CHANCE_WM_COMMAND.txt"
$fl = Join-Path $crumbDir "COMMAND_FLIGHT.jsonl"
$ideInf = Join-Path $crumbDir "IDE_GETTEXT_INFLIGHT.txt"

if (Test-Path $ideInf) {
  Write-Host "==== IDE_GETTEXT_INFLIGHT (mid-crash retain) ===="
  Get-Content $ideInf
}

if (Test-Path $bc) {
  Write-Host "==== BREADCRUMB (id=1001 / fault) ===="
  Get-Content $bc | Where-Object { $_ -match 'id=1001|SEH|CXX|route|newFile|unified|FLIGHT|SWALLOWED|EDITOR' }
  Write-Host "==== BREADCRUMB_FULL_TAIL ===="
  Get-Content $bc | Select-Object -Last 40
} else { Write-Host "NO_BREADCRUMB" }

if (Test-Path $fc) {
  Write-Host "==== FIRST_CHANCE ===="
  Get-Content $fc
} else { Write-Host "NO_FIRST_CHANCE (NON-AUTHORITY if exit-only)" }

if (Test-Path $fl) {
  Write-Host "==== FLIGHT ===="
  Get-Content $fl | Select-Object -Last 8
} else { Write-Host "NO_FLIGHT" }

Copy-Item -Force "$crumbDir\*" $repoEv -ErrorAction SilentlyContinue
if ($alive) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
Write-Host DONE
