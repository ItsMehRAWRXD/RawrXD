# Settle-path IDE sender proof â€” no repair.
# Expect: IDE_SB_GETTEXTW_OWNER.txt tags runUiEncodingProbe*; CERT_READSTATUS0 absent at settle.
$ErrorActionPreference = 'Stop'
function FmtExit([int]$ec) {
  $bytes = [BitConverter]::GetBytes($ec)
  return ('0x{0:X8}' -f [BitConverter]::ToUInt32($bytes, 0))
}' -f $u
}
Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$bin = "F:\~dev\rawrxd\build-ninja\bin"
$ide = Join-Path $bin "RawrXD-Win32IDE.exe"
$repo = "F:\~dev\rawrxd\evidence\P1_UI_MENU_E2E_001"
$diag = Join-Path $bin "evidence\P1_UI_MENU_E2E_001"
New-Item -ItemType Directory -Force -Path $diag,$repo | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue `
  "$diag\IDE_GETTEXT_INFLIGHT.txt","$diag\CERT_READSTATUS0_INFLIGHT.txt",`
  "$diag\IDE_SB_GETTEXTW_OWNER.txt","$diag\FIRST_CHANCE_WM_COMMAND.txt",`
  "$diag\CMD_BREADCRUMB.txt","$diag\IDE_SB_GETTEXTW_ENTRY.txt","$diag\CMD_DIAG_ARMED.txt"

$sha = (Get-FileHash $ide -Algorithm SHA256).Hash
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $ide
$psi.WorkingDirectory = $bin
$psi.UseShellExecute = $false
$psi.EnvironmentVariables["RAWRXD_P1_CMD_DIAG"] = "1"
$psi.EnvironmentVariables["RAWRXD_P1_UI_MENU_E2E"] = "1"

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public class SettleOwner {
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
$lines.Add("P1_UI_MENU_E2E_001 SETTLE_IDE_SENDER_PROOF")
$lines.Add("SHA256=$sha")
$lines.Add("PID=$($proc.Id)")
$lines.Add("MODE=CMD_DIAG=1 E2E=1 settle25s then File.New wait40s NO_CERT_READSTATUS0")
$lines.Add("REPAIR=NOT_STARTED")

$main = [IntPtr]::Zero
for ($i = 0; $i -lt 90; $i++) {
  Start-Sleep -Seconds 1
  if ($proc.HasExited) { $lines.Add("EXIT_BEFORE_MAIN=$(FmtExit $proc.ExitCode)"); break }
  $main = [SettleOwner]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { $lines.Add("MAIN=$main at_sec=$i"); break }
}
if ($main -eq [IntPtr]::Zero -and -not $proc.HasExited) { throw "NO_MAIN" }

# Settle window â€” encoding probe runs at PS panel create (startup).
if (-not $proc.HasExited) {
  $lines.Add("SETTLE_25S")
  for ($i = 0; $i -lt 25; $i++) {
    Start-Sleep -Seconds 1
    if ($proc.HasExited) {
      $lines.Add("DIED_SETTLE_SEC=$i EXIT=$(FmtExit $proc.ExitCode)")
      break
    }
  }
}

$owner = Join-Path $diag "IDE_SB_GETTEXTW_OWNER.txt"
$ideInf = Join-Path $diag "IDE_GETTEXT_INFLIGHT.txt"
$certInf = Join-Path $diag "CERT_READSTATUS0_INFLIGHT.txt"
$lines.Add("POST_SETTLE_OWNER_LOG=$(Test-Path $owner)")
$lines.Add("POST_SETTLE_IDE_INFLIGHT=$(Test-Path $ideInf)")
$lines.Add("POST_SETTLE_CERT_INFLIGHT=$(Test-Path $certInf)")
if (Test-Path $owner) {
  $lines.Add("==== IDE_SB_GETTEXTW_OWNER (settle) ====")
  $lines.AddRange([string[]](Get-Content $owner))
  Copy-Item $owner (Join-Path $repo "IDE_SB_GETTEXTW_OWNER.txt") -Force
}

if (-not $proc.HasExited) {
  $lines.Add("INVOKE File.New id=1001")
  [void][SettleOwner]::SendMessageW($main, 0x0111, [IntPtr]1001, [IntPtr]::Zero)
  $lines.Add("AFTER_FILENEW_ALIVE=$(-not $proc.HasExited)")
  for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Seconds 1
    if ($proc.HasExited) {
      $lines.Add("DIED_AFTER_FILENEW_SEC=$i EXIT=$(FmtExit $proc.ExitCode)")
      break
    }
  }
  if (-not $proc.HasExited) {
    $lines.Add("STILL_ALIVE_AFTER_40S")
    $proc.Kill()
    $proc.WaitForExit(10000) | Out-Null
    $lines.Add("KILLED_CLEANUP EXIT=$(FmtExit $proc.ExitCode)")
  }
}

$fc = Join-Path $diag "FIRST_CHANCE_WM_COMMAND.txt"
$lines.Add("FIRST_CHANCE=$(Test-Path $fc)")
$lines.Add("FATAL_IDE_INFLIGHT=$(Test-Path $ideInf)")
$lines.Add("FATAL_CERT_INFLIGHT=$(Test-Path $certInf)")
if (Test-Path $fc) {
  $lines.Add("==== FIRST_CHANCE ====")
  $lines.AddRange([string[]](Get-Content $fc))
  Copy-Item $fc (Join-Path $repo "FIRST_CHANCE_WM_COMMAND.txt") -Force
}
if (Test-Path $owner) {
  Copy-Item $owner (Join-Path $repo "IDE_SB_GETTEXTW_OWNER.txt") -Force
}
$bc = Join-Path $diag "CMD_BREADCRUMB.txt"
if (Test-Path $bc) {
  $lines.Add("==== CRUMBS probe/panel ====")
  $filt = @(Get-Content $bc | Where-Object {
    $_ -match 'runUiEncoding|initializePowerShell|showPowerShell|newFile_|VEH|GETTEXT'
  })
  if ($filt.Count -gt 0) { $lines.AddRange([string[]]$filt) }
  Copy-Item $bc (Join-Path $repo "CMD_BREADCRUMB.txt") -Force
}

$out = Join-Path $repo "SETTLE_IDE_SENDER_PROOF.txt"
$lines | Set-Content $out -Encoding UTF8
$lines | ForEach-Object { Write-Host $_ }
Write-Host "WROTE $out"
