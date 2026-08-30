# P1_UI_MENU_E2E_001 â€” settle first-chance retain (signed-exit + mandatory FC)
# Localization only. Requires FIRST_CHANCE_WM_COMMAND.txt or fails closed.
# Optional: attach cdb with sxe av / eh / 0xC0000374 when Debuggers kit is present.
$ErrorActionPreference = 'Stop'

function FmtExit([int]$ec) {
  $bytes = [BitConverter]::GetBytes($ec)
  return ('0x{0:X8}' -f [BitConverter]::ToUInt32($bytes, 0))
}' -f $u)
}

function Find-Cdb {
  $candidates = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\cdb.exe",
    "${env:ProgramFiles}\Windows Kits\10\Debuggers\x64\cdb.exe"
  )
  foreach ($c in $candidates) {
    if (Test-Path -LiteralPath $c) { return $c }
  }
  $hit = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers" -Recurse -Filter cdb.exe -EA SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName
  if ($hit) { return $hit }
  return $null
}

Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$bin = "F:\~dev\rawrxd\build-ninja\bin"
$ide = Join-Path $bin "RawrXD-Win32IDE.exe"
$crumbDir = Join-Path $bin "evidence\P1_UI_MENU_E2E_001"
$repoEv = "F:\~dev\rawrxd\evidence\P1_UI_MENU_E2E_001"
$out = Join-Path $repoEv "SETTLE_FIRST_CHANCE_RETAIN.txt"
New-Item -ItemType Directory -Force -Path $crumbDir,$repoEv | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue `
  "$crumbDir\CMD_BREADCRUMB.txt","$crumbDir\FIRST_CHANCE_WM_COMMAND.txt",`
  "$crumbDir\FIRST_CHANCE_JOURNAL.txt","$crumbDir\CMD_DIAG_ARMED.txt",`
  "$crumbDir\IDE_GETTEXT_INFLIGHT.txt","$crumbDir\CERT_READSTATUS0_INFLIGHT.txt",`
  "$crumbDir\IDE_SB_GETTEXTW_OWNER.txt",$out

$cdb = Find-Cdb
$sha = (Get-FileHash $ide -Algorithm SHA256).Hash
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("P1_UI_MENU_E2E_001 SETTLE_FIRST_CHANCE_RETAIN")
$lines.Add("SHA256=$sha")
$lines.Add("MODE=settle_only_mandatory_first_chance")
$lines.Add("CDB=$(if ($cdb) { $cdb } else { 'ABSENT â€” VEH-only retain' })")

if ($cdb) {
  $scriptPath = Join-Path $env:TEMP "rawrxd_p1_settle_fc.cdb"
  @"
sxe av
sxe eh
sxe -c ".printf `"FIRST_CHANCE_HEAP_OR_FAIL\n`"; .exr -1; kb; .logopen /t `"$($crumbDir -replace '\\','\\')\\CDB_FIRST_CHANCE.txt`"; .logclose; q" 0xC0000374
g
"@ | Set-Content -Path $scriptPath -Encoding ASCII
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $cdb
  $psi.Arguments = "-g -G -c `"`$`$<$scriptPath`" `"$ide`""
  $psi.WorkingDirectory = $bin
  $psi.UseShellExecute = $false
  $psi.EnvironmentVariables["RAWRXD_P1_CMD_DIAG"] = "1"
  $psi.EnvironmentVariables["RAWRXD_P1_UI_MENU_E2E"] = "1"
  $proc = [System.Diagnostics.Process]::Start($psi)
  $lines.Add("LAUNCH=cdb PID=$($proc.Id)")
} else {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $ide
  $psi.WorkingDirectory = $bin
  $psi.UseShellExecute = $false
  $psi.EnvironmentVariables["RAWRXD_P1_CMD_DIAG"] = "1"
  $psi.EnvironmentVariables["RAWRXD_P1_UI_MENU_E2E"] = "1"
  $proc = [System.Diagnostics.Process]::Start($psi)
  $lines.Add("LAUNCH=direct PID=$($proc.Id)")
}

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public class SettleRetainProbe {
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

$main = [IntPtr]::Zero
$mainAt = -1
for ($i = 0; $i -lt 120; $i++) {
  Start-Sleep -Seconds 1
  if ($proc.HasExited) {
    $lines.Add("EXIT_BEFORE_MAIN=$(FmtExit $proc.ExitCode)")
    break
  }
  # Under cdb, child IDE PID may differ â€” scan by class only after exit check.
  $main = [SettleRetainProbe]::FindMain([uint32]$proc.Id)
  if ($main -eq [IntPtr]::Zero) {
    # Best-effort: any visible IDE main (cdb parent case).
    $main = [SettleRetainProbe]::FindMain(0)
  }
  if ($main -ne [IntPtr]::Zero) { $mainAt = $i; break }
}
$lines.Add("MAIN=$main at_sec=$mainAt")

if (-not $proc.HasExited) {
  for ($i = 0; $i -lt 45; $i++) {
    Start-Sleep -Seconds 1
    if ($proc.HasExited) {
      $lines.Add("DIED_DURING_SETTLE_AT_SEC=$i EXIT=$(FmtExit $proc.ExitCode)")
      break
    }
  }
}
if (-not $proc.HasExited) {
  $lines.Add("SETTLE_ALIVE_AFTER_45S=1")
  try { $proc.Kill() } catch {}
  $proc.WaitForExit(8000) | Out-Null
  $lines.Add("KILLED_AFTER_WAIT EXIT=$(FmtExit $proc.ExitCode)")
} elseif ($lines -notmatch 'EXIT=') {
  $lines.Add("EXIT=$(FmtExit $proc.ExitCode)")
}

$fc = Join-Path $crumbDir "FIRST_CHANCE_WM_COMMAND.txt"
$ideInf = Join-Path $crumbDir "IDE_GETTEXT_INFLIGHT.txt"
$certInf = Join-Path $crumbDir "CERT_READSTATUS0_INFLIGHT.txt"
$owner = Join-Path $crumbDir "IDE_SB_GETTEXTW_OWNER.txt"
$cdbFc = Join-Path $crumbDir "CDB_FIRST_CHANCE.txt"

$fcPresent = Test-Path $fc
$lines.Add("FIRST_CHANCE_PRESENT=$fcPresent")
$lines.Add("IDE_GETTEXT_INFLIGHT_PRESENT=$(Test-Path $ideInf)")
$lines.Add("CERT_READSTATUS0_INFLIGHT_PRESENT=$(Test-Path $certInf)")
$lines.Add("IDE_OWNER_LOG_PRESENT=$(Test-Path $owner)")
$lines.Add("CDB_LOG_PRESENT=$(Test-Path $cdbFc)")

if (Test-Path $ideInf) {
  $lines.Add("---- IDE_GETTEXT_INFLIGHT ----")
  $lines.AddRange([string[]](Get-Content $ideInf))
}
if (Test-Path $fc) {
  $lines.Add("---- FIRST_CHANCE_WM_COMMAND ----")
  $lines.AddRange([string[]](Get-Content $fc))
  Copy-Item $fc (Join-Path $repoEv "FIRST_CHANCE_WM_COMMAND.txt") -Force
}
if (Test-Path $owner) {
  Copy-Item $owner (Join-Path $repoEv "IDE_SB_GETTEXTW_OWNER.txt") -Force
  $lines.Add("---- IDE_SB_GETTEXTW_OWNER_TAIL ----")
  $lines.AddRange([string[]](Get-Content $owner | Select-Object -Last 20))
}
if (Test-Path $cdbFc) {
  Copy-Item $cdbFc $repoEv -Force
}

if (-not $fcPresent -and -not (Test-Path $cdbFc)) {
  $lines.Add("GATE_NOTE=FIRST_CHANCE_NOT_RETAINED â€” observation non-authority")
  $lines.Add("DISPOSITION=NON-AUTHORITY OBSERVATION")
} else {
  $lines.Add("GATE_NOTE=FIRST_CHANCE_RETAINED â€” correlate IDE_GETTEXT_INFLIGHT before promote")
}

$lines | Set-Content -Path $out -Encoding UTF8
$lines | ForEach-Object { Write-Host $_ }
Write-Host "WROTE $out"
if (-not $fcPresent -and -not (Test-Path $cdbFc)) { exit 2 }
exit 0
