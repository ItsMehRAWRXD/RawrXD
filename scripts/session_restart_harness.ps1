# session_restart_harness.ps1 — 50-cycle native IDE restart acceptance (item 7).
# Launches the IDE N times, verifies startup + session persistence each cycle.
# GUI execution required; run on a desktop session. Exit non-zero on any failure.
param(
  [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
  [int]$Cycles = 50,
  [int]$StartupMs = 6000
)
$ErrorActionPreference = 'Stop'
if (!(Test-Path $Exe)) { Write-Host "FAIL: exe missing $Exe"; exit 2 }
$session = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
$pass = 0; $fail = 0
for ($i = 1; $i -le $Cycles; $i++) {
  $p = Start-Process -FilePath $Exe -PassThru
  Start-Sleep -Milliseconds $StartupMs
  if ($p.HasExited) { Write-Host "cycle $i: FAIL (exited early code=$($p.ExitCode))"; $fail++; continue }
  try { $p.Kill() } catch {}
  $ok = (Test-Path $session) -and ((Get-Item $session).Length -gt 0)
  if ($ok) { $pass++ } else { Write-Host "cycle $i: FAIL (no session)"; $fail++ }
}
Write-Host "SESSION_RESTART: $pass/$Cycles pass, $fail fail"
if ($fail -eq 0) { Write-Host "RESULT: PASS"; exit 0 } else { Write-Host "RESULT: FAIL"; exit 3 }