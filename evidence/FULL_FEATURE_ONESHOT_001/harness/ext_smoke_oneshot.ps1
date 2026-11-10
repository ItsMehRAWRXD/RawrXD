param(
  [Parameter(Mandatory=$true)][string]$TipExe,
  [string]$EvidenceRoot = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001",
  [string]$ExtEvidence = "F:\rawrxd\evidence\FULL_FEATURE_EXTENSIONHOST_001"
)
$ErrorActionPreference = "Continue"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runlog = Join-Path $ExtEvidence "logs\ext_smoke_run_$stamp.txt"
$receipt = Join-Path $EvidenceRoot "artifacts\ext_runtime_receipt.txt"
$summary = Join-Path $EvidenceRoot "artifacts\ext_smoke_summary_$stamp.json"
$fixture = Join-Path $EvidenceRoot "fixtures\ext_hello"
$malformed = Join-Path $EvidenceRoot "fixtures\ext_malformed"
$a4f = "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe"
New-Item -ItemType Directory -Force -Path (Split-Path $runlog),(Split-Path $receipt) | Out-Null

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}

$sha = (Get-FileHash $TipExe -Algorithm SHA256).Hash
$a4fSha = (Get-FileHash $a4f -Algorithm SHA256).Hash
Log "=== EXT SMOKE tip $sha ==="
Log "TIP_EXE=$TipExe"
Log "TIP_SHA256=$sha"
Log "FROZEN_A4F=$a4fSha"
Log "FROZEN_A4F_UNTOUCHED=$($a4fSha -eq 'A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E')"
Log "FIXTURE=$fixture"

Get-Process -Name "RawrXD-Win32IDE-Native*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 1
Remove-Item $receipt -Force -ErrorAction SilentlyContinue

$argsA = @("--ext-dir", $fixture, "--ext-cmd", "extHello.ping", "--ext-quit")
Log "SMOKE_A_ARGS=$($argsA -join ' ')"
$p = Start-Process -FilePath $TipExe -ArgumentList $argsA -PassThru -WindowStyle Minimized
Log "SMOKE_A_PID=$($p.Id)"
$hwnd = 0
for ($i=0; $i -lt 40; $i++) {
  Start-Sleep -Milliseconds 250
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { break }
  if ($p.MainWindowHandle -ne 0) { $hwnd = $p.MainWindowHandle; break }
}
if (-not $p.HasExited) {
  $p.WaitForExit(20000) | Out-Null
  if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; $force=1 } else { $force=0 }
} else { $force=0 }
Log "SMOKE_A_EXIT=$($p.ExitCode) FORCE_KILL=$force HWND=0x$('{0:X}' -f $hwnd)"
Log "--- RECEIPT_A ---"
if (Test-Path $receipt) { Get-Content $receipt | ForEach-Object { Log $_ } } else { Log "RECEIPT_MISSING" }

$recA = @{}
if (Test-Path $receipt) {
  Get-Content $receipt | ForEach-Object {
    if ($_ -match '^(.*?)=(.*)$') { $recA[$matches[1]] = $matches[2] }
  }
}

Start-Sleep 1
Remove-Item $receipt -Force -ErrorAction SilentlyContinue
$argsB = @("--ext-malformed", $malformed, "--ext-quit")
Log "SMOKE_B_ARGS=$($argsB -join ' ')"
$p2 = Start-Process -FilePath $TipExe -ArgumentList $argsB -PassThru -WindowStyle Minimized
$p2.WaitForExit(20000) | Out-Null
if (-not $p2.HasExited) { Stop-Process -Id $p2.Id -Force -ErrorAction SilentlyContinue }
Log "SMOKE_B_EXIT=$($p2.ExitCode)"
Log "--- RECEIPT_B ---"
$recB = @{}
if (Test-Path $receipt) {
  Get-Content $receipt | ForEach-Object {
    Log $_
    if ($_ -match '^(.*?)=(.*)$') { $recB[$matches[1]] = $matches[2] }
  }
}

$orphans = @(Get-Process -Name "RawrXD-Win32IDE-Native*" -ErrorAction SilentlyContinue).Count
Log "ORPHANS=$orphans"
$pass = ($recA['INIT_OK'] -eq '1' -and $recA['LOAD_OK'] -eq '1' -and $recA['ACTIVATE_OK'] -eq '1' -and $recA['CMD_OK'] -eq '1' -and $p.ExitCode -eq 0)
$malOk = ($recB['FAULT_ISOLATED'] -eq '1')
Log "=== DISPOSITION ==="
Log "EXT_LOAD=$(if($pass){'PASS'}else{'FAIL'}) INIT_OK=$($recA['INIT_OK']) LOAD_OK=$($recA['LOAD_OK']) ACTIVATE_OK=$($recA['ACTIVATE_OK']) CMD_OK=$($recA['CMD_OK'])"
Log "DEACTIVATE_OK=$($recA['DEACTIVATE_OK']) RELOAD_OK=$($recA['RELOAD_OK'])"
Log "MALFORMED_FAULT=$($recB['FAULT_ISOLATED'])"
Log "PROMOTE=0"
@{
  tip_sha = $sha
  ext_load = $(if($pass){'PASS'}else{'FAIL'})
  init = $recA['INIT_OK']; load = $recA['LOAD_OK']; activate = $recA['ACTIVATE_OK']; cmd = $recA['CMD_OK']
  deactivate = $recA['DEACTIVATE_OK']; reload = $recA['RELOAD_OK']
  malformed_fault = $recB['FAULT_ISOLATED']
  runlog = $runlog
  a4f_untouched = ($a4fSha -eq 'A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E')
  promote = 0
} | ConvertTo-Json | Set-Content $summary
Write-Host "SUMMARY=$summary"
exit $(if($pass -and $malOk){0}else{1})
