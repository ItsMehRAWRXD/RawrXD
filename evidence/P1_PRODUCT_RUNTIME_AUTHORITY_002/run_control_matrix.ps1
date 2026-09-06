# P1PRA control matrix: same E2E env/automation, two binaries, preserved artifacts.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$script = Join-Path $root 'run_e2e_product_authority.ps1'
$ninja = 'F:\~dev\rawrxd\build-ninja\bin\RawrXD-Win32IDE.exe'
$p1pra = 'F:\~dev\rawrxd\build_p1pra_win32ide\bin\RawrXD-Win32IDE.exe'
$dumpSrc = Join-Path $env:TEMP 'RawrXD_Dumps'
$runs = @(
  @{ Label = 'CONTROL_NINJA'; Exe = $ninja },
  @{ Label = 'CONTROL_P1PRA'; Exe = $p1pra }
)

function Stop-RawrIde {
  if ($env:RAWRXD_MATRIX_NO_KILL -eq '1' -or $env:RAWRXD_E2E_ATTACH -eq '1') {
    Write-Host 'matrix_skip_kill=1'
    return
  }
  Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 2
}

function Save-Artifacts {
  param([string]$Label, [int]$ExitCode, [string]$Transcript)
  $dest = Join-Path $root $Label
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  foreach ($name in @('RUN.log', 'WITNESS.log', 'E2E.log')) {
    $src = Join-Path $root $name
    if (Test-Path $src) { Copy-Item $src (Join-Path $dest $name) -Force }
  }
  Set-Content -Path (Join-Path $dest 'exit.code') -Value $ExitCode -NoNewline
  Set-Content -Path (Join-Path $dest 'RUN.transcript.log') -Value $Transcript
  if (Test-Path $dumpSrc) {
    $dumpDest = Join-Path $dest 'dumps'
    New-Item -ItemType Directory -Force -Path $dumpDest | Out-Null
    Get-ChildItem $dumpSrc -ErrorAction SilentlyContinue | Copy-Item -Destination $dumpDest -Force
  }
  Write-Host "artifacts_saved=$dest exit=$ExitCode"
}

Stop-RawrIde
$summary = @()

foreach ($r in $runs) {
  if (-not (Test-Path $r.Exe)) { throw "EXE missing: $($r.Exe)" }
  Stop-RawrIde
  if (Test-Path $dumpSrc) { Remove-Item $dumpSrc\* -Force -ErrorAction SilentlyContinue }
  $env:RAWRXD_E2E_EXE = $r.Exe
  Write-Host "===== $($r.Label) exe=$($r.Exe) ====="
  $transcript = New-Object System.Collections.Generic.List[string]
  $code = 1
  try {
    & $script 2>&1 | ForEach-Object {
      $line = $_.ToString()
      $transcript.Add($line)
      Write-Host $line
    }
    if ($null -ne $LASTEXITCODE) { $code = $LASTEXITCODE }
  } catch {
    $transcript.Add("MATRIX_CATCH=$($_.Exception.Message)")
    Write-Host "MATRIX_CATCH=$($_.Exception.Message)"
    $code = 1
  }
  Save-Artifacts -Label $r.Label -ExitCode $code -Transcript ($transcript -join "`n")
  $txt = $transcript -join "`n"
  $aliveNote = 'unknown'
  if ($txt -match 'IDE exited|IDE process exited|exit=-1073741819') { $aliveNote = 'crashed_or_exited' }
  elseif ($txt -match 'send_e2e_post') { $aliveNote = 'reached_send' }
  elseif ($txt -match 'model_status=') { $aliveNote = 'load_status_ok_harness_fail' }
  else { $aliveNote = 'harness_fail_no_load_status' }
  $summary += [pscustomobject]@{
    Label = $r.Label
    Exe = $r.Exe
    ExitCode = $code
    AliveNote = $aliveNote
  }
}

Remove-Item Env:RAWRXD_E2E_EXE -ErrorAction SilentlyContinue
Stop-RawrIde

$report = Join-Path $root 'CONTROL_MATRIX_SUMMARY.txt'
$summary | Format-Table -AutoSize | Out-String | Set-Content $report
Write-Host '===== CONTROL MATRIX SUMMARY ====='
$summary | Format-Table -AutoSize
Write-Host "report=$report"
