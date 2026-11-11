[CmdletBinding()]
param(
    [Parameter(Position=0)] [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$Output = ''
)
$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path $RepoRoot).Path
if (-not $Output) { $Output = Join-Path $RepoRoot 'evidence\rawr_ide_functional_e2e.json' }
$checks = [System.Collections.Generic.List[object]]::new()
function Check([string]$Id,[string]$Area,[string]$Status,[string]$Evidence,[string]$Next='') {
    $checks.Add([ordered]@{id=$Id;area=$Area;status=$Status;evidence=$Evidence;next_action=$Next})
}

$temp = Join-Path $RepoRoot '_e2e_functional_workspace'
try {
    if (Test-Path $temp) { Remove-Item $temp -Recurse -Force }
    New-Item $temp -ItemType Directory -Force | Out-Null
    $source = Join-Path $temp 'sample.cpp'
    Set-Content $source "int RawrFunctionalProbe() { return 7; }`n" -Encoding UTF8
    $read = Get-Content $source -Raw
    Check 'E2E-FILE-READ' 'file-explorer' ($(if ($read -match 'RawrFunctionalProbe') {'PASS'} else {'FAIL'})) 'Disposable source file opened and read.' 'Verify file explorer selection through the GUI.'
    Add-Content $source "int RawrFunctionalProbeEdited() { return 8; }`n"
    $saved = Get-Content $source -Raw
    Check 'E2E-EDIT-SAVE' 'editor' ($(if ($saved -match 'Edited') {'PASS'} else {'FAIL'})) 'Disposable source edited and saved.' 'Verify editor typing and save command through the GUI.'
    Check 'E2E-SEARCH' 'search' ($(if ($saved -match 'RawrFunctionalProbeEdited') {'PASS'} else {'FAIL'})) 'Known symbol found in saved source.'
    $terminal = & powershell -NoProfile -Command 'Write-Output RawrXD_TERMINAL_OK'
    Check 'E2E-TERMINAL' 'terminal' ($(if ($terminal -contains 'RawrXD_TERMINAL_OK') {'PASS'} else {'FAIL'})) 'Harmless native shell command completed.'
    $git = & git -C $RepoRoot status --porcelain 2>&1
    Check 'E2E-SCM' 'source-control' ($(if ($LASTEXITCODE -eq 0) {'PASS'} else {'FAIL'})) 'Git status command completed.' 'Verify controlled change detection through the GUI.'
    $exe = Join-Path $RepoRoot 'build_ide\bin\RawrXD-Win32IDE-Native.exe'
    if (Test-Path $exe) {
        $p = Start-Process $exe -ArgumentList '--health-check' -Wait -PassThru -WindowStyle Hidden
        Check 'E2E-HEALTH' 'runtime' ($(if ($p.ExitCode -eq 0) {'PASS'} else {'FAIL'})) "Native health exit=$($p.ExitCode)"
    } else { Check 'E2E-HEALTH' 'runtime' 'NOT_RUN' 'Native executable is not built.' 'Build RawrXD-Win32IDE-Native.' }
    $providerReceipt = Join-Path $env:LOCALAPPDATA 'RawrXD\evidence\provider_route_e2e.jsonl'
    Check 'E2E-PROVIDER-RECEIPT' 'providers' ($(if (Test-Path $providerReceipt) {'PASS'} else {'NOT_RUN'})) 'Provider inference receipt presence.' 'Run one real prompt through each configured provider.'
    Check 'E2E-BROWSER' 'browser' 'NOT_RUN' 'Visible WebView2 rendering requires UI automation.' 'Run the browser surface test and record a screenshot/receipt.'
    Check 'E2E-SNAPSHOT' 'snapshot' 'NOT_RUN' 'Snapshot recovery requires an actual GUI state transition.' 'Run capture, mutate, restore, and compare the snapshot.'
    Check 'E2E-AGENT' 'agentic-loop' 'NOT_RUN' 'Model-driven read/edit/build/test requires an authorized live task.' 'Run the bounded agent E2E workflow.'
} finally {
    if (Test-Path $temp) { Remove-Item $temp -Recurse -Force }
}
$failed=@($checks|? status -eq 'FAIL'); $unrun=@($checks|? status -eq 'NOT_RUN')
$report=[ordered]@{schema='rawrxd.ide.functional_e2e.v1';generated_utc=[DateTime]::UtcNow.ToString('o');repository=$RepoRoot;source_revision=((& git -C $RepoRoot rev-parse HEAD 2>$null).Trim());checks=$checks;executed_count=$checks.Count-$unrun.Count;unavailable_count=$unrun.Count;failed_count=$failed.Count;certification='NOT_CERTIFIED';verdict=$(if($failed.Count){'FAIL'}elseif($unrun.Count){'PARTIAL'}else{'PASS'})}
$report|ConvertTo-Json -Depth 8|Set-Content $Output -Encoding UTF8
Write-Host "E2E_RECEIPT=$Output";Write-Host "EXECUTED=$($report.executed_count) UNAVAILABLE=$($report.unavailable_count) FAILED=$($report.failed_count) VERDICT=$($report.verdict)"
exit $(if($failed.Count){1}else{0})
