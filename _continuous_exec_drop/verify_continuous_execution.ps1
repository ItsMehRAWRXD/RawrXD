param(
    [Parameter(Mandatory=$false)]
    [string]$Root = "."
)

$ErrorActionPreference = "Stop"

$source = Get-ChildItem -Path $Root -Recurse -File -Include *.cpp,*.c,*.hpp,*.h |
    Where-Object {
        $_.FullName -notmatch '\\build\\|\\out\\|\\third_party\\|\\external\\'
    }

$forbiddenControl = @(
    'Sleep\s*\(',
    'sleep_for\s*\(',
    'sleep_until\s*\(',
    '\.wait_for\s*\(',
    '\.wait_until\s*\(',
    'GetTickCount(?:64)?\s*\(',
    'SetTimer\s*\('
)

$hits = @()
foreach ($pattern in $forbiddenControl) {
    $hits += $source | Select-String -Pattern $pattern
}

# QueryPerformanceCounter is allowed for telemetry/measurement, but not as a
# predicate controlling generation. Flag nearby suspicious branches for review.
$qpc = $source | Select-String -Pattern 'QueryPerformanceCounter\s*\(' -Context 4,4
foreach ($m in $qpc) {
    $window = (($m.Context.PreContext + $m.Line + $m.Context.PostContext) -join "`n")
    if ($window -match '\b(if|while|return|break|cancel|stop|timeout|deadline)\b') {
        $hits += $m
    }
}

# Scheduler budget must not silently terminate a started decode.
$budget = $source | Select-String -Pattern 'rxd_token_budget_reserve|g_token_budget|token_budget' -Context 5,5
foreach ($m in $budget) {
    $window = (($m.Context.PreContext + $m.Line + $m.Context.PostContext) -join "`n")
    if ($window -match '\b(return|break|cancel|stop|abort)\b') {
        $hits += $m
    }
}

# Every live response path should surface a terminal event/error rather than
# silently exiting after a backend failure. Flag obvious empty/silent exits.
$silent = $source | Select-String -Pattern 'forwardTokenAllLayers|computeLogits|sampleToken' -Context 3,5
foreach ($m in $silent) {
    $window = (($m.Context.PreContext + $m.Line + $m.Context.PostContext) -join "`n")
    if ($window -match 'return\s*;\s*(//.*)?$' -and
        $window -notmatch 'Error|emit|fail|Completed|terminal') {
        $hits += $m
    }
}

if ($hits.Count -gt 0) {
    Write-Host "RAWRXD_CONTINUOUS_EXECUTION_001=FAIL"
    $hits |
        Sort-Object Path,LineNumber -Unique |
        Select-Object Path,LineNumber,Line |
        Format-Table -AutoSize
    exit 1
}

Write-Host "RAWRXD_CONTINUOUS_EXECUTION_001=PASS"
Write-Host "TIME_DRIVEN_CONTROL=0"
Write-Host "SILENT_BUDGET_TERMINATION=0"
exit 0
