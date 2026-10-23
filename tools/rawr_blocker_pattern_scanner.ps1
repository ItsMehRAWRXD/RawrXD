[CmdletBinding()]
param(
    [Parameter(Position=0)] [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [Parameter(Position=1)] [string]$Output = ''
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
if (-not $Output) { $Output = Join-Path $RepoRoot 'evidence\rawr_blocker_pattern_scan.json' }

function Rel([string]$Path) {
    return $Path.Substring($RepoRoot.Length).TrimStart('\','/')
}
function Add-Finding([System.Collections.Generic.List[object]]$List, [string]$Id,
    [string]$Category, [string]$Status, [string]$Path, [int]$Line,
    [string]$Evidence, [string]$Action) {
    $List.Add([ordered]@{ id=$Id; category=$Category; status=$Status; path=$Path;
        line=$Line; evidence=$Evidence; next_action=$Action })
}
function Scan-Pattern([System.Collections.Generic.List[object]]$List, [string]$Id,
    [string]$Category, [string]$Pattern, [string]$Action) {
    foreach ($root in $script:ScanRoots) {
        $hits = & rg.exe -n --no-heading --color never --glob '*.cpp' --glob '*.hpp' --glob '*.h' --glob '*.c' --glob '*.ps1' --glob '*.cmake' --glob '*.txt' --glob '*.md' $Pattern $root 2>$null
        foreach ($hit in @($hits)) {
            if ($hit -match '^(.*):(\d+):(.*)$') {
                Add-Finding $List $Id $Category 'INFO' (Rel $Matches[1]) ([int]$Matches[2]) $Matches[3].Trim() $Action
            }
        }
    }
}

$script:ScanRoots = @(
    (Join-Path $RepoRoot '~dev\src'),
    (Join-Path $RepoRoot '~dev\rawrxd\src'),
    (Join-Path $RepoRoot 'src'),
    (Join-Path $RepoRoot 'tools')
) | Where-Object { Test-Path -LiteralPath $_ }

$findings = [System.Collections.Generic.List[object]]::new()
$patterns = @(
    @{id='PAT-UNSUPPORTED'; category='unsupported'; pattern='UnsupportedOperator|NOT_IMPLEMENTED|UNSUPPORTED|not implemented'; action='Implement the operator or reject it before admission with an explicit receipt.'},
    @{id='PAT-PLACEHOLDER'; category='placeholder'; pattern='TODO|FIXME|PLACEHOLDER|stub|STUB'; action='Classify as intentional or replace with production behavior and a test.'},
    @{id='PAT-SILENT-FAIL'; category='error-handling'; pattern='catch\s*\([^)]*\)\s*\{\s*\}|catch\s*\([^)]*\)\s*\{\s*return'; action='Preserve the exception and failure stage in the durable receipt.'},
    @{id='PAT-CPU-FALLBACK'; category='fallback'; pattern='CPU_FALLBACK|CPU fallback|fallback to CPU|GetGEMV\('; action='Require explicit policy and record every fallback; GPU policy must fail closed.'},
    @{id='PAT-NONFINITE'; category='numerics'; pattern='non-finite|NaN|isfinite|isnan'; action='Attach tensor, layer, index, and first-divergence evidence.'},
    @{id='PAT-UNVALIDATED'; category='certification'; pattern='CERTIFIED|FULL_MODEL_CERTIFIED|PASS_FULL_MODEL'; action='Verify all full-model gates before allowing this status.'},
    @{id='PAT-RAW-RETURN'; category='dispatch'; pattern='return\s+false\s*;'; action='Add a stage-specific diagnostic or propagate a structured failure code.'}
)
foreach ($p in $patterns) { Scan-Pattern $findings $p.id $p.category $p.pattern $p.action }

# Evidence-derived blockers are kept separate from source pattern hits.
$receipts = Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'evidence') -Filter '*.json' -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -lt 10MB } | Select-Object -First 500
foreach ($receipt in $receipts) {
    try { $obj = Get-Content -LiteralPath $receipt.FullName -Raw | ConvertFrom-Json } catch { continue }
    $text = $obj | ConvertTo-Json -Depth 20 -Compress
    $explicitFailure = $text -match '"(?:status|verdict|certification|final_verdict|result|execution_truth)"\s*:\s*"(?:FAIL|FAILED|BLOCKED|NOT_CERTIFIED|INCOMPLETE|NOT_RUN|NOT_IMPLEMENTED)"'
    $explicitError = $text -match '"(?:error|failure_reason|first_failure)"\s*:\s*"[^" ]+'
    $nonzeroExit = $text -match '"(?:exit_code|exit|gen_exit)"\s*:\s*(?!0\b)[0-9-]+'
    if ($explicitFailure -or $explicitError -or $nonzeroExit) {
        Add-Finding $findings 'EVIDENCE-RECEIPT' 'receipt' 'OPEN' (Rel $receipt.FullName) 0 'Receipt contains an explicit failure/verdict/error or nonzero exit field.' 'Inspect the receipt and close the specific gate; do not infer certification from unrelated boolean or zero-valued fields.'
    }
}

$required = @(
    @{id='GATE-BUILD'; name='rawr.exe'; paths=@('~dev\build\Release\rawr.exe')},
    @{id='GATE-TEST'; name='native primitives test'; paths=@('~dev\build\Release\rawr_deep2_native_primitives_test.exe')},
    @{id='GATE-RECEIPT'; name='blocker ledger'; paths=@('evidence\rawr_run_blocker_ledger_20261020.md')}
)
foreach ($gate in $required) {
    foreach ($path in $gate.paths) {
        if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot $path))) {
            Add-Finding $findings $gate.id 'artifact' 'MISSING' $path 0 "$($gate.name) artifact is absent." 'Build or generate the artifact, then rerun this scanner.'
        }
    }
}

$open = @($findings | Where-Object { $_.status -notin @('INFO') })
$report = [ordered]@{
    schema='rawrxd.blocker_pattern_scan.v1'
    generated_utc=[DateTime]::UtcNow.ToString('o')
    repository=$RepoRoot
    policy='pattern hits are leads; only evidence-backed gates can close; no scan result certifies a model'
    pattern_count=$findings.Count
    open_count=$open.Count
    certification='NOT_CERTIFIED'
    findings=$findings
}
$parent = Split-Path -Parent $Output
if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Output -Encoding UTF8
Write-Host "SCAN=$Output"
Write-Host "FINDINGS=$($findings.Count)"
Write-Host "OPEN=$($open.Count)"
exit $(if ($open.Count -gt 0) { 4 } else { 0 })
