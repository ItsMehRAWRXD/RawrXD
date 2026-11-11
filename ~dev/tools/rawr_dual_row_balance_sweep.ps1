[CmdletBinding()]
param(
    [string]$RawrPath = (Join-Path $PSScriptRoot '..\build\Release\rawr.exe'),
    [string]$Model = 'llama3.2:3b',
    [string]$Prompt = 'Write one short sentence about Vulkan.',
    [string]$EvidenceDirectory = (Join-Path $PSScriptRoot '..\evidence\dual_row_balance_sweep'),
    [int]$Tokens = 32,
    [int]$Context = 2048,
    [double[]]$Gpu0Weights = @(1.0, 1.15, 1.30, 1.45, 1.60),
    [double]$Gpu1Weight = 1.0
)

$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path -LiteralPath $RawrPath -ErrorAction Stop).Path
$shaderDir = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\rawrxd\src\deep2\shaders')).Path
New-Item -ItemType Directory -Force -Path $EvidenceDirectory | Out-Null
$run = Get-Date -Format 'yyyyMMdd_HHmmss'
$rows = [System.Collections.Generic.List[object]]::new()

foreach ($w0 in $Gpu0Weights) {
    if ($w0 -le 0 -or $Gpu1Weight -le 0) { throw 'GPU weights must be positive.' }
    $tag = ('{0:0.00}' -f $w0).Replace('.', '_')
    $receiptPath = Join-Path $EvidenceDirectory "${run}_g0_${tag}_g1_1_00.json"
    $stdoutPath = "$receiptPath.stdout.log"
    $stderrPath = "$receiptPath.stderr.log"
    $env:RAWRXD_DEEP2_SHADER_DIR = $shaderDir
    $env:DEEP2_DUAL_ROW_SPLIT = '1'
    $env:DEEP2_GPU0_THROUGHPUT_WEIGHT = [string]$w0
    $env:DEEP2_GPU1_THROUGHPUT_WEIGHT = [string]$Gpu1Weight
    & $exe run $Model $Prompt --device=gpu --context=$Context --max-tokens=$Tokens --receipt=$receiptPath 1>$stdoutPath 2>$stderrPath
    $exitCode = $LASTEXITCODE
    $r = if (Test-Path -LiteralPath $receiptPath) { Get-Content -Raw $receiptPath | ConvertFrom-Json } else { $null }
    $rows.Add([pscustomobject]@{
        gpu0_weight = $w0
        gpu1_weight = $Gpu1Weight
        exit_code = $exitCode
        generated_tokens = if ($r) {$r.generated_tokens} else {0}
        decode_tps = if ($r) {$r.decode_tps} else {0}
        generation_ms = if ($r) {$r.generation_ms} else {0}
        gpu_kernel_ns_0 = if ($r) {$r.gpu_kernel_ns_slot_0} else {0}
        gpu_kernel_ns_1 = if ($r) {$r.gpu_kernel_ns_slot_1} else {0}
        queue_submits_0 = if ($r) {$r.queue_submits_slot_0} else {0}
        queue_submits_1 = if ($r) {$r.queue_submits_slot_1} else {0}
        dual_physical_gpu = if ($r) {$r.dual_physical_gpu} else {$false}
        fallback_count = if ($r) {$r.unplanned_fallbacks} else {-1}
        strict_violation = if ($r) {$r.strict_violation} else {$true}
        result = if ($r -and $exitCode -eq 0 -and $r.generated_tokens -eq $Tokens -and $r.unplanned_fallbacks -eq 0 -and -not $r.strict_violation) {'PASS'} else {'FAIL'}
        receipt = $receiptPath
    })
}

$csv = Join-Path $EvidenceDirectory "dual_row_balance_${run}.csv"
$json = Join-Path $EvidenceDirectory "dual_row_balance_${run}.json"
$rows | Export-Csv -NoTypeInformation -LiteralPath $csv
$best = $rows | Where-Object result -eq 'PASS' | Sort-Object decode_tps -Descending | Select-Object -First 1
[ordered]@{
    schema = 'DEEP2_DUAL_ROW_BALANCE_001'
    tokens = $Tokens
    rows = $rows
    best = $best
    csv = $csv
    verdict = if ($best) {'PROFILED'} else {'REJECTED'}
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $json -Encoding UTF8
Write-Host "BALANCE_SWEEP_CSV=$csv"
Write-Host "BALANCE_SWEEP_RECEIPT=$json"
if (-not $best) { exit 1 }
