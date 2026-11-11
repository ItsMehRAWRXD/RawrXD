[CmdletBinding()]
param(
    [string]$RawrPath = (Join-Path $PSScriptRoot '..\build\Release\rawr.exe'),
    [string]$Model = 'llama3.2:3b',
    [string]$Prompt = 'Write one short sentence about Vulkan.',
    [string]$EvidenceDirectory = (Join-Path $PSScriptRoot '..\evidence\profiling_session_3a'),
    [ValidateSet('single','dual')][string]$Mode = 'single',
    [int[]]$TokenCounts = @(8,32,128,256),
    [int]$Context = 2048,
    [ValidateRange(1,10)][int]$Repetitions = 3
)

$ErrorActionPreference = 'Stop'
$resolvedRawr = (Resolve-Path -LiteralPath $RawrPath -ErrorAction Stop).Path
New-Item -ItemType Directory -Force -Path $EvidenceDirectory | Out-Null

$shaderDir = Join-Path $PSScriptRoot '..\rawrxd\src\deep2\shaders'
$rows = [System.Collections.Generic.List[object]]::new()
$runId = Get-Date -Format 'yyyyMMdd_HHmmss'

foreach ($count in $TokenCounts) {
    if ($count -le 0) { throw "Token count must be positive: $count" }
    for ($repeat = 1; $repeat -le $Repetitions; $repeat++) {
    $stem = "${runId}_${Mode}_${count}tok_r${repeat}"
    $receiptPath = Join-Path $EvidenceDirectory "$stem.json"
    $stdoutPath = Join-Path $EvidenceDirectory "$stem.stdout.log"
    $stderrPath = Join-Path $EvidenceDirectory "$stem.stderr.log"

    $env:RAWRXD_DEEP2_SHADER_DIR = (Resolve-Path -LiteralPath $shaderDir).Path
    $env:DEEP2_DUAL_ROW_SPLIT = if ($Mode -eq 'dual') { '1' } else { '0' }
    & $resolvedRawr run $Model $Prompt --device=gpu --context=$Context --max-tokens=$count --receipt=$receiptPath 1>$stdoutPath 2>$stderrPath
    $exitCode = $LASTEXITCODE

    $receipt = $null
    if (Test-Path -LiteralPath $receiptPath) {
        try { $receipt = Get-Content -Raw -LiteralPath $receiptPath | ConvertFrom-Json } catch { }
    }
    $stderr = if (Test-Path -LiteralPath $stderrPath) { Get-Content -Raw -LiteralPath $stderrPath } else { '' }
    $gpuMs = $null
    $submitCount = $null
    $waitCount = $null
    $gpuMatch = [regex]::Match($stderr, 'BACKEND_GPU_MS_TOTAL=([0-9.]+)')
    $submitMatch = [regex]::Match($stderr, 'BACKEND_SUBMISSIONS=([0-9]+)')
    $waitMatch = [regex]::Match($stderr, 'BACKEND_WAITS=([0-9]+)')
    if ($gpuMatch.Success) { $gpuMs = [double]$gpuMatch.Groups[1].Value }
    if ($submitMatch.Success) { $submitCount = [uint64]$submitMatch.Groups[1].Value }
    if ($waitMatch.Success) { $waitCount = [uint64]$waitMatch.Groups[1].Value }

    $ok = $exitCode -eq 0 -and $receipt -and $receipt.status -eq 'PASS' -and
          $receipt.generated_tokens -eq $count -and $receipt.unplanned_fallbacks -eq 0 -and
          -not $receipt.strict_violation
    $rows.Add([pscustomobject]@{
        mode = $Mode
        repetition = $repeat
        requested_tokens = $count
        generated_tokens = if ($receipt) { $receipt.generated_tokens } else { 0 }
        exit_code = $exitCode
        decode_tps = if ($receipt) { $receipt.decode_tps } else { 0 }
        generation_ms = if ($receipt) { $receipt.generation_ms } else { 0 }
        gpu_ms = $gpuMs
        submissions = $submitCount
        waits = $waitCount
        dual_row_dispatches = if ($receipt) { $receipt.dual_row_dispatches } else { 0 }
        dual_row_slot_0 = if ($receipt) { $receipt.dual_row_slot_0 } else { 0 }
        dual_row_slot_1 = if ($receipt) { $receipt.dual_row_slot_1 } else { 0 }
        dual_physical_gpu = if ($receipt) { $receipt.dual_physical_gpu } else { $false }
        fallback_count = if ($receipt) { $receipt.unplanned_fallbacks } else { -1 }
        strict_violation = if ($receipt) { $receipt.strict_violation } else { $true }
        timestamp_valid_slot_0 = if ($receipt) { $receipt.timestamp_valid_slot_0 } else { $false }
        timestamp_valid_slot_1 = if ($receipt) { $receipt.timestamp_valid_slot_1 } else { $false }
        gpu_kernel_ns_slot_0 = if ($receipt) { $receipt.gpu_kernel_ns_slot_0 } else { 0 }
        gpu_kernel_ns_slot_1 = if ($receipt) { $receipt.gpu_kernel_ns_slot_1 } else { 0 }
        queue_submits_slot_0 = if ($receipt) { $receipt.queue_submits_slot_0 } else { 0 }
        queue_submits_slot_1 = if ($receipt) { $receipt.queue_submits_slot_1 } else { 0 }
        weight_uploads_slot_0 = if ($receipt) { $receipt.weight_uploads_slot_0 } else { 0 }
        weight_uploads_slot_1 = if ($receipt) { $receipt.weight_uploads_slot_1 } else { 0 }
        weight_hits_slot_0 = if ($receipt) { $receipt.weight_hits_slot_0 } else { 0 }
        weight_hits_slot_1 = if ($receipt) { $receipt.weight_hits_slot_1 } else { 0 }
        submit_cpu_ns_slot_0 = if ($receipt) { $receipt.submit_cpu_ns_slot_0 } else { 0 }
        submit_cpu_ns_slot_1 = if ($receipt) { $receipt.submit_cpu_ns_slot_1 } else { 0 }
        wait_ns_slot_0 = if ($receipt) { $receipt.wait_ns_slot_0 } else { 0 }
        wait_ns_slot_1 = if ($receipt) { $receipt.wait_ns_slot_1 } else { 0 }
        result = if ($ok) { 'PASS' } else { 'FAIL' }
        receipt = $receiptPath
    })
    }
}

$csvPath = Join-Path $EvidenceDirectory "profiling_session_3A_${runId}.csv"
$jsonPath = Join-Path $EvidenceDirectory "profiling_session_3A_${runId}.json"
$rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation
$allPass = @($rows | Where-Object result -ne 'PASS').Count -eq 0
$hasGpuTimestamps = @($rows | Where-Object { $null -ne $_.gpu_ms }).Count -eq $rows.Count
$dominant = if (-not $hasGpuTimestamps) { 'UNAVAILABLE' } else { 'REQUIRES_TIMESTAMP_SCOPE' }
$summary = [ordered]@{
    schema = 'DEEP2_SUSTAINED_PROFILING_3A'
    model = $Model
    mode = $Mode
    token_counts = $TokenCounts
    repetitions = $Repetitions
    sweep_status = if ($allPass) { 'COMPLETE' } else { 'FAILED_CLOSED' }
    dominant_bottleneck = $dominant
    vulkan_timestamp_validity = if ($hasGpuTimestamps) { 'PASS' } else { 'NOT_AVAILABLE_IN_RECEIPT' }
    rows = $rows
    csv = $csvPath
    verdict = if ($allPass) { 'PROFILED' } else { 'REJECTED' }
}
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
Write-Host "SESSION_3A_CSV=$csvPath"
Write-Host "SESSION_3A_RECEIPT=$jsonPath"
Write-Host "SESSION_3A_STATUS=$($summary.sweep_status)"
if (-not $allPass) { exit 1 }
