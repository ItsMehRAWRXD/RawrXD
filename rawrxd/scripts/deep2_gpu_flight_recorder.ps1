param(
    [string]$Exe = (Join-Path $PSScriptRoot '..\..\_s12_parity_build\bin\deep2_end_to_end_bench.exe'),
    [string]$Model = 'F:\~dev\qwen2.5-coder-1.5b-base.gguf',
    [string]$Prompt = 'The capital of France is',
    [int]$Tokens = 32,
    [int]$Runs = 3,
    [int]$TimeoutSec = 180,
    [string]$OutputDir = '',
    [switch]$Q6Hot,
    [switch]$Q4Hot,
    [string]$Gpu0Weight = '100',
    [string]$Gpu1Weight = '0.01'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Tokens -lt 1) { throw 'Tokens must be positive.' }
if ($Runs -lt 1) { throw 'Runs must be positive.' }
if ($TimeoutSec -lt 1) { throw 'TimeoutSec must be positive.' }

$exePath = [System.IO.Path]::GetFullPath($Exe)
$modelPath = [System.IO.Path]::GetFullPath($Model)
if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
    throw "Executable not found: $exePath"
}
if (-not (Test-Path -LiteralPath $modelPath -PathType Leaf)) {
    throw "Model not found: $modelPath"
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path (Get-Location) ("deep2_flight_recorder_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$trackedEnv = @(
    'DEEP2_DENSE_EXEC',
    'DEEP2_GPU0_THROUGHPUT_WEIGHT',
    'DEEP2_GPU1_THROUGHPUT_WEIGHT',
    'DEEP2_Q4K_HOT_BATCH_ROWS',
    'DEEP2_Q6K_HOT_BATCH_ROWS',
    'DEEP2_GPU_TRACE'
)
$savedEnv = @{}
foreach ($name in $trackedEnv) {
    $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

function Get-LastMatch {
    param(
        [string]$Text,
        [string]$Pattern
    )
    $matches = [regex]::Matches($Text, $Pattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
    if ($matches.Count -eq 0) { return $null }
    return $matches[$matches.Count - 1]
}

function Get-LastInt {
    param(
        [string]$Text,
        [string]$Pattern
    )
    $match = Get-LastMatch -Text $Text -Pattern $Pattern
    if ($null -eq $match) { return $null }
    return [int]$match.Groups[1].Value
}

function Get-LastDouble {
    param(
        [string]$Text,
        [string]$Pattern
    )
    $match = Get-LastMatch -Text $Text -Pattern $Pattern
    if ($null -eq $match) { return $null }
    return [double]::Parse($match.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture)
}

try {
    $env:DEEP2_DENSE_EXEC = 'LAYER_SPLIT'
    $env:DEEP2_GPU0_THROUGHPUT_WEIGHT = $Gpu0Weight
    $env:DEEP2_GPU1_THROUGHPUT_WEIGHT = $Gpu1Weight
    $env:DEEP2_Q4K_HOT_BATCH_ROWS = if ($Q4Hot) { '1' } else { '0' }
    $env:DEEP2_Q6K_HOT_BATCH_ROWS = if ($Q6Hot) { '1' } else { '0' }
    $env:DEEP2_GPU_TRACE = '1'

    $results = [System.Collections.Generic.List[object]]::new()
    for ($run = 1; $run -le $Runs; $run++) {
        $stdoutPath = Join-Path $OutputDir ("run_{0:D2}.stdout.txt" -f $run)
        $stderrPath = Join-Path $OutputDir ("run_{0:D2}.stderr.txt" -f $run)
        $combinedPath = Join-Path $OutputDir ("run_{0:D2}.flight.txt" -f $run)
        Remove-Item -LiteralPath $stdoutPath,$stderrPath,$combinedPath -Force -ErrorAction SilentlyContinue

        $arguments = @(
            '--strict-vulkan',
            '--no-time-reverse',
            '--no-vram-stream',
            '--stream-tokens', $Tokens.ToString([Globalization.CultureInfo]::InvariantCulture),
            '--max-tokens', $Tokens.ToString([Globalization.CultureInfo]::InvariantCulture),
            '--format', 'receipt',
            $modelPath,
            ('"{0}"' -f ($Prompt -replace '"', '\\"'))
        )

        $started = Get-Date
        $process = Start-Process -FilePath $exePath -ArgumentList $arguments -WorkingDirectory (Split-Path $exePath) -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
        $completed = $process.WaitForExit($TimeoutSec * 1000)
        $timedOut = -not $completed
        if ($timedOut) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            $process.WaitForExit(5000)
        }
        $finished = Get-Date

        $stdout = if (Test-Path -LiteralPath $stdoutPath) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
        $stderr = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
        $combined = $stdout + [Environment]::NewLine + $stderr
        Set-Content -LiteralPath $combinedPath -Value $combined -Encoding UTF8

        $lastReceipt = Get-LastMatch -Text $combined -Pattern 'GPUFWD_RECEIPT\s+gen=(\d+)\s+tokens=(\d+).*?nan=(\d+)\s+inf=(\d+)\s+expectLayers=(\d+)'
        $lastResult = Get-LastMatch -Text $combined -Pattern '\[STREAM\]\s+RESULT\s+generated=(\d+).*?cancelled=(\d+)\s+completed=(\d+)\s+status=([-\d]+)'
        $lastHostFallback = Get-LastInt -Text $combined -Pattern 'hostFwdLayers=(\d+)'
        $lastDecodeTps = Get-LastDouble -Text $combined -Pattern 'DECODE_TPS=([0-9]+(?:\.[0-9]+)?)'
        $receiptGen = if ($null -eq $lastReceipt) { $null } else { [int]$lastReceipt.Groups[1].Value }
        $receiptTokens = if ($null -eq $lastReceipt) { $null } else { [int]$lastReceipt.Groups[2].Value }
        $nan = if ($null -eq $lastReceipt) { $null } else { [int]$lastReceipt.Groups[3].Value }
        $inf = if ($null -eq $lastReceipt) { $null } else { [int]$lastReceipt.Groups[4].Value }
        $expectedLayers = if ($null -eq $lastReceipt) { $null } else { [int]$lastReceipt.Groups[5].Value }
        $generated = if ($null -eq $lastResult) { $null } else { [int]$lastResult.Groups[1].Value }
        $cancelled = if ($null -eq $lastResult) { $null } else { [int]$lastResult.Groups[2].Value }
        $completedFlag = if ($null -eq $lastResult) { $null } else { [int]$lastResult.Groups[3].Value }
        $status = if ($null -eq $lastResult) { $null } else { [int]$lastResult.Groups[4].Value }
        $dispatchCount = ([regex]::Matches($combined, '\[HOT_QUANT_DISPATCH\]')).Count
        $failureCount = ([regex]::Matches($combined, '\[HOT_(?:LANE|GROUP)_(?:RESET|SUBMIT|WAIT)_FAIL\]')).Count
        $processExit = if ($timedOut) { $null } else { $process.ExitCode }
        $gatePass = (
            -not $timedOut -and
            $processExit -eq 0 -and
            $null -ne $lastResult -and
            $generated -eq $Tokens -and
            $cancelled -eq 0 -and
            $completedFlag -eq 1 -and
            $status -eq 0 -and
            $null -ne $lastReceipt -and
            $null -ne $lastHostFallback -and
            $lastHostFallback -eq 0 -and
            $nan -eq 0 -and
            $inf -eq 0 -and
            $failureCount -eq 0
        )

        $results.Add([pscustomobject]@{
            run = $run
            pass = [bool]$gatePass
            process_exit = $processExit
            timeout = [bool]$timedOut
            duration_sec = [math]::Round(($finished - $started).TotalSeconds, 3)
            requested_tokens = $Tokens
            generated_tokens = $generated
            last_receipt_gen = $receiptGen
            last_receipt_tokens = $receiptTokens
            expected_layers = $expectedLayers
            host_forward_layers = $lastHostFallback
            nan = $nan
            inf = $inf
            q_dispatches = $dispatchCount
            fence_failures = $failureCount
            decode_tps = $lastDecodeTps
            stdout = $stdoutPath
            stderr = $stderrPath
            flight_log = $combinedPath
        })

        $state = if ($gatePass) { 'PASS' } else { 'FAIL' }
        Write-Output ("RUN={0} STATE={1} EXIT={2} GENERATED={3}/{4} RECEIPT_GEN={5} HOST_FWD={6} NAN={7} INF={8} FENCE_FAIL={9} DECODE_TPS={10}" -f $run, $state, $processExit, $generated, $Tokens, $receiptGen, $lastHostFallback, $nan, $inf, $failureCount, $lastDecodeTps)
    }

    $failedResults = @($results | Where-Object { -not $_.pass })
    $overallPass = ($results.Count -eq $Runs) -and ($failedResults.Count -eq 0)
    $report = [pscustomobject]@{
        gate = 'DEEP2_GPU_FLIGHT_RECORDER_001'
        verdict = if ($overallPass) { 'PASS' } else { 'FAIL' }
        executable = $exePath
        model = $modelPath
        tokens = $Tokens
        runs = $Runs
        timeout_sec = $TimeoutSec
        q4_hot = [bool]$Q4Hot
        q6_hot = [bool]$Q6Hot
        dense_exec = $env:DEEP2_DENSE_EXEC
        gpu0_weight = $Gpu0Weight
        gpu1_weight = $Gpu1Weight
        results = @($results)
    }
    $reportPath = Join-Path $OutputDir 'flight_recorder_report.json'
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8
    Write-Output "REPORT=$reportPath"
    Write-Output "VERDICT=$($report.verdict)"
    if (-not $overallPass) { exit 1 }
}
finally {
    foreach ($name in $trackedEnv) {
        [Environment]::SetEnvironmentVariable($name, $savedEnv[$name], 'Process')
    }
}
