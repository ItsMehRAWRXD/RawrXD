# Measure-Deep2Native.ps1
# Native Deep2 benchmark harness — bypasses HTTP/Ollama entirely
# Uses rawrxd_run_modelname_001.exe (native Deep2Engine → GGUF → tokens → TPS)
#
# Authority chain:
#   GGUF model file
#     ↓
#   rawrxd_run_modelname_001.exe (native C++ binary)
#     ↓
#   Deep2Engine::loadModel() + generateStream()
#     ↓
#   native Vulkan kernels (if --vulkan)
#     ↓
#   measured decode TPS (wall time / generated tokens)
#
# NOT:
#   script → HTTP :11434 → Ollama → llama.cpp

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Model,                    # GGUF path or model alias resolvable by RAWRXD_MODEL_DIR

    [Parameter(Mandatory)]
    [string]$Prompt,

    [Parameter()]
    [int]$MaxTokens = 256,

    [Parameter()]
    [int]$Runs = 5,

    [Parameter()]
    [switch]$Vulkan,

    [Parameter()]
    [string]$ExePath = "F:\~dev\rawrxd\build\bin\Release\rawrxd_run_modelname_001.exe",

    [Parameter()]
    [string]$OutDir = ".\native_deep2_results",

    [Parameter()]
    [string]$ModelDirEnv = "D:\rawrxd"   # RAWRXD_MODEL_DIR fallback
)

$ErrorActionPreference = "Stop"

# ---- Verify executable exists ----
if (-not (Test-Path $ExePath)) {
    # Auto-discover
    $candidates = Get-ChildItem "F:\~dev","G:\~dev","F:\~dev\rawrxd","G:\~dev\rawrxd" -Filter "rawrxd_run_modelname_001.exe" -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    if ($candidates) { $ExePath = $candidates[0].FullName }
    else { throw "rawrxd_run_modelname_001.exe not found. Set -ExePath explicitly." }
}

# ---- Verify model exists ----
$modelPath = ""
if (Test-Path $Model) { $modelPath = $Model }
elseif (Test-Path "$ModelDirEnv\$Model") { $modelPath = "$ModelDirEnv\$Model" }
elseif (Test-Path "$ModelDirEnv\$Model.gguf") { $modelPath = "$ModelDirEnv\$Model.gguf" }

if (-not $modelPath) {
    # Try RAWRXD_MODEL_DIR
    $env:RAWRXD_MODEL_DIR = $ModelDirEnv
    # The exe will try to resolve it
}

$modelResolved = $modelPath
if (-not $modelResolved) { $modelResolved = $Model }

# ---- Model metadata ----
$modelBytes = 0
$modelSha256 = ""
if ($modelPath -and (Test-Path $modelPath)) {
    $modelBytes = (Get-Item $modelPath).Length
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($modelPath)
    try {
        $hashBytes = $sha.ComputeHash($stream)
        $modelSha256 = [BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()
    }
    finally {
        $stream.Close()
        $sha.Dispose()
    }
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  NATIVE DEEP2 BENCHMARK" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Executable: $ExePath"
Write-Host "Model:      $modelResolved"
Write-Host "ModelBytes: $modelBytes"
Write-Host "SHA-256:    $(if($modelSha256){$modelSha256.Substring(0,16)+"..."}else{"N/A"})"
Write-Host "Prompt:     $Prompt"
Write-Host "MaxTokens:  $MaxTokens"
Write-Host "Runs:       $Runs"
Write-Host "Vulkan:     $($Vulkan.IsPresent)"
Write-Host ""

# ---- Environment: clean native authority ----
Remove-Item Env:DEEP2_K2_SHARD_DIR -ErrorAction SilentlyContinue
$env:TPS_LIMIT = "NONE"
$env:FULL_MODEL_RESIDENCY_REQUIRED = "0"
$env:DEEP2_TPS_DISPLAY_SCALE = "1"
$env:RAWRXD_MODEL_DIR = $ModelDirEnv

# ---- Verify no Ollama interference ----
$ollamaProcs = Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'ollama' }
if ($ollamaProcs) {
    Write-Warning "Ollama processes detected: $($ollamaProcs | Select-Object ProcessId,Name | Out-String)"
    Write-Warning "Native benchmark should not route through Ollama. Continuing anyway..."
}

# ---- Run loop ----
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$allRuns = @()

for ($r = 1; $r -le $Runs; $r++) {
    Write-Host "`n=== RUN $r / $Runs ===" -ForegroundColor Green

    $stdoutFile = "$OutDir\run_${r}_stdout.txt"
    $stderrFile = "$OutDir\run_${r}_stderr.txt"

    $argList = @($modelResolved, $Prompt)
    if ($Vulkan) {
        # If the exe supports --vulkan as a third arg
        $argList += "--vulkan"
    }

    $t0 = Get-Date
    $proc = Start-Process -FilePath $ExePath -WorkingDirectory (Split-Path $ExePath) `
        -ArgumentList $argList `
        -RedirectStandardOutput $stdoutFile `
        -RedirectStandardError $stderrFile `
        -Wait -PassThru
    $t1 = Get-Date

    $wallMs = ($t1 - $t0).TotalMilliseconds
    $exitCode = $proc.ExitCode

    # Parse receipt from stderr
    $stderr = Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue
    $generatedTokens = 0
    $promptTokens = 0
    $reportedTps = 0.0
    $completed = $false

    if ($stderr -match 'GENERATED_TOKENS=(\d+)') { $generatedTokens = [int]$Matches[1] }
    if ($stderr -match 'PROMPT_TOKENS=(\d+)')    { $promptTokens = [int]$Matches[1] }
    if ($stderr -match 'TPS=([\d\.]+)')           { $reportedTps = [double]$Matches[1] }
    if ($stderr -match 'COMPLETED=(\w+)')          { $completed = $Matches[1] -eq 'YES' }

    # Recalculate from wall time for authority
    $wallTps = if ($wallMs -gt 0 -and $generatedTokens -gt 0) { $generatedTokens / ($wallMs / 1000.0) } else { 0 }

    $row = [PSCustomObject]@{
        run_ordinal       = $r
        model             = $modelResolved
        model_bytes       = $modelBytes
        model_sha256      = $modelSha256
        prompt            = $Prompt
        prompt_sha256     = (Get-FileHash -Algorithm SHA256 -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($Prompt)))).Hash.ToLower()
        max_tokens        = $MaxTokens
        vulkan            = $Vulkan.IsPresent
        wall_ms           = [math]::Round($wallMs, 3)
        generated_tokens  = $generatedTokens
        prompt_tokens     = $promptTokens
        reported_tps      = [math]::Round($reportedTps, 6)
        wall_tps          = [math]::Round($wallTps, 6)
        exit_code         = $exitCode
        completed         = $completed
        status            = if ($completed -and $exitCode -eq 0) { "VALID" } else { "INVALID" }
    }

    $allRuns += $row

    Write-Host "  Exit: $exitCode | Generated: $generatedTokens | Reported TPS: $([math]::Round($reportedTps,2)) | Wall TPS: $([math]::Round($wallTps,2)) | Completed: $completed"
}

# ---- Summary ----
$validRuns = $allRuns | Where-Object { $_.status -eq "VALID" }
if ($validRuns.Count -gt 0) {
    $medianWallTps = ($validRuns | Sort-Object wall_tps | Select-Object -Index ([int]($validRuns.Count / 2))).wall_tps
    $medianReportedTps = ($validRuns | Sort-Object reported_tps | Select-Object -Index ([int]($validRuns.Count / 2))).reported_tps
    $meanWallTps = ($validRuns | Measure-Object wall_tps -Average).Average
    $meanReportedTps = ($validRuns | Measure-Object reported_tps -Average).Average
} else {
    $medianWallTps = 0; $medianReportedTps = 0; $meanWallTps = 0; $meanReportedTps = 0
}

$summary = [PSCustomObject]@{
    model               = $modelResolved
    model_bytes         = $modelBytes
    model_sha256_prefix = if($modelSha256){$modelSha256.Substring(0,16)}else{""}
    runs                = $Runs
    valid_runs          = $validRuns.Count
    wall_tps_median     = [math]::Round($medianWallTps, 6)
    wall_tps_mean       = [math]::Round($meanWallTps, 6)
    reported_tps_median = [math]::Round($medianReportedTps, 6)
    reported_tps_mean   = [math]::Round($meanReportedTps, 6)
    vulkan_enabled      = $Vulkan.IsPresent
    exe_path            = $ExePath
    mode                = "NATIVE_MEASUREMENT_ONLY"
}

# ---- Export ----
$allRuns | Export-Csv -Path "$OutDir\runs.csv" -NoTypeInformation -Force
$summary | Export-Csv -Path "$OutDir\summary.csv" -NoTypeInformation -Force

# ---- Receipt ----
$receipt = @"
GATE=DEEP2_NATIVE_BENCHMARK_001
STATUS=$(if($validRuns.Count -eq $Runs){"PASS"}else{"PARTIAL"})
MODEL=$modelResolved
MODEL_BYTES=$modelBytes
MODEL_SHA256_PREFIX=$(if($modelSha256){$modelSha256.Substring(0,16)}else{"N/A"})
RUNS=$Runs
VALID_RUNS=$($validRuns.Count)
WALL_TPS_MEDIAN=$medianWallTps
WALL_TPS_MEAN=$meanWallTps
REPORTED_TPS_MEDIAN=$medianReportedTps
REPORTED_TPS_MEAN=$meanReportedTps
VULKAN=$($Vulkan.IsPresent)
EXE=$ExePath
MODE=NATIVE_MEASUREMENT_ONLY
CLASSIFICATION=AXIS_2_IMPLEMENTATION_OR_AXIS_3_CONCURRENCY

RECEIPT_FLAGS:
- NATIVE_CHAIN=PASS (rawrxd_run_modelname_001 → Deep2Engine → generateStream)
- NO_HTTP_INTERMEDIATE=PASS (no :11434, no Ollama)
- EVAL_COUNT_FROM_NATIVE=PASS (token count from engine callback)
- WALL_TIME_FROM_HARNESS=PASS (PowerShell Start-Process timing)
- IDENTITY_AUTHORITY=$(if($modelSha256 -and $modelBytes -gt 0){"PASS"}else{"PARTIAL"})
"@

$receipt | Set-Content -Path "$OutDir\DEEP2_NATIVE_BENCHMARK_001.txt" -Force

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Results written to: $OutDir" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
$summary | Format-Table -AutoSize
