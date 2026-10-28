# Numeric EXIT capture for Deep2 MoE probes (no Start-Process ExitCode null).
# Usage: .\run_moe_probe_exit_hygiene.ps1 [-Tag KIMI_K2_MOE_RUNTIME_003]
param(
    [string]$Tag = 'KIMI_K2_MOE_RUNTIME_EXIT_HYGIENE',
    [string]$Exe = 'G:\~dev\rawrxd\build-fd\bin\deep2_benchmark.exe',
    [string]$ShardDir = 'F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M',
    [int]$TimeoutMs = 2700000
)
$ErrorActionPreference = 'Stop'
$ev = 'G:\~dev\rawrxd\evidence\DEEP2_KIMI_K2_001'
$model = Join-Path $ShardDir 'Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf'
$out = Join-Path $ev "$Tag.out.log"
$err = Join-Path $ev "$Tag.err.log"
$exitFile = Join-Path $ev "${Tag}_EXIT.txt"
$meta = Join-Path $ev "${Tag}_LAUNCH.txt"
$report = Join-Path $ev "${Tag}_report.json"

$sha = (Get-FileHash $Exe -Algorithm SHA256).Hash
$env:DEEP2_K2_SHARD_DIR = $ShardDir
$env:RAWRXD_ALLOW_GPU = '1'
$env:RAWRXD_HOST_DECODE = '0'
$env:RAWRXD_BOUNDED_RESIDENCY = '1'
$env:DEEP2_REAL_K2_GENERATE = '1'
$env:RAWRXD_K2_LAYERS = '61'
$env:WEIGHT_BUDGET_MIB = '32768'
$env:DEEP2_WEIGHT_BUDGET_MIB = '32768'
$env:DEEP2_LIVE_CACHE_BUDGET_MIB = '12288'
$env:RAWRXD_DEEP2_ALLOW_ELASTIC = '1'
Remove-Item Env:VK_ICD_FILENAMES -ErrorAction SilentlyContinue
Remove-Item Env:VK_DRIVER_FILES -ErrorAction SilentlyContinue

@"
LAUNCH_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
EXE=$Exe
SHA256=$sha
MODEL=$model
METHOD=cmd_/c_call_operator (numeric %ERRORLEVEL%)
PROMOTE=0
"@ | Set-Content $meta -Encoding utf8

$argList = @(
    '--model', $model,
    '--phase', 'single',
    '--prompt', 'The capital of France is',
    '--max-tokens', '1',
    '--ctx-size', '128',
    '--output', $report,
    '--format', 'telemetry'
)
# Build a single command line for cmd.exe so %ERRORLEVEL% is numeric.
$quoted = ($argList | ForEach-Object {
    if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
}) -join ' '
$sw = [Diagnostics.Stopwatch]::StartNew()
# Redirect via cmd so ERRORLEVEL is real; tee paths via cmd redirection.
$cmd = "`"$Exe`" $quoted > `"$out`" 2> `"$err`" & exit /b %ERRORLEVEL%"
cmd.exe /c $cmd
$rc = $LASTEXITCODE
$sw.Stop()
if ($null -eq $rc) {
    "EXIT=EXIT_UNKNOWN ELAPSED_MS=$($sw.ElapsedMilliseconds)" | Set-Content $exitFile
    "EXIT_CODE=EXIT_UNKNOWN" | Add-Content $meta
    throw 'EXIT_UNKNOWN'
}
"EXIT=$rc ELAPSED_MS=$($sw.ElapsedMilliseconds)" | Set-Content $exitFile
"EXIT_CODE=$rc DONE_UTC=$((Get-Date).ToUniversalTime().ToString('o')) ELAPSED_MS=$($sw.ElapsedMilliseconds)" | Add-Content $meta
Write-Host "EXIT=$rc ELAPSED_MS=$($sw.ElapsedMilliseconds)"
exit $rc
