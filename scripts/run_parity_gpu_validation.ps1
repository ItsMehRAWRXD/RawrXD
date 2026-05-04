# run_parity_gpu_validation.ps1 — Real-model CLI/UI parity validation
#
# Runs the full inference path (no RAWRXD_PARITY_CPU) on a real GGUF model and
# compares CLI vs UI traces. Requires:
#   - A Vulkan/CUDA/HIP-capable GPU (gpu_enforcement gate must succeed)
#   - RawrXD_ServeInference.dll next to rawrxd.exe / RawrXD-Win32IDE.exe
#   - A real GGUF model file
#
# When hardware is missing the script exits with code 0 and a clear "deferred"
# message so it can be safely invoked from any CI lane without false failures.
# Use -Strict to convert deferral into a hard failure (for hardware-equipped CI).

[CmdletBinding()]
param(
    [string]$BinDir   = "d:\rawrxd\build_pipeline\bin",
    [string]$OutDir   = "d:\rawrxd\build_pipeline\parity_gpu",
    [string]$Model    = "D:\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf",
    [string]$Prompt   = "Say exactly: ready",
    [int]   $MaxTokens = 16,
    [switch]$Strict
)

$ErrorActionPreference = 'Stop'
$cliExe = Join-Path $BinDir "rawrxd.exe"
$uiExe  = Join-Path $BinDir "RawrXD-Win32IDE.exe"

function Defer([string]$why) {
    Write-Host "[DEFERRED] $why" -ForegroundColor Yellow
    if ($Strict) {
        Write-Host "[STRICT] Treating deferral as failure." -ForegroundColor Red
        exit 1
    }
    exit 0
}

if (!(Test-Path $cliExe)) { Defer "CLI binary not built: $cliExe" }
if (!(Test-Path $uiExe))  { Defer "UI binary not built: $uiExe" }
if (!(Test-Path $Model))  { Defer "Model file not present: $Model" }

# Probe for the inference plugin DLL.
$plugin = Join-Path $BinDir "RawrXD_ServeInference.dll"
if (!(Test-Path $plugin)) {
    $envDll = $env:RAWRXD_SERVE_INFERENCE_DLL
    if (-not $envDll -or -not (Test-Path $envDll)) {
        Defer "RawrXD_ServeInference.dll missing from $BinDir and RAWRXD_SERVE_INFERENCE_DLL"
    }
}

# Probe GPU. Run CLI list (cheap) and capture stderr; gpu_enforcement aborts
# the process before list output if no GPU is present.
$gpuProbe = Join-Path $OutDir "gpu_probe.txt"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# Make sure we are NOT in CPU-fallback mode for this lane.
Remove-Item Env:\RAWRXD_PARITY_CPU -ErrorAction SilentlyContinue

# We can't reliably probe GPU without invoking the real path, so we run the CLI
# inference attempt under stderr capture and inspect the result. If the GPU
# enforcement gate fires, we defer cleanly instead of failing.
Write-Host "=== Attempting CLI inference (will defer if GPU absent) ==="
$cliTrace  = Join-Path $OutDir "cli_real.json"
$cliStderr = Join-Path $OutDir "cli.stderr.txt"
$cliStdout = Join-Path $OutDir "cli.stdout.txt"
$uiTrace   = Join-Path $OutDir "ui_real.json"
Remove-Item -Force $cliTrace, $uiTrace -ErrorAction SilentlyContinue

$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$proc = Start-Process -FilePath $cliExe `
    -ArgumentList @('run', $Model, '--prompt', $Prompt, '--emit-json-trace', $cliTrace) `
    -RedirectStandardError $cliStderr -RedirectStandardOutput $cliStdout `
    -NoNewWindow -PassThru -Wait
$cliExit = $proc.ExitCode
$ErrorActionPreference = $prevEAP

$stderrText = if (Test-Path $cliStderr) { Get-Content $cliStderr -Raw } else { '' }
if ($stderrText -match 'No GPU backend available') {
    Defer "GPU enforcement gate fired (no Vulkan/CUDA/HIP device)."
}

if ($cliExit -ne 0 -or -not (Test-Path $cliTrace)) {
    Write-Host "[FAIL] CLI inference failed (exit=$cliExit)" -ForegroundColor Red
    Write-Host "stderr:`n$stderrText"
    exit 2
}

Write-Host "[OK] CLI real-model trace written: $cliTrace"

Write-Host "=== UI inference (headless driver) ==="
# The headless UI driver (rawrxd-parity-ui-driver.exe) calls the same
# RawrXD::runLocalInferencePipeline path that Win32IDE.cpp uses, with no GUI
# / message loop. RAWRXD_PIPELINE_TRACE drives the JSON envelope writer.
$env:RAWRXD_PIPELINE_TRACE = $uiTrace
$uiDriver = Join-Path $BinDir "rawrxd-parity-ui-driver.exe"
if (!(Test-Path $uiDriver)) {
    Write-Host "[DEFERRED] Headless UI driver not built: $uiDriver" -ForegroundColor Yellow
    Write-Host "[INFO] Build it with: ninja -C $BinDir/.. bin/rawrxd-parity-ui-driver.exe"
    Write-Host "[CLI HALF VERIFIED] real-model CLI trace at $cliTrace"
    if ($Strict) { exit 1 }
    exit 0
}

$uiStderr = Join-Path $OutDir "ui.stderr.txt"
$uiStdout = Join-Path $OutDir "ui.stdout.txt"
$proc = Start-Process -FilePath $uiDriver `
    -ArgumentList @('--model', $Model, '--prompt', $Prompt, '--num-predict', $MaxTokens) `
    -RedirectStandardError $uiStderr -RedirectStandardOutput $uiStdout `
    -NoNewWindow -PassThru -Wait
$uiExit = $proc.ExitCode

if ($uiExit -ne 0 -or -not (Test-Path $uiTrace)) {
    Write-Host "[FAIL] UI driver failed (exit=$uiExit)" -ForegroundColor Red
    if (Test-Path $uiStderr) { Write-Host "stderr:`n$(Get-Content $uiStderr -Raw)" }
    exit 2
}

Write-Host "[OK] UI real-model trace written: $uiTrace"

Write-Host "=== Structural diff ==="
$cmp = Join-Path $PSScriptRoot "compare_parity_trace.ps1"
& $cmp -Cli $cliTrace -Ui $uiTrace
exit $LASTEXITCODE
