# B009 Benchmark Runner — Production Binary T Comparison
# Runs rawrxd.exe with --benchmark-t for controlled prefill measurements

$model = "D:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
$exe = "D:\rawrxd\build-ninja\bin\rawrxd.exe"
$outDir = "D:\rawrxd\benchmark_t_results"

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$T_values = @(1, 3, 10, 32, 128)

foreach ($T in $T_values) {
    $logBase = "$outDir\bench_t${T}"
    $stdoutLog = "$logBase`_stdout.log"
    $stderrLog = "$logBase`_stderr.log"

    Write-Host "=== Running T=$T ===" -ForegroundColor Cyan

    $proc = Start-Process -FilePath $exe -ArgumentList "--model", $model, "--prompt", "benchmark", "--benchmark-t", $T, "--max-tokens", 0 -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -Wait -PassThru

    $exitCode = $proc.ExitCode
    Write-Host "  Exit code: $exitCode"

    # Verify T from stderr
    $stderrContent = Get-Content $stderrLog -Raw
    if ($stderrContent -match "prefill: tokens=(\d+)") {
        $reportedT = [int]$matches[1]
        if ($reportedT -eq $T) {
            Write-Host "  [PASS] Reported T=$reportedT matches target" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Reported T=$reportedT != target $T" -ForegroundColor Red
        }
    } else {
        Write-Host "  [WARN] Could not find prefill token count in output" -ForegroundColor Yellow
    }

    # Check for profiler output
    if ($stderrContent -match "Target: StreamingMatMul") {
        Write-Host "  [PASS] Profiler output detected" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] No profiler output detected" -ForegroundColor Yellow
    }

    Write-Host ""
}

Write-Host "=== All benchmarks complete. Logs in $outDir ===" -ForegroundColor Cyan
