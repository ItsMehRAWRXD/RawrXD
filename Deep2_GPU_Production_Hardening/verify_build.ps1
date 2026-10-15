# Deep2 GPU Production Hardening — Build Verification
# Run from F:\rawrxd after applying patches

param(
    [string]$BuildDir = "F:\rawrxd\build_hardening",
    [string]$Config = "Release",
    [int]$Parallel = 4,
    [switch]$RunBenchmarks,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

Write-Host "=== Deep2 GPU Production Hardening — Build Verification ===" -ForegroundColor Cyan
Write-Host "Build directory: $BuildDir"
Write-Host "Config: $Config"
Write-Host "Parallel jobs: $Parallel"
Write-Host "Run benchmarks: $RunBenchmarks"
Write-Host ""

if (-not $SkipBuild) {
    Write-Host "=== Configuring CMake ===" -ForegroundColor Yellow

    if (-not (Test-Path $BuildDir)) {
        New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
    }

    Push-Location $BuildDir

    $cmakeArgs = @(
        "..",
        "-DCMAKE_BUILD_TYPE=$Config",
        "-G", "Visual Studio 17 2022",
        "-A", "x64",
        "-DRAWRXD_BUILD_TESTS=ON",
        "-DENABLE_VULKAN=ON"
    )

    $result = cmake @cmakeArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "CMake configure failed"
        exit 1
    }

    Write-Host "=== Building ===" -ForegroundColor Yellow
    $buildResult = cmake --build . --config $Config --parallel $Parallel
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed"
        exit 1
    }

    Pop-Location
}

Write-Host ""
Write-Host "=== Build Successful ===" -ForegroundColor Green

if ($RunBenchmarks) {
    Write-Host ""
    Write-Host "=== Running Benchmarks ===" -ForegroundColor Yellow

    $bench = Join-Path $BuildDir "tools\deep2_strata_bench.exe"
    if (-not (Test-Path $bench)) {
        $bench = Join-Path $BuildDir "tools\$Config\deep2_strata_bench.exe"
    }

    if (-not (Test-Path $bench)) {
        Write-Error "Benchmark executable not found at $bench"
        exit 1
    }

    $models = @(
        @{ Name = "Nemotron 30B MoE"; Path = "F:\rawrxd\models\nemotron-3.5-lightning_30b.gguf" },
        @{ Name = "DeepSeek R1 32B Dense"; Path = "F:\rawrxd\models\deepseek-r1_32b.gguf" }
    )

    foreach ($model in $models) {
        if (-not (Test-Path $model.Path)) {
            Write-Warning "Model not found: $($model.Path) — skipping"
            continue
        }

        Write-Host ""
        Write-Host "Running: $($model.Name)" -ForegroundColor Cyan
        Write-Host "Model: $($model.Path)"

        $startTime = Get-Date
        $result = & $bench --model $model.Path --generate 64 --gpu --strata 2>&1
        $exitCode = $LASTEXITCODE
        $elapsed = (Get-Date) - $startTime

        Write-Host "Exit code: $exitCode"
        Write-Host "Elapsed: $($elapsed.TotalSeconds) seconds"

        # Parse key metrics from output
        $result | Select-String 'S10_DECODE_TPS_MEAN|S04_BACKEND|S01_EXPERT_LEDGER|S02_VRAM_CACHE|DISPATCH|BENCH_EXIT_CODE' | ForEach-Object { Write-Host "  $_" }

        # Check for new fields
        if ($result -match 'gpu_ms=([\d.]+)') {
            Write-Host "  GPU MS: $($matches[1])" -ForegroundColor Green
        }
        if ($result -match 'host_wait_ms=([\d.]+)') {
            Write-Host "  Host Wait MS: $($matches[1])" -ForegroundColor Green
        }
        if ($result -match 'expert_observations=(\d+)') {
            Write-Host "  Expert Observations: $($matches[1])" -ForegroundColor Green
        }
        if ($result -match 'total_device_weight_bytes=(\d+)') {
            $gb = [math]::Round([int64]$matches[1] / 1GB, 2)
            Write-Host "  Total Device Weight: $gb GB" -ForegroundColor Green
        }

        # Save receipt
        $receiptDir = "F:\rawrxd\strata_bench\hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -ItemType Directory -Path $receiptDir -Force | Out-Null
        $result | Out-File (Join-Path $receiptDir "bench_$($model.Name.Replace(' ', '_')).log")
        Get-ChildItem "F:\rawrxd\strata_bench" -Filter "strata_bench_run.json" -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $receiptDir "receipt_$($model.Name.Replace(' ', '_')).json")
        }
    }
}

Write-Host ""
Write-Host "=== Verification Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Expected improvements vs baseline:" -ForegroundColor Cyan
Write-Host "  - gpu_ms should be < host_wait_ms (real GPU time vs CPU wait)"
Write-Host "  - expert_observations > 0 (MoE telemetry active)"
Write-Host "  - total_device_weight_bytes ≈ model size (full residency)"
Write-Host "  - submits/waits per token << 184 (batched submissions)"

exit 0