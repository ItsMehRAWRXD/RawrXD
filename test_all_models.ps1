# Test all local GGUF models with deep2_agentic_loop
# Each model gets a short max_new to prove: load + prefill + first token decode

$models = @(
    "bench_min.gguf",
    "gemma3-1b-Q2_K.gguf",
    "llama3.2-3b-Q2_K.gguf",
    "llama3.2-3b-Q3_K_S.gguf",
    "phi3-mini-Q2_K.gguf",
    "nemotron-bolt.gguf",
    "test_mock.gguf",
    "synthetic_moe.gguf"
)

$exe = "F:\rawrxd\build_cmake\bin\Release\deep2_agentic_loop.exe"
$results = @()

foreach ($m in $models) {
    $path = "F:\rawrxd\$m"
    if (-not (Test-Path $path)) { continue }
    
    $sizeMB = [math]::Round((Get-Item $path).Length / 1MB, 2)
    Write-Host "========================================"
    Write-Host "TESTING: $m ($sizeMB MB)"
    Write-Host "========================================"
    
    # Run with --plain to get clean logits output
    $p = Start-Process -FilePath $exe `
        -ArgumentList @("--model", $path, "--task", "test", "--max-new", "2", "--plain", "--plain-tokens", "2") `
        -RedirectStandardOutput "F:\rawrxd\test_$m.log" `
        -RedirectStandardError "F:\rawrxd\test_$m.err.log" `
        -PassThru
    
    if (-not $p.WaitForExit(120000)) {
        Write-Host "  TIMEOUT after 120s - killing process"
        Stop-Process -Id $p.Id -Force
        $results += @{Model=$m; Status="TIMEOUT"; Load="?"; Prefill="?"; GPU="?"}
        continue
    }
    
    $log = Get-Content "F:\rawrxd\test_$m.log" -ErrorAction SilentlyContinue
    
    # Check for load success
    $loaded = $false
    $prefill = $false
    $gpu = $false
    $cpuFallbacks = $false
    
    foreach ($line in $log) {
        if ($line -like "*ingest done*") { $loaded = $true }
        if ($line -like "*prefill_end*") { $prefill = $true }
        if ($line -like "*Vulkan initialized*") { $gpu = $true }
        if ($line -like "*cpu_fallbacks*") {
            if ($line -match "cpu_fallbacks=([0-9]+)") {
                if ($Matches[1] -eq "0") { $cpuFallbacks = $true }
            }
        }
    }
    
    $status = if ($loaded -and $prefill) { "PASS" } else { "FAIL" }
    $loadStatus = if ($loaded) { "LOAD_OK" } else { "LOAD_FAIL" }
    $prefillStatus = if ($prefill) { "PREFILL_OK" } else { "PREFILL_FAIL" }
    $gpuStatus = if ($gpu) { "GPU_OK" } else { "GPU_FAIL" }
    
    Write-Host "  Load:   $loadStatus"
    Write-Host "  Prefill: $prefillStatus"
    Write-Host "  GPU:    $gpuStatus"
    Write-Host "  Status: $status"
    Write-Host ""
    
    $results += @{Model=$m; Status=$status; Load=$loadStatus; Prefill=$prefillStatus; GPU=$gpuStatus}
}

Write-Host "========================================"
Write-Host "SUMMARY"
Write-Host "========================================"
foreach ($r in $results) {
    Write-Host ("{0,-30} {1,-10} {2,-15} {3,-15} {4,-10}" -f $r.Model, $r.Status, $r.Load, $r.Prefill, $r.GPU)
}
