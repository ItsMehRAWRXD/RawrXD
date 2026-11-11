# Production Verification Script
# Verifies all compilers produce correct output

$OUTPUT_DIR = "d:\rawrxd\compilers\production_build"
Set-Location $OUTPUT_DIR

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PRODUCTION COMPILER VERIFICATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$compilers = @(
    "universal_compiler_runtime.exe",
    "bash_compiler_from_scratch.exe",
    "powershell_compiler_from_scratch.exe",
    "eon_bootstrap_compiler.exe",
    "universal_cross_platform_compiler.exe",
    "omega_pro.exe",
    "omega_pro_v3.exe"
)

$verified = 0
$failed = 0

foreach ($compiler in $compilers) {
    $exePath = Join-Path $OUTPUT_DIR $compiler
    if (-not (Test-Path $exePath)) {
        Write-Host "`n$compiler : MISSING" -ForegroundColor Red
        $failed++
        continue
    }
    
    # Run and capture output
    $outputFile = "temp_output.txt"
    $proc = Start-Process -FilePath $exePath -RedirectStandardOutput $outputFile -PassThru -Wait -WindowStyle Hidden
    $output = Get-Content $outputFile -Raw -ErrorAction SilentlyContinue
    
    # Check for success indicators
    $hasBanner = $output -match "v1\.0"
    $hasReady = $output -match "\[READY\]"
    $hasPass = $output -match "\[TEST\] PASS"
    $hasExit = $output -match "\[EXIT\]"
    
    if ($hasBanner -and $hasReady -and $hasPass -and $hasExit) {
        Write-Host "`n$compiler : VERIFIED" -ForegroundColor Green
        Write-Host "  Size: $((Get-Item $exePath).Length) bytes" -ForegroundColor Gray
        Write-Host "  Output: $($output.Trim().Replace("`r`n", " | "))" -ForegroundColor DarkGray
        $verified++
    } else {
        Write-Host "`n$compiler : FAILED" -ForegroundColor Red
        Write-Host "  Output: $output" -ForegroundColor DarkGray
        $failed++
    }
}

# Cleanup
Remove-Item "temp_output.txt" -ErrorAction SilentlyContinue

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "VERIFICATION COMPLETE" -ForegroundColor Cyan
Write-Host "Verified: $verified, Failed: $failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "========================================" -ForegroundColor Cyan

if ($failed -eq 0) {
    Write-Host "`nALL COMPILERS PRODUCTION READY" -ForegroundColor Green
    exit 0
} else {
    exit 1
}
