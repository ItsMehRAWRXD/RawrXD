# RawrXD Test Result Exporter
# Exports test results to JSON for dashboard consumption

param(
    [string]$OutputDir = "reports",
    [switch]$IncludePerformance = $true,
    [switch]$IncludeStress = $true
)

$ErrorActionPreference = "Stop"

# Ensure output directory exists
$OutputPath = Join-Path $PSScriptRoot $OutputDir
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-Host "RawrXD Test Result Exporter" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host ""

# Test categories and their executables
$TestCategories = @{
    "CPU" = @("cpu\test_avx2_rmsnorm.exe", "cpu\test_avx2_softmax.exe")
    "Tokenizer" = @("tokenizer\test_bpe_tokenizer.exe")
    "GGUF" = @("gguf\test_gguf_magic.exe")
    "Kernels" = @(
        "kernels\test_attention.exe",
        "kernels\test_gelu_activation.exe",
        "kernels\test_layer_norm.exe",
        "kernels\test_matmul.exe",
        "kernels\test_rms_norm.exe",
        "kernels\test_rope.exe",
        "kernels\test_silu_activation.exe",
        "kernels\test_softmax.exe"
    )
    "Sampler" = @("sampler\test_temperature.exe")
    "Integration" = @("integration\test_inference_pipeline.exe")
    "Regression" = @("regression\test_regression.exe")
    "Performance" = @("performance\test_perf_quick.exe")
    "Stress" = @("stress\test_fuzz.exe", "stress\test_memory.exe")
}

$Results = @{
    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
    version = "15.0.0-dev"
    summary = @{
        total = 0
        passed = 0
        failed = 0
    }
    categories = @()
    tests = @()
}

$TotalTests = 0
$PassedTests = 0
$FailedTests = 0

# Run each category
foreach ($Category in $TestCategories.GetEnumerator()) {
    $CategoryName = $Category.Key
    $Executables = $Category.Value
    
    $CategoryTests = 0
    $CategoryPassed = 0
    
    Write-Host "[$CategoryName]" -ForegroundColor Yellow
    
    foreach ($Exe in $Executables) {
        $ExePath = Join-Path $PSScriptRoot $Exe
        $TestName = [System.IO.Path]::GetFileNameWithoutExtension($Exe)
        
        if (Test-Path $ExePath) {
            $StartTime = Get-Date
            
            try {
                $Process = Start-Process -FilePath $ExePath -WorkingDirectory $PSScriptRoot `
                    -Wait -PassThru -WindowStyle Hidden
                $ExitCode = $Process.ExitCode
            }
            catch {
                $ExitCode = 1
            }
            
            $EndTime = Get-Date
            $Duration = ($EndTime - $StartTime).TotalMilliseconds
            
            $Status = if ($ExitCode -eq 0) { "PASS" } else { "FAIL" }
            
            $TestResult = @{
                name = $TestName
                category = $CategoryName
                status = $Status
                time = "{0:N1}ms" -f $Duration
                exit_code = $ExitCode
            }
            
            $Results.tests += $TestResult
            
            $TotalTests++
            $CategoryTests++
            
            if ($ExitCode -eq 0) {
                $PassedTests++
                $CategoryPassed++
                Write-Host "  [PASS] $TestName" -ForegroundColor Green
            }
            else {
                $FailedTests++
                Write-Host "  [FAIL] $TestName" -ForegroundColor Red
            }
        }
        else {
            Write-Host "  [SKIP] $TestName (not found)" -ForegroundColor Gray
        }
    }
    
    $Results.categories += @{
        name = $CategoryName
        tests = $CategoryTests
        passed = $CategoryPassed
    }
    
    Write-Host ""
}

# Update summary
$Results.summary.total = $TotalTests
$Results.summary.passed = $PassedTests
$Results.summary.failed = $FailedTests

# Export to JSON
$JsonOutput = $Results | ConvertTo-Json -Depth 10
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile = Join-Path $OutputPath "report_$Timestamp.json"
$LatestFile = Join-Path $OutputPath "latest.json"

$JsonOutput | Out-File -FilePath $ReportFile -Encoding UTF8
$JsonOutput | Out-File -FilePath $LatestFile -Encoding UTF8

# Summary
Write-Host "==========================" -ForegroundColor Cyan
Write-Host "Export Complete" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host "Total Tests:  $TotalTests"
Write-Host "Passed:       $PassedTests" -ForegroundColor Green
Write-Host "Failed:       $FailedTests" -ForegroundColor $(if ($FailedTests -gt 0) { "Red" } else { "Green" })
Write-Host ""
Write-Host "Reports saved:" -ForegroundColor Cyan
Write-Host "  $ReportFile"
Write-Host "  $LatestFile"

if ($FailedTests -eq 0) {
    Write-Host "`n✓ All tests passed!" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "`n✗ Some tests failed" -ForegroundColor Red
    exit 1
}
