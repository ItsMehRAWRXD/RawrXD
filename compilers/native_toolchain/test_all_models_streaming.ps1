# test_all_models_streaming.ps1 - Test All GGUF Models with Streaming Engine
# Tests all models from F:\OllamaModels with the Sovereign Streaming Engine

param(
    [string]$ModelsPath = "F:\OllamaModels",
    [string]$LoaderPath = ".\sovereign_streaming_engine.dll",
    [string]$TestExePath = ".\test_sovereign_streaming.exe"
)

Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD Sovereign Streaming Engine - Model Test Suite         ║" -ForegroundColor Cyan
Write-Host "║                                                                  ║" -ForegroundColor Cyan
Write-Host "║  Tests all GGUF models with streaming inference engine           ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Write-Host "Models Path: $ModelsPath" -ForegroundColor Yellow
Write-Host "Loader Path: $LoaderPath" -ForegroundColor Yellow
Write-Host "Test Exe Path: $TestExePath" -ForegroundColor Yellow
Write-Host ""

# Check if paths exist
if (-not (Test-Path $ModelsPath)) {
    Write-Host "ERROR: Models path not found: $ModelsPath" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $LoaderPath)) {
    Write-Host "ERROR: Loader not found: $LoaderPath" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $TestExePath)) {
    Write-Host "ERROR: Test executable not found: $TestExePath" -ForegroundColor Red
    exit 1
}

# Find all GGUF files
$models = Get-ChildItem -Path $ModelsPath -Filter "*.gguf" -File | Sort-Object Name

Write-Host "Found $($models.Count) GGUF models" -ForegroundColor Green
Write-Host ""

# Test results
$results = @()
$passed = 0
$failed = 0

# Test each model
foreach ($model in $models) {
    Write-Host "Testing: $($model.Name)" -ForegroundColor Cyan
    Write-Host "  Size: $([math]::Round($model.Length / 1GB, 2)) GB" -ForegroundColor Yellow
    
    $result = @{
        Name = $model.Name
        Path = $model.FullName
        Size = $model.Length
        SizeGB = [math]::Round($model.Length / 1GB, 2)
        Valid = $false
        Status = "Unknown"
        Error = ""
        LoadTime = 0
        TensorCount = 0
        MetadataCount = 0
    }
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        # Run test
        $output = & $TestExePath $model.FullName 2>&1 | Out-String
        $stopwatch.Stop()
        
        $result.LoadTime = $stopwatch.ElapsedMilliseconds
        
        # Parse output
        if ($output -match "Model loaded successfully") {
            $result.Valid = $true
            $result.Status = "Valid"
            
            # Extract tensor count
            if ($output -match "Tensors: (\d+)") {
                $result.TensorCount = [int]$matches[1]
            }
            
            # Extract metadata count
            if ($output -match "Metadata: (\d+)") {
                $result.MetadataCount = [int]$matches[1]
            }
            
            Write-Host "  [PASS] Valid GGUF format" -ForegroundColor Green
            Write-Host "  Tensors: $($result.TensorCount)" -ForegroundColor Yellow
            Write-Host "  Metadata: $($result.MetadataCount)" -ForegroundColor Yellow
            Write-Host "  Load time: $($result.LoadTime)ms" -ForegroundColor Yellow
            $passed++
        } else {
            $result.Status = "Load failed"
            $result.Error = $output
            Write-Host "  [FAIL] Load failed" -ForegroundColor Red
            Write-Host "  Error: $($result.Error)" -ForegroundColor Red
            $failed++
        }
    } catch {
        $stopwatch.Stop()
        $result.LoadTime = $stopwatch.ElapsedMilliseconds
        $result.Status = "Exception"
        $result.Error = $_.Exception.Message
        Write-Host "  [FAIL] Exception: $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
    
    $results += $result
    Write-Host ""
}

# Summary
Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                        TEST SUMMARY                              " -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

Write-Host "Total Models: $($models.Count)" -ForegroundColor White
Write-Host "Passed: $passed" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor Red
Write-Host ""

# Detailed results
Write-Host "Detailed Results:" -ForegroundColor Cyan
Write-Host ""

$results | Format-Table -Property Name, SizeGB, Status, TensorCount, MetadataCount, LoadTime -AutoSize

# Save results to JSON
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$jsonFile = "streaming_test_results_$timestamp.json"
$results | ConvertTo-Json -Depth 3 | Out-File -FilePath $jsonFile -Encoding UTF8

Write-Host "Results saved to: $jsonFile" -ForegroundColor Yellow

# Final status
if ($failed -eq 0) {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                    ALL TESTS PASSED!                             ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║                    SOME TESTS FAILED                             ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
}

exit $failed