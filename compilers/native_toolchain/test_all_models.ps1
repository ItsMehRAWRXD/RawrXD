<#
.SYNOPSIS
    Comprehensive GGUF Model Test Suite for RawrXD Native Toolchain
.DESCRIPTION
    Tests all GGUF models on F:\OllamaModels with the native toolchain
    Validates model format, metadata, and tensor structure
.PARAMETER ModelsPath
    Path to the models directory (default: F:\OllamaModels)
.PARAMETER LoaderPath
    Path to the GGUF loader executable (default: .\gguf_mini_loader.exe)
.PARAMETER Verbose
    Show detailed output for each model
.EXAMPLE
    .\test_all_models.ps1 -Verbose
    .\test_all_models.ps1 -ModelsPath "F:\OllamaModels" -LoaderPath ".\gguf_mini_loader.exe"
#>

param(
    [string]$ModelsPath = "F:\OllamaModels",
    [string]$LoaderPath = ".\gguf_mini_loader.exe",
    [switch]$Verbose,
    [switch]$SkipLargeModels
)

# Colors for output
$Colors = @{
    Header = "Cyan"
    Pass = "Green"
    Fail = "Red"
    Warning = "Yellow"
    Info = "White"
    Model = "Magenta"
}

function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Colors[$Color]
}

function Test-GGUFModel {
    param([string]$ModelPath, [string]$LoaderPath, [bool]$Verbose)
    
    $result = @{
        Name = Split-Path $ModelPath -Leaf
        Path = $ModelPath
        Size = (Get-Item $ModelPath).Length
        SizeGB = [math]::Round((Get-Item $ModelPath).Length / 1GB, 2)
        Valid = $false
        Version = 0
        TensorCount = 0
        MetadataCount = 0
        DataOffset = 0
        Status = "Unknown"
        Error = ""
        LoadTime = 0
    }
    
    # Skip large models if requested
    if ($SkipLargeModels -and $result.SizeGB -gt 20) {
        $result.Status = "Skipped (too large)"
        return $result
    }
    
    # Test with GGUF loader (use verbose mode for full parsing)
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        # Use verbose mode directly for full parsing
        $outputArray = & $LoaderPath $ModelPath -v 2>&1
        $stopwatch.Stop()
        $result.LoadTime = $stopwatch.ElapsedMilliseconds
        
        # Join output array into single string for regex matching
        $output = $outputArray -join "`n"
        
        if ($LASTEXITCODE -eq 0) {
            $result.Valid = $true
            $result.Status = "Valid"
            
            # Parse version
            if ($output -match "\[INFO\]\s*Version:\s*(\d+)") {
                $result.Version = [int]$matches[1]
            }
            
            # Parse tensor count
            if ($output -match "\[INFO\]\s*Tensor count:\s*(\d+)") {
                $result.TensorCount = [int]$matches[1]
            }
            
            # Parse metadata count
            if ($output -match "\[INFO\]\s*Metadata KV pairs:\s*(\d+)") {
                $result.MetadataCount = [int]$matches[1]
            }
            
            # Parse data offset
            if ($output -match "Data offset:\s*(\d+)\s*bytes") {
                $result.DataOffset = [int]$matches[1]
            }
            
            # Check if model has tensors
            if ($result.TensorCount -eq 0) {
                $result.Status = "Placeholder (no tensors)"
                $result.Valid = $false
            }
        } else {
            $result.Status = "Load failed"
            $result.Error = $output
        }
    } catch {
        $stopwatch.Stop()
        $result.LoadTime = $stopwatch.ElapsedMilliseconds
        $result.Status = "Exception"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-ColorOutput "╔══════════════════════════════════════════════════════════════════╗" "Header"
Write-ColorOutput "║     RawrXD GGUF Model Test Suite - Native Toolchain              ║" "Header"
Write-ColorOutput "║                                                                  ║" "Header"
Write-ColorOutput "║  Tests all GGUF models with native loader                       ║" "Header"
Write-ColorOutput "║  Validates format, metadata, and tensor structure                ║" "Header"
Write-ColorOutput "╚══════════════════════════════════════════════════════════════════╝" "Header"
Write-Host ""

Write-ColorOutput "Models Path: $ModelsPath" "Info"
Write-ColorOutput "Loader Path: $LoaderPath" "Info"
Write-Host ""

# Check if loader exists
if (-not (Test-Path $LoaderPath)) {
    Write-ColorOutput "[ERROR] Loader not found: $LoaderPath" "Fail"
    exit 1
}

# Find all GGUF models
$models = Get-ChildItem -Path $ModelsPath -Filter "*.gguf" -Recurse -File | 
    Where-Object { $_.Length -gt 0 } | 
    Sort-Object Length -Descending

if ($models.Count -eq 0) {
    Write-ColorOutput "[ERROR] No GGUF models found in: $ModelsPath" "Fail"
    exit 1
}

Write-ColorOutput "Found $($models.Count) GGUF models" "Info"
Write-Host ""

# Test each model
$results = @()
$passed = 0
$failed = 0
$skipped = 0

foreach ($model in $models) {
    Write-ColorOutput "Testing: $($model.Name)" "Model"
    Write-ColorOutput "  Size: $([math]::Round($model.Length / 1GB, 2)) GB" "Info"
    
    $result = Test-GGUFModel -ModelPath $model.FullName -LoaderPath $LoaderPath -Verbose $Verbose
    $results += $result
    
    if ($result.Valid) {
        Write-ColorOutput "  [PASS] Valid GGUF format" "Pass"
        Write-ColorOutput "  Version: $($result.Version)" "Info"
        Write-ColorOutput "  Tensors: $($result.TensorCount)" "Info"
        Write-ColorOutput "  Metadata: $($result.MetadataCount)" "Info"
        Write-ColorOutput "  Load time: $($result.LoadTime)ms" "Info"
        $passed++
    } else {
        if ($result.Status -eq "Skipped (too large)") {
            Write-ColorOutput "  [SKIP] $($result.Status)" "Warning"
            $skipped++
        } else {
            Write-ColorOutput "  [FAIL] $($result.Status)" "Fail"
            if ($result.Error) {
                Write-ColorOutput "  Error: $($result.Error)" "Fail"
            }
            $failed++
        }
    }
    
    if ($Verbose) {
        Write-ColorOutput "  Full output:" "Info"
        & $LoaderPath $model.FullName -v 2>&1 | ForEach-Object { Write-Host "    $_" }
    }
    
    Write-Host ""
}

# Summary
Write-ColorOutput "══════════════════════════════════════════════════════════════════" "Header"
Write-ColorOutput "                        TEST SUMMARY                              " "Header"
Write-ColorOutput "══════════════════════════════════════════════════════════════════" "Header"
Write-Host ""

Write-ColorOutput "Total Models: $($models.Count)" "Info"
Write-ColorOutput "Passed: $passed" "Pass"
Write-ColorOutput "Failed: $failed" "Fail"
Write-ColorOutput "Skipped: $skipped" "Warning"
Write-Host ""

# Detailed results
Write-ColorOutput "Detailed Results:" "Header"
$results | Select-Object Name, SizeGB, Status, TensorCount, MetadataCount, LoadTime | 
    Format-Table -AutoSize | Out-String | Write-Host

# Save results to JSON
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$jsonPath = "model_test_results_$timestamp.json"
$results | ConvertTo-Json -Depth 10 | Out-File $jsonPath
Write-ColorOutput "Results saved to: $jsonPath" "Info"

# Return exit code
if ($failed -gt 0) {
    exit 1
} else {
    exit 0
}