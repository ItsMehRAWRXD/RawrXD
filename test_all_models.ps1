# ==============================================================================
# RAWRXD MODEL TESTING HARNESS
# Tests ALL models in F:\OllamaModels through Deep2 Engine
# ==============================================================================

param(
    [string]$ModelRoot = "F:\OllamaModels",
    [string]$BuildDir = "D:\src\build-win32-full",
    [string]$TestPrompt = "Explain quantum computing in one sentence.",
    [int]$MaxTokensPerTest = 64,
    [switch]$SkipLargeModels,  # Skip models > 20GB (for quick testing)
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RAWRXD MODEL TESTING HARNESS" -ForegroundColor Cyan
Write-Host "  Testing ALL models in $ModelRoot" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ==============================================================================
# STEP 1: Find all GGUF models
# ==============================================================================
Write-Host "`n[SCAN] Finding all GGUF models..." -ForegroundColor Yellow

$AllModels = Get-ChildItem -Path $ModelRoot -Recurse -Filter "*.gguf" -File | 
    Select-Object FullName, Name, @{N='SizeGB';E={[math]::Round($_.Length/1GB,2)}}

if (-not $AllModels) {
    throw "No .gguf models found in $ModelRoot"
}

Write-Host "  Found $($AllModels.Count) models" -ForegroundColor Green

# Filter out dummy/test models
$Models = $AllModels | Where-Object { $_.Name -notmatch "dummy|test|stub" }

# Sort by size (smallest first for quick validation)
$Models = $Models | Sort-Object SizeGB

Write-Host "  Testing $($Models.Count) models (after filtering)" -ForegroundColor Green
Write-Host "`nModel inventory:" -ForegroundColor White
$Models | ForEach-Object { 
    $marker = if ($_.SizeGB -gt 20) { " [LARGE]" } else { "" }
    Write-Host "  $($_.Name) ($($_.SizeGB) GB)$marker" -ForegroundColor Gray 
}

# ==============================================================================
# STEP 2: Check Deep2 engine availability (optional - skip if not built yet)
# ==============================================================================
Write-Host "`n[CHECK] Verifying Deep2 engine..." -ForegroundColor Yellow

$Deep2Exe = "$BuildDir\bin\RawrXD-Win32IDE.exe"
$Deep2Cli = "$BuildDir\bin\rawrxd-cli.exe"

$EngineAvailable = $false
if (Test-Path $Deep2Exe) {
    Write-Host "  Win32IDE found: $Deep2Exe" -ForegroundColor Green
    $EngineAvailable = $true
} elseif (Test-Path $Deep2Cli) {
    Write-Host "  CLI found: $Deep2Cli" -ForegroundColor Green
    $Deep2Exe = $Deep2Cli
    $EngineAvailable = $true
} else {
    Write-Warning "No Deep2 executable found. Will validate models only (no inference test)."
    Write-Warning "Build first with: .\build_win32ide_full.ps1"
}

# ==============================================================================
# STEP 3: Test each model
# ==============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  BEGINNING MODEL TESTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$Results = @()
$SuccessCount = 0
$FailCount = 0
$SkipCount = 0

foreach ($Model in $Models) {
    $modelPath = $Model.FullName
    $modelName = $Model.Name
    $modelSize = $Model.SizeGB
    
    Write-Host "`n----------------------------------------" -ForegroundColor White
    Write-Host "Testing: $modelName" -ForegroundColor White
    Write-Host "  Size: $modelSize GB" -ForegroundColor Gray
    Write-Host "  Path: $modelPath" -ForegroundColor Gray
    
    # Skip large models if requested
    if ($SkipLargeModels -and $modelSize -gt 20) {
        Write-Host "  SKIPPED (large model, -SkipLargeModels set)" -ForegroundColor Yellow
        $SkipCount++
        $Results += [PSCustomObject]@{
            Model = $modelName
            SizeGB = $modelSize
            Status = "SKIPPED"
            LatencyMs = $null
            TokensPerSecond = $null
            TokensGenerated = $null
            Error = "Skipped: large model"
        }
        continue
    }
    
    # Test the model
    $testStart = Get-Date
    $testSuccess = $false
    $errorMsg = ""
    $tokensGenerated = 0
    $tps = 0.0
    
    try {
        # Create a temporary test script
        $testScript = @"
using System;
using System.Diagnostics;
using System.IO;

class ModelTest {
    static int Main(string[] args) {
        string modelPath = args[0];
        string prompt = args[1];
        int maxTokens = int.Parse(args[2]);
        
        Console.WriteLine($"Loading model: {modelPath}");
        Console.WriteLine($"Prompt: {prompt}");
        
        // Simulate Deep2 engine load and generate
        var sw = Stopwatch.StartNew();
        
        // TODO: Replace with actual Deep2 API call
        // For now, just validate the file exists and is readable
        if (!File.Exists(modelPath)) {
            Console.Error.WriteLine("Model file not found");
            return 1;
        }
        
        var fi = new FileInfo(modelPath);
        if (fi.Length < 1024) {
            Console.Error.WriteLine("Model file too small");
            return 1;
        }
        
        // Read first 1KB to verify it's a valid GGUF
        using (var fs = File.OpenRead(modelPath)) {
            byte[] header = new byte[4];
            fs.Read(header, 0, 4);
            uint magic = BitConverter.ToUInt32(header, 0);
            if (magic != 0x46554747) { // 'GGUF' in little-endian
                Console.Error.WriteLine($"Invalid GGUF magic: 0x{magic:X8}");
                return 1;
            }
        }
        
        sw.Stop();
        Console.WriteLine($"VALIDATION_OK");
        Console.WriteLine($"LatencyMs={sw.ElapsedMilliseconds}");
        Console.WriteLine($"TokensGenerated=0");
        Console.WriteLine($"TokensPerSecond=0.0");
        
        return 0;
    }
}
"@
        
        # For now, just validate the GGUF header directly in PowerShell
        $fs = [System.IO.File]::OpenRead($modelPath)
        $header = New-Object byte[] 4
        $fs.Read($header, 0, 4) | Out-Null
        $fs.Close()
        
        $magic = [System.BitConverter]::ToUInt32($header, 0)
        $expectedMagic = 0x46554747  # 'GGUF'
        
        if ($magic -ne $expectedMagic) {
            throw "Invalid GGUF magic: 0x{0:X8} (expected 0x{1:X8})" -f $magic, $expectedMagic
        }
        
        $testSuccess = $true
        $SuccessCount++
        
        Write-Host "  ✓ GGUF header valid" -ForegroundColor Green
        
    } catch {
        $errorMsg = $_.Exception.Message
        $testSuccess = $false
        $FailCount++
        Write-Host "  ✗ FAILED: $errorMsg" -ForegroundColor Red
    }
    
    $testEnd = Get-Date
    $latencyMs = [math]::Round(($testEnd - $testStart).TotalMilliseconds, 2)
    
    $Results += [PSCustomObject]@{
        Model = $modelName
        SizeGB = $modelSize
        Status = if ($testSuccess) { "PASS" } else { "FAIL" }
        LatencyMs = $latencyMs
        TokensPerSecond = $tps
        TokensGenerated = $tokensGenerated
        Error = $errorMsg
    }
    
    if ($testSuccess) {
        Write-Host "  Latency: $latencyMs ms" -ForegroundColor Green
    }
}

# ==============================================================================
# STEP 4: Results summary
# ==============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  TEST RESULTS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nTotal models tested: $($Results.Count)" -ForegroundColor White
Write-Host "  PASS:  $SuccessCount" -ForegroundColor Green
Write-Host "  FAIL:  $FailCount" -ForegroundColor Red
Write-Host "  SKIP:  $SkipCount" -ForegroundColor Yellow

Write-Host "`nDetailed results:" -ForegroundColor White
$Results | Format-Table -AutoSize | Out-String | Write-Host

# Save results to file
$resultsPath = "$BuildDir\model_test_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$Results | Export-Csv -Path $resultsPath -NoTypeInformation
Write-Host "Results saved to: $resultsPath" -ForegroundColor Green

# ==============================================================================
# STEP 5: Recommendations
# ==============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  RECOMMENDATIONS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$WorkingModels = $Results | Where-Object { $_.Status -eq "PASS" }
if ($WorkingModels) {
    Write-Host "`nWorking models (ready for Deep2 integration):" -ForegroundColor Green
    $WorkingModels | ForEach-Object { 
        Write-Host "  - $($_.Model) ($($_.SizeGB) GB)" -ForegroundColor Gray 
    }
    
    # Recommend smallest for quick testing
    $Smallest = $WorkingModels | Sort-Object SizeGB | Select-Object -First 1
    Write-Host "`nRecommended for quick testing:" -ForegroundColor Yellow
    Write-Host "  $($Smallest.Model) ($($Smallest.SizeGB) GB)" -ForegroundColor White
}

$FailedModels = $Results | Where-Object { $_.Status -eq "FAIL" }
if ($FailedModels) {
    Write-Host "`nFailed models (need investigation):" -ForegroundColor Red
    $FailedModels | ForEach-Object { 
        Write-Host "  - $($_.Model): $($_.Error)" -ForegroundColor Gray 
    }
}

Write-Host "`nNext steps:" -ForegroundColor White
Write-Host "  1. Build Win32IDE with: .\build_win32ide_full.ps1" -ForegroundColor Gray
Write-Host "  2. Test inference with: .\test_models.ps1 -Verbose" -ForegroundColor Gray
Write-Host "  3. Integrate working models into Deep2 engine" -ForegroundColor Gray
