# ============================================================================
# agentic_test_suite.ps1
# RawrXD Agentic System Test Suite
# Run: powershell -ExecutionPolicy Bypass -File agentic_test_suite.ps1
# ============================================================================

param(
    [string]$Model = "deepseek-r1:8b",
    [string]$Prompt = "What are your capabilities?",
    [switch]$Verbose,
    [switch]$SkipBuild
)

# Colors for output
$Colors = @{
    Success = 'Green'
    Error = 'Red'
    Warning = 'Yellow'
    Info = 'Cyan'
    Header = 'Magenta'
}

function Write-Header($text) {
    Write-Host "`n========================================" -ForegroundColor $Colors.Header
    Write-Host $text -ForegroundColor $Colors.Header
    Write-Host "========================================" -ForegroundColor $Colors.Header
}

function Write-Success($text) {
    Write-Host "[PASS] $text" -ForegroundColor $Colors.Success
}

function Write-Error($text) {
    Write-Host "[FAIL] $text" -ForegroundColor $Colors.Error
}

function Write-Info($text) {
    Write-Host "[INFO] $text" -ForegroundColor $Colors.Info
}

function Write-Warning($text) {
    Write-Host "[WARN] $text" -ForegroundColor $Colors.Warning
}

# Test results
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:TestsTotal = 0

function Start-Test($name) {
    $script:TestsTotal++
    Write-Host "`n[Test $script:TestsTotal] $name" -ForegroundColor White
}

function Complete-Test($success, $message) {
    if ($success) {
        Write-Success $message
        $script:TestsPassed++
    } else {
        Write-Error $message
        $script:TestsFailed++
    }
}

# ============================================================================
# Main Script
# ============================================================================

Write-Header "RawrXD Agentic System Test Suite"
Write-Info "Date: $(Get-Date)"
Write-Info "Model: $Model"
Write-Info "Prompt: $Prompt"

# Test 1: Toolchain Build
Start-Test "Native Toolchain Build"
if (-not $SkipBuild) {
    $toolchainPath = "d:\rawrxd\compilers\native_toolchain"
    if (Test-Path "$toolchainPath\build_toolchain.bat") {
        Write-Info "Building toolchain..."
        Push-Location $toolchainPath
        $output = & .\build_toolchain.bat 2>&1
        Pop-Location
        
        if ($LASTEXITCODE -eq 0 -or $output -match "SUCCESS") {
            Complete-Test $true "Toolchain built successfully"
        } else {
            Complete-Test $false "Toolchain build failed"
        }
        
        if ($Verbose) {
            $output | ForEach-Object { Write-Info $_ }
        }
    } else {
        Complete-Test $false "build_toolchain.bat not found"
    }
} else {
    Write-Info "Skipping build (SkipBuild specified)"
    Complete-Test $true "Build skipped"
}

# Test 2: Toolchain Verification
Start-Test "Toolchain Component Verification"
$tools = @(
    "compilers/native_toolchain/rawrxd_native_assembler.exe",
    "compilers/native_toolchain/rawrxd_native_linker.exe",
    "compilers/native_toolchain/rawrxd_native_librarian.exe",
    "compilers/native_toolchain/rawrxd_native_rc.exe",
    "compilers/native_toolchain/rawrxd_native_debug.exe",
    "compilers/native_toolchain/rawrxd_native_implib.exe",
    "compilers/native_toolchain/rawrxd_native_manifest.exe"
)

$found = 0
foreach ($tool in $tools) {
    $path = Join-Path "d:\rawrxd" $tool
    if (Test-Path $path) {
        $found++
        if ($Verbose) {
            Write-Info "Found: $tool"
        }
    }
}

if ($found -eq $tools.Count) {
    Complete-Test $true "All $($tools.Count) toolchain components present"
} else {
    Complete-Test $false "Only $found/$($tools.Count) components found"
}

# Test 3: Ollama Connectivity
Start-Test "Ollama Connectivity"
try {
    $response = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 10
    if ($response.models) {
        $modelCount = $response.models.Count
        Write-Info "Found $modelCount models in Ollama"
        
        # Check for specified model
        $targetModel = $response.models | Where-Object { $_.name -eq $Model }
        if ($targetModel) {
            Write-Info "Model '$Model' is available"
            Complete-Test $true "Ollama responding, $Model available"
        } else {
            Write-Warning "Model '$Model' not found, but Ollama is responding"
            Complete-Test $true "Ollama responding ($modelCount models)"
        }
    } else {
        Complete-Test $false "Ollama responded but no models found"
    }
} catch {
    Complete-Test $false "Cannot connect to Ollama: $_"
}

# Test 4: Unified Test
Start-Test "Unified Agentic Test"
$unifiedTestPath = "d:\rawrxd\unified_agentic_test.exe"
if (Test-Path $unifiedTestPath) {
    $output = & $unifiedTestPath 2>&1
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -eq 0) {
        Complete-Test $true "Unified test passed"
    } else {
        Complete-Test $false "Unified test failed (exit code: $exitCode)"
    }
    
    if ($Verbose) {
        $output | ForEach-Object { Write-Info $_ }
    }
} else {
    Complete-Test $false "unified_agentic_test.exe not found"
}

# Test 5: Simple Ollama Test
Start-Test "Simple Ollama API Test"
$simpleTestPath = "d:\rawrxd\test_ollama_simple.exe"
if (Test-Path $simpleTestPath) {
    $output = & $simpleTestPath 2>&1
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -eq 0) {
        Complete-Test $true "Ollama API test passed"
    } else {
        Complete-Test $false "Ollama API test failed"
    }
    
    if ($Verbose) {
        $output | ForEach-Object { Write-Info $_ }
    }
} else {
    Complete-Test $false "test_ollama_simple.exe not found"
}

# ============================================================================
# Summary
# ============================================================================

Write-Header "Test Summary"
Write-Host "Total:  $script:TestsTotal" -ForegroundColor White
Write-Host "Passed: $script:TestsPassed" -ForegroundColor $Colors.Success
Write-Host "Failed: $script:TestsFailed" -ForegroundColor $(if ($script:TestsFailed -gt 0) { $Colors.Error } else { $Colors.Success })

if ($script:TestsFailed -eq 0) {
    Write-Header "ALL TESTS PASSED!"
    Write-Host "The RawrXD Agentic System is ready for use." -ForegroundColor $Colors.Success
    Write-Host "`nNext steps:" -ForegroundColor White
    Write-Host "  1. Run: .\test_chat_streaming.exe" -ForegroundColor $Colors.Info
    Write-Host "  2. Run: .\test_deepseek_streaming.exe" -ForegroundColor $Colors.Info
    Write-Host "  3. Integrate with your IDE" -ForegroundColor $Colors.Info
    exit 0
} else {
    Write-Header "SOME TESTS FAILED"
    Write-Host "Please review the output above for details." -ForegroundColor $Colors.Warning
    exit 1
}
