# RawrXD_Ring_Smoke_Test_Build.ps1
# Build and run automated ring smoke test suite

param(
    [switch]$Clean,
    [switch]$Run,
    [switch]$CI,           # CI mode - outputs JSON for automation
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Paths
$MASM_PATH = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$LINK_PATH = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
$SRC_DIR = "D:\RawrXD"
$OBJ_DIR = "$SRC_DIR\obj"
$BIN_DIR = "$SRC_DIR\bin"

# Test configuration
$TEST_CONFIG = @{
    RING_NODES = 4
    CONTEXT_SIZE = 4096
    LAYER_COUNT = 16
    MAX_TEST_TIME_MS = 30000
    THROUGHPUT_MIN_TPS = 250
    PROTOCOL_EFF_MIN = 85
}

# Create directories
if (!(Test-Path $OBJ_DIR)) { New-Item -ItemType Directory -Path $OBJ_DIR -Force | Out-Null }
if (!(Test-Path $BIN_DIR)) { New-Item -ItemType Directory -Path $BIN_DIR -Force | Out-Null }

# Clean if requested
if ($Clean) {
    Write-Host "Cleaning build artifacts..." -ForegroundColor Yellow
    Remove-Item "$OBJ_DIR\*" -ErrorAction SilentlyContinue
    Remove-Item "$BIN_DIR\*" -ErrorAction SilentlyContinue
}

Write-Host "Building RawrXD Ring Attention Smoke Test Suite..." -ForegroundColor Cyan
Write-Host ""

# Build steps
$buildSteps = @(
    @{
        Name = "Error Recovery"
        Source = "$SRC_DIR\RawrXD_Error_Recovery.asm"
        Object = "$OBJ_DIR\RawrXD_Error_Recovery.obj"
    },
    @{
        Name = "Ring Attention"
        Source = "$SRC_DIR\RawrXD_Ring_Attention_Simple.asm"
        Object = "$OBJ_DIR\RawrXD_Ring_Attention_Simple.obj"
    },
    @{
        Name = "Smoke Test"
        Source = "$SRC_DIR\RawrXD_Ring_Smoke_Test.asm"
        Object = "$OBJ_DIR\RawrXD_Ring_Smoke_Test.obj"
    }
)

# Assemble each module
$stepNum = 0
foreach ($step in $buildSteps) {
    $stepNum++
    Write-Host "[$stepNum/$($buildSteps.Count)] Assembling $($step.Name)..." -NoNewline
    
    try {
        $result = & $MASM_PATH `
            /c /W3 /nologo /Zi `
            /Fo "$($step.Object)" `
            "$($step.Source)" 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Host $result
            exit 1
        }
        Write-Host " OK" -ForegroundColor Green
    } catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host $_
        exit 1
    }
}

# Link executable
Write-Host "[$($buildSteps.Count + 1)/$($buildSteps.Count + 1)] Linking executable..." -NoNewline
try {
    $linkResult = & $LINK_PATH `
        /SUBSYSTEM:CONSOLE `
        /ENTRY:main `
        /OUT:"$BIN_DIR\RawrXD_Ring_Smoke_Test.exe" `
        "$OBJ_DIR\RawrXD_Ring_Smoke_Test.obj" `
        "$OBJ_DIR\RawrXD_Ring_Attention_Simple.obj" `
        "$OBJ_DIR\RawrXD_Error_Recovery.obj" `
        kernel32.lib `
        ucrt.lib `
        legacy_stdio_definitions.lib `
        /NODEFAULTLIB:libucrt.lib 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host $linkResult
        exit 1
    }
    Write-Host " OK" -ForegroundColor Green
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host $_
    exit 1
}

Write-Host ""
Write-Host "Build successful!" -ForegroundColor Green
Write-Host "  Binary: $BIN_DIR\RawrXD_Ring_Smoke_Test.exe" -ForegroundColor Gray

# Run tests if requested
if ($Run -or $CI) {
    Write-Host ""
    Write-Host "Running smoke test suite..." -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor DarkGray
    
    $testOutput = & "$BIN_DIR\RawrXD_Ring_Smoke_Test.exe" 2>&1
    $testExit = $LASTEXITCODE
    
    Write-Host $testOutput
    Write-Host "========================================" -ForegroundColor DarkGray
    
    # Parse results for CI
    if ($CI) {
        $results = @{
            timestamp = (Get-Date -Format "o")
            build_status = "success"
            test_results = @{
                total = 4
                passed = 0
                failed = 0
                tests = @()
            }
            metrics = @{}
        }
        
        # Parse test output
        if ($testOutput -match "Passed: (\d+)/(\d+)") {
            $results.test_results.passed = [int]$matches[1]
            $results.test_results.failed = [int]$matches[2] - $matches[1]
        }
        
        # Extract metrics from output
        if ($testOutput -match "TPS: ([\d.]+)") {
            $results.metrics.tps = [float]$matches[1]
        }
        if ($testOutput -match "Rotations: (\d+)") {
            $results.metrics.ring_rotations = [int]$matches[1]
        }
        if ($testOutput -match "Efficiency: ([\d.]+)%") {
            $results.metrics.protocol_efficiency = [float]$matches[1]
        }
        
        # Output JSON for CI
        $jsonOutput = $results | ConvertTo-Json -Depth 10
        Write-Host ""
        Write-Host "CI Test Results (JSON):" -ForegroundColor Yellow
        Write-Host $jsonOutput
        
        # Save to file
        $jsonOutput | Out-File "$BIN_DIR\smoke_test_results.json" -Encoding UTF8
    }
    
    if ($testExit -eq 0) {
        Write-Host "All smoke tests passed!" -ForegroundColor Green
    } else {
        Write-Host "Some smoke tests failed (exit code: $testExit)" -ForegroundColor Red
        if ($CI) {
            exit $testExit
        }
    }
}

Write-Host ""
Write-Host "Usage:" -ForegroundColor Yellow
Write-Host "  .\RawrXD_Ring_Smoke_Test_Build.ps1 -Run      # Build and run tests"
Write-Host "  .\RawrXD_Ring_Smoke_Test_Build.ps1 -CI       # CI mode (JSON output)"
Write-Host "  .\RawrXD_Ring_Smoke_Test_Build.ps1 -Clean    # Clean build"
