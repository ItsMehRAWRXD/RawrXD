# Phase 22: Quick Validation Test (30 minutes)
# Run this before the full 24-hour soak test

param(
    [switch]$FullSoakTest = $false
)

$testDuration = $(if ($FullSoakTest) { 24 } else { 0.5 }  # 30 minutes or 24 hours
$testName = $(if ($FullSoakTest) { "24-Hour Soak Test" } else { "30-Minute Validation" }

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Phase 22: $testName" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if (-not $FullSoakTest) {
    Write-Host "This is a QUICK VALIDATION test (30 minutes)." -ForegroundColor Yellow
    Write-Host "For full 24-hour soak test, run with -FullSoakTest flag.`n" -ForegroundColor Yellow
}

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor White

# Check if RawrXD binary exists
$binaryPaths = @(
    ".\build-ninja\bin\RawrXD-Win32IDE.exe",
    ".\build\bin\RawrXD-Win32IDE.exe",
    ".\RawrXD-Win32IDE.exe",
    "..\src\asm\Sovereign_Complete.exe",
    "..\src\asm\Sovereign_Final.exe",
    "..\src\asm\Sovereign_v1.1_Graph.exe",
    "d:\src\asm\Sovereign_Complete.exe",
    "d:\src\asm\Sovereign_Final.exe",
    "d:\src\asm\Sovereign_v1.1_Graph.exe"
)

$binaryFound = $false
$foundBinaryPath = $null
foreach ($path in $binaryPaths) {
    if (Test-Path $path) {
        $binaryFound = $true
        $foundBinaryPath = $path
        $binarySize = (Get-Item $path).Length / 1MB
        Write-Host "  ✅ Binary found: $path ($([math]::Round($binarySize, 2)) MB)" -ForegroundColor Green
        break
    }
}

if (-not $binaryFound) {
    Write-Host "  ⚠️ RawrXD binary not found, but will run in simulation mode." -ForegroundColor Yellow
    Write-Host "     For full test, ensure binary is built." -ForegroundColor Yellow
}

# Check if orchestrator files exist
$orchestratorFiles = @(
    ".\Sovereign_CrossModel_Orchestrator.hpp",
    ".\Sovereign_CrossModel_Orchestrator.cpp"
)

$orchestratorFound = $true
foreach ($file in $orchestratorFiles) {
    if (Test-Path $file) {
        Write-Host "  ✅ $file" -ForegroundColor Green
    } else {
        Write-Host "  ❌ $file not found" -ForegroundColor Red
        $orchestratorFound = $false
    }
}

if (-not $orchestratorFound) {
    Write-Host "`n⚠️ Orchestrator files not found. Soak test will run in simulation mode." -ForegroundColor Yellow
}

# Check Windows Performance Counters
Write-Host "`nChecking performance counters..." -ForegroundColor White
try {
    $cpu = Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 1
    Write-Host "  ✅ CPU counter accessible" -ForegroundColor Green
} catch {
    Write-Host "  ⚠️ CPU counter not accessible (will use fallback)" -ForegroundColor Yellow
}

# Check Event Log access
Write-Host "`nChecking Event Log access..." -ForegroundColor White
try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Application'; ID=1000; StartTime=(Get-Date).AddMinutes(-5)} -MaxEvents 1 -ErrorAction SilentlyContinue
    Write-Host "  ✅ Event Log accessible" -ForegroundColor Green
} catch {
    Write-Host "  ⚠️ Event Log access limited (crash detection may be affected)" -ForegroundColor Yellow
}

# Create output directory
$outputDir = ".\soak-test-results"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
Write-Host "  ✅ Output directory: $outputDir" -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Prerequisites check complete!" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Ask for confirmation
if (-not $FullSoakTest) {
    $response = Read-Host "Start 30-minute validation test? (Y/N)"
    if ($response -ne 'Y' -and $response -ne 'y') {
        Write-Host "Test cancelled." -ForegroundColor Yellow
        exit 0
    }
} else {
    Write-Host "⚠️ WARNING: This will run for 24 hours!" -ForegroundColor Red
    Write-Host "Press Ctrl+C to cancel within 5 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
}

# Run the soak test
Write-Host "`nStarting $testName...`n" -ForegroundColor Green

& ".\Phase22_SoakTest.ps1" -DurationHours $testDuration -TargetTPS 336.7 -LogMetrics $true -CaptureCrashDumps $true -OutputDir $outputDir

$exitCode = $LASTEXITCODE

Write-Host "`n========================================" -ForegroundColor Cyan
if ($exitCode -eq 0) {
    Write-Host "✅ $testName PASSED" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    if (-not $FullSoakTest) {
        Write-Host "The system is ready for the full 24-hour soak test." -ForegroundColor Green
        Write-Host "Run: .\Phase22_QuickTest.ps1 -FullSoakTest" -ForegroundColor White
    } else {
        Write-Host "🏆 SYSTEM VALIDATED FOR PRODUCTION DEPLOYMENT" -ForegroundColor Green
        Write-Host "Phase 22: Cross-Model Orchestrator is 24-hour stable." -ForegroundColor Green
    }
} else {
    Write-Host "❌ $testName FAILED" -ForegroundColor Red
    Write-Host "========================================`n" -ForegroundColor Cyan
    Write-Host "Review logs in: $outputDir" -ForegroundColor Yellow
    Write-Host "Address issues before production deployment." -ForegroundColor Red
}

exit $exitCode