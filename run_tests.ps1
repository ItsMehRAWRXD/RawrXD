# d:\rawrxd\run_tests.ps1
# RawrXD Vertical Slice Test Runner
# Automatically detects VS environment, builds, and runs tests

param(
    [string]$VSPath = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
    [string]$Arch = "x64",
    [switch]$Verbose
)

function Write-Header($text) {
    Write-Host "`n=================================================================" -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
}

function Write-Success($text) {
    Write-Host "[PASS] $text" -ForegroundColor Green
}

function Write-Error($text) {
    Write-Host "[FAIL] $text" -ForegroundColor Red
}

function Write-Info($text) {
    Write-Host "[INFO] $text" -ForegroundColor White
}

# 1. Setup VS Environment
Write-Header "Initializing Visual Studio Environment"

if (-not (Test-Path $VSPath)) {
    # Try alternative paths
    $altPaths = @(
        "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat",
        "D:\VS2022Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
    )
    
    foreach ($alt in $altPaths) {
        if (Test-Path $alt) {
            $VSPath = $alt
            Write-Info "Found VS at: $VSPath"
            break
        }
    }
}

if (-not (Test-Path $VSPath)) {
    Write-Error "Could not find vcvarsall.bat. Please specify -VSPath"
    exit 1
}

Write-Info "Loading environment from: $VSPath"
& cmd /c "$VSPath $Arch && set" | ForEach-Object {
    if ($_ -match "^([^=]+)=(.*)$") {
        [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2])
    }
}

# Verify environment
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    Write-Error "Failed to load VS environment. cl.exe not found."
    exit 1
}

Write-Success "Visual Studio environment loaded"

# 2. Prepare directories
$srcDir = "d:\rawrxd\src\debug"
$binDir = "d:\rawrxd\build\bin"
$logDir = "d:\rawrxd\build\logs"

if (-not (Test-Path $binDir)) { New-Item -ItemType Directory -Path $binDir -Force | Out-Null }
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

# 3. Build QuickTest
Write-Header "Building QuickTest.exe"

$sourceFiles = @(
    "$srcDir\QuickTest.cpp",
    "$srcDir\DebugBackend.cpp",
    "$srcDir\DebugBridge.cpp"
)

$clArgs = @(
    "/nologo",
    "/EHsc",
    "/O2",
    "/W4",
    "/DUNICODE",
    "/D_UNICODE",
    "/I`"$srcDir`"",
    "/Fe`"$binDir\QuickTest.exe`"",
    "/Fo`"$binDir\\`"",
    "/link",
    "dbghelp.lib",
    "kernel32.lib",
    "user32.lib",
    "/SUBSYSTEM:CONSOLE"
)

$clCommand = "cl.exe $($clArgs -join ' ') $($sourceFiles -join ' ')"
if ($Verbose) {
    Write-Info "Command: $clCommand"
}

# Run compilation
$compileOutput = & cl.exe @clArgs $sourceFiles 2>&1
$compileExitCode = $LASTEXITCODE

if ($compileExitCode -ne 0) {
    Write-Error "Compilation failed!"
    Write-Host $compileOutput
    exit 1
}

Write-Success "Build successful: $binDir\QuickTest.exe"

# 4. Run Tests
Write-Header "Running Vertical Slice Tests"

$testOutput = & "$binDir\QuickTest.exe" 2>&1
$testExitCode = $LASTEXITCODE

# Display output
Write-Host ""
if (Test-Path "$binDir\test_results.txt") {
    Get-Content "$binDir\test_results.txt" | ForEach-Object {
        if ($_ -match "\[PASS\]") {
            Write-Host $_ -ForegroundColor Green
        } elseif ($_ -match "\[FAIL\]") {
            Write-Host $_ -ForegroundColor Red
        } elseif ($_ -match "\[SUCCESS\]") {
            Write-Host $_ -ForegroundColor Green -BackgroundColor Black
        } elseif ($_ -match "\[FAILURE\]") {
            Write-Host $_ -ForegroundColor Red -BackgroundColor Black
        } else {
            Write-Host $_
        }
    }
} else {
    Write-Host $testOutput
}

# 5. Summary
Write-Header "Test Summary"

if ($testExitCode -eq 0) {
    Write-Success "All vertical slice tests passed!"
    Write-Info "The stack is ready for VS Code integration."
    Write-Info ""
    Write-Info "Next steps:"
    Write-Info "  1. Build DAPServer.exe for VS Code integration"
    Write-Info "  2. Create VS Code extension glue code"
    Write-Info "  3. Test end-to-end debugging"
    exit 0
} else {
    Write-Error "Some tests failed. Review output above."
    exit 1
}
