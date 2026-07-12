#==============================================================================
# build_phase13_5.ps1 - Phase 13.5 Completion Build Script
#
# Compiles and links the fully sovereign agent subsystem with:
# - Native GGUF backend (your CPUInferenceEngine)
# - Ollama backend (optional HTTP fallback)
# - Execution Journal (event-sourced audit log)
# - AgentSubsystem registration with CLI
#==============================================================================

$ErrorActionPreference = "Stop"

# Configuration
$VS_PATH = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64"
$SRC_DIR = "d:\rawrxd\src"
$BIN_DIR = "d:\rawrxd\bin"
$INCLUDE_DIRS = @(
    "d:\rawrxd\src\core",
    "d:\include"  # Your existing headers
)

# Ensure bin directory exists
if (!(Test-Path $BIN_DIR)) {
    New-Item -ItemType Directory -Path $BIN_DIR -Force | Out-Null
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Phase 13.5 Build - Sovereign Agent Integration" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Compiler flags
$CXXFLAGS = @(
    "/c",           # Compile only
    "/EHsc",        # Exception handling
    "/O2",          # Optimize for speed
    "/W3",          # Warning level 3
    "/nologo",       # No logo
    "/Zi"           # Debug info
)

# Include flags
$INCLUDES = $INCLUDE_DIRS | ForEach-Object { "/I`"$_`"" }

#==============================================================================
# Compile Phase 13.5 Components
#==============================================================================

$components = @(
    @{Name="InferenceBackend"; Source="core\InferenceBackend.cpp"; Obj="InferenceBackend.obj"},
    @{Name="NativeInferenceBackend_Wrapper"; Source="core\NativeInferenceBackend_Wrapper.cpp"; Obj="NativeInferenceBackend_Wrapper.obj"},
    @{Name="OllamaInferenceBackend"; Source="core\OllamaInferenceBackend.cpp"; Obj="OllamaInferenceBackend.obj"},
    @{Name="AgentSubsystem"; Source="core\AgentSubsystem.cpp"; Obj="AgentSubsystem.obj"},
    @{Name="ExecutionJournal"; Source="core\ExecutionJournal.cpp"; Obj="ExecutionJournal.obj"},
    @{Name="AgentSubsystem_Registration"; Source="cli\AgentSubsystem_Registration.cpp"; Obj="AgentSubsystem_Registration.obj"}
)

Write-Host "Compiling Phase 13.5 components..." -ForegroundColor Yellow
Write-Host ""

foreach ($comp in $components) {
    Write-Host "  Compiling $($comp.Name)..." -NoNewline
    
    $sourcePath = Join-Path $SRC_DIR $comp.Source
    $objPath = Join-Path $BIN_DIR $comp.Obj
    
    if (!(Test-Path $sourcePath)) {
        Write-Host " SKIPPED (source not found)" -ForegroundColor Yellow
        continue
    }
    
    $cmd = "`"$VS_PATH\cl.exe`" $CXXFLAGS $INCLUDES `"$sourcePath`" /Fo`"$objPath`" 2>&1"
    $output = Invoke-Expression $cmd
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host " OK" -ForegroundColor Green
    } else {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host $output
        exit 1
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Phase 13.5 Compilation Complete" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

#==============================================================================
# Link Instructions
#==============================================================================

Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Link with your existing object files:" -ForegroundColor White
Write-Host "   link.exe /OUT:bin\SovereignCLI_Unified.exe \\" -ForegroundColor Gray
Write-Host "     obj\SovereignCLI_Unified.obj \\" -ForegroundColor Gray
Write-Host "     obj\AgentSubsystem_Registration.obj \\" -ForegroundColor Gray
Write-Host "     obj\AgentSubsystem.obj \\" -ForegroundColor Gray
Write-Host "     obj\InferenceBackend.obj \\" -ForegroundColor Gray
Write-Host "     obj\NativeInferenceBackend_Wrapper.obj \\" -ForegroundColor Gray
Write-Host "     obj\OllamaInferenceBackend.obj \\" -ForegroundColor Gray
Write-Host "     obj\ExecutionJournal.obj \\" -ForegroundColor Gray
Write-Host "     [your existing inference engine objs] \\" -ForegroundColor Gray
Write-Host "     winhttp.lib" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Test the sovereign agent:" -ForegroundColor White
Write-Host "   .\SovereignCLI_Unified.exe agent status" -ForegroundColor Gray
Write-Host "   .\SovereignCLI_Unified.exe agent generate \"Hello world\" rust" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Verify Execution Journal:" -ForegroundColor White
Write-Host "   Check logs/sovereign.journal" -ForegroundColor Gray
Write-Host ""

#==============================================================================
# Create Test Script
#==============================================================================

$testScript = @"
@echo off
echo =========================================
echo Phase 13.5 - Sovereign Agent Test
echo =========================================
echo.

REM Test 1: Agent status
echo Test 1: Agent status
SovereignCLI_Unified.exe agent status
echo.

REM Test 2: Generate code
echo Test 2: Generate Rust code
SovereignCLI_Unified.exe agent generate "Hello world in Rust" rust > hello.rs
echo Generated hello.rs
echo.

REM Test 3: Compile
echo Test 3: Compile
cd rust
SovereignCLI_Unified.exe rust compile hello.rs
echo.

REM Test 4: Run
echo Test 4: Run
SovereignCLI_Unified.exe rust run hello
echo.

echo =========================================
echo Phase 13.5 Test Complete
echo =========================================
pause
"@

$testPath = Join-Path $BIN_DIR "test_phase13_5.bat"
$testScript | Out-File -FilePath $testPath -Encoding ASCII

Write-Host "Created test script: $testPath" -ForegroundColor Green
Write-Host ""
