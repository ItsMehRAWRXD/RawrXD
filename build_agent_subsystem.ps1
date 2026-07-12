#==============================================================================
# Build Agent Subsystem
#==============================================================================

$ErrorActionPreference = "Stop"

$VS_PATH = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64"
$SRC_DIR = "d:\rawrxd\src"
$BIN_DIR = "d:\rawrxd\bin"

# Ensure bin directory exists
if (!(Test-Path $BIN_DIR)) {
    New-Item -ItemType Directory -Path $BIN_DIR -Force | Out-Null
}

Write-Host "Building Agent Subsystem..." -ForegroundColor Cyan

# Compile AgentSubsystem.cpp
Write-Host "  Compiling AgentSubsystem.cpp..." -NoNewline
& "$VS_PATH\cl.exe" /c /EHsc /O2 /W3 /nologo /Fo"$BIN_DIR\AgentSubsystem.obj" `
    "$SRC_DIR\core\AgentSubsystem.cpp" `
    /I"$SRC_DIR\core" 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " FAILED" -ForegroundColor Red
    exit 1
}

# Compile AgentCLICommands.cpp
Write-Host "  Compiling AgentCLICommands.cpp..." -NoNewline
& "$VS_PATH\cl.exe" /c /EHsc /O2 /W3 /nologo /Fo"$BIN_DIR\AgentCLICommands.obj" `
    "$SRC_DIR\cli\AgentCLICommands.cpp" `
    /I"$SRC_DIR\core" 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " FAILED" -ForegroundColor Red
    exit 1
}

Write-Host "`nAgent Subsystem build complete!" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. Ensure Ollama is running: ollama serve" -ForegroundColor White
Write-Host "  2. Link AgentSubsystem.obj into SovereignCLI_Unified.exe" -ForegroundColor White
Write-Host "  3. Test: SovereignCLI_Unified.exe agent status" -ForegroundColor White
