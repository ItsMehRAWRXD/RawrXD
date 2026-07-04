# Build script for RawrXD-Script DAP Server
# Uses VS2022 Enterprise compiler

$ErrorActionPreference = "Stop"

# VS2022 paths
$VSPath = "C:\Program Files\Microsoft Visual Studio\18\Enterprise"
$VCPath = "$VSPath\VC\Tools\MSVC\14.50.35717"
$ClExe = "$VCPath\bin\Hostx64\x64\cl.exe"
$LinkExe = "$VCPath\bin\Hostx64\x64\link.exe"

# Include paths
$IncludePaths = @(
    ".",
    "..\..\..",
    "..\..\..\lsp",
    "..\..\..\3rdparty",
    "..\..\..\3rdparty\nlohmann\include",
    "..\..\..\3rdparty\spdlog\include"
)

$IncludeArgs = $IncludePaths | ForEach-Object { "/I`"$_`"" }

# Source files
$SourceFiles = @(
    "main_dap_server.cpp",
    "rawrxd_script_dap_adapter.cpp"
)

# Compiler flags
$CompilerFlags = @(
    "/std:c++20",
    "/EHsc",
    "/O2",
    "/nologo",
    "/W3",
    "/Zi",
    "/D_CRT_SECURE_NO_WARNINGS",
    "/D_WIN32_WINNT=0x0A00"
)

# Linker flags
$LinkerFlags = @(
    "/SUBSYSTEM:CONSOLE",
    "/OUT:rxd-script-dap.exe",
    "/DEBUG"
)

Write-Host "Building RawrXD-Script DAP Server..." -ForegroundColor Cyan
Write-Host "Compiler: $ClExe" -ForegroundColor Gray

# Compile
$CompileArgs = $CompilerFlags + $IncludeArgs + "/c" + $SourceFiles
Write-Host "Compiling..." -ForegroundColor Yellow
& $ClExe @CompileArgs

if ($LASTEXITCODE -ne 0) {
    Write-Error "Compilation failed!"
    exit 1
}

# Link
$ObjectFiles = $SourceFiles -replace "\.cpp$", ".obj"
$LinkArgs = $LinkerFlags + $ObjectFiles
Write-Host "Linking..." -ForegroundColor Yellow
& $LinkExe @LinkArgs

if ($LASTEXITCODE -ne 0) {
    Write-Error "Linking failed!"
    exit 1
}

Write-Host "Build successful! Output: rxd-script-dap.exe" -ForegroundColor Green
