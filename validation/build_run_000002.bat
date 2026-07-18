@echo off
REM Build script for run-000002-BUILT
REM Compiles all validation stage binaries

setlocal enabledelayedexpansion

echo ========================================
echo  RawrXD Validation Build - Run 000002
echo ========================================
echo.

set RUN_DIR=validation\runs\run-000002-BUILT
set BINARY_DIR=%RUN_DIR%\binaries

REM Create directories if they don't exist
if not exist %BINARY_DIR% mkdir %BINARY_DIR%

REM Record build start time
for /f "tokens=*" %%a in ('powershell -Command "Get-Date -Format yyyy-MM-ddTHH:mm:ssZ"') do set BUILD_START=%%a
echo Build started: %BUILD_START%
echo.

REM Set compiler flags
set CFLAGS=/EHsc /O2 /W4 /nologo
set LDFLAGS=/SUBSYSTEM:CONSOLE

echo Compiler: MSVC 14.50.35717
echo Flags: %CFLAGS%
echo.

REM Build embedding_stage.exe
echo [1/3] Building embedding_stage.exe...
cl.exe %CFLAGS% validation\embedding_stage.cpp /Fe:%BINARY_DIR%\embedding_stage.exe /link %LDFLAGS%
if errorlevel 1 (
    echo [ERROR] embedding_stage.exe build failed
    exit /b 1
)
echo [PASS] embedding_stage.exe built successfully
echo.

REM Build rmsnorm_stage.exe
echo [2/3] Building rmsnorm_stage.exe...
cl.exe %CFLAGS% validation\rmsnorm_stage.cpp /Fe:%BINARY_DIR%\rmsnorm_stage.exe /link %LDFLAGS%
if errorlevel 1 (
    echo [ERROR] rmsnorm_stage.exe build failed
    exit /b 1
)
echo [PASS] rmsnorm_stage.exe built successfully
echo.

REM Build RawrXDValidator.exe
echo [3/3] Building RawrXDValidator.exe...
cl.exe %CFLAGS% validation\RawrXDValidator.cpp /Fe:%BINARY_DIR%\RawrXDValidator.exe /link %LDFLAGS% bcrypt.lib
if errorlevel 1 (
    echo [ERROR] RawrXDValidator.exe build failed
    exit /b 1
)
echo [PASS] RawrXDValidator.exe built successfully
echo.

REM Compute SHA256 hashes
echo Computing SHA256 hashes...
echo.

for %%f in (%BINARY_DIR%\*.exe) do (
    echo Computing hash for %%~nxf...
    certutil -hashfile "%%f" SHA256 | findstr /v "SHA256" | findstr /v "CertUtil" > "%%f.sha256"
    set /p HASH=<"%%f.sha256"
    echo   SHA256: !HASH!
)

echo.
echo ========================================
echo  Build Complete - Run 000002
echo ========================================
echo.
echo Binaries location: %BINARY_DIR%
echo.
echo Next steps:
echo   1. Update manifest.json with SHA256 hashes
echo   2. Execute binaries to create run-000003-EXECUTED
echo   3. Use RawrXDValidator.exe for verification
echo.

endlocal
