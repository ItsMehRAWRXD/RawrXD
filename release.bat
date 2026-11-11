@echo off
REM =============================================================================
REM   RawrXD Release Packager - Batch 7 of 5 (Bonus)
REM   Production release packaging and distribution
REM =============================================================================

setlocal EnableDelayedExpansion

set "RAWRXD_HOME=d:\rawrxd"
set "RELEASE_DIR=%RAWRXD_HOME%\releases"
set "STAGING_DIR=%RELEASE_DIR%\staging"
set "VERSION=%1"

if "!VERSION!"=="" (
    echo ERROR: Version required
    echo Usage: release.bat [version]
    echo Example: release.bat 1.0.0
    goto :error
)

set "RELEASE_NAME=rawrxd-!VERSION!-win64"
set "RELEASE_PATH=%RELEASE_DIR%\!RELEASE_NAME!"

echo =============================================================================
echo   RawrXD Release Packager
echo   Version: !VERSION!
echo =============================================================================
echo.

REM =============================================================================
REM Phase 1: Pre-flight Checks
echo [Phase 1/6] Pre-flight checks...

REM Verify production status
if not exist "%RAWRXD_HOME%\verify_production.bat" (
    echo ERROR: verify_production.bat not found
    goto :error
)

call "%RAWRXD_HOME%\verify_production.bat" >NUL 2>&1
if errorlevel 1 (
    echo ERROR: Production verification failed
    echo Run verify_production.bat to check status
    goto :error
)

echo   ✓ Production verification passed
echo.

REM =============================================================================
REM Phase 2: Clean and Prepare
echo [Phase 2/6] Preparing release directory...

if exist "%RELEASE_PATH%" (
    echo   Cleaning existing release...
    rmdir /s /q "%RELEASE_PATH%"
)

if exist "%STAGING_DIR%" (
    rmdir /s /q "%STAGING_DIR%"
)

mkdir "%RELEASE_PATH%"
mkdir "%RELEASE_PATH%\bin"
mkdir "%RELEASE_PATH%\lib"
mkdir "%RELEASE_PATH%\include"
mkdir "%RELEASE_PATH%\docs"
mkdir "%RELEASE_PATH%\tests"
mkdir "%RELEASE_PATH%\tools"
mkdir "%RELEASE_PATH%\samples"

echo   ✓ Release directory prepared
echo.

REM =============================================================================
REM Phase 3: Copy Binaries
echo [Phase 3/6] Copying binaries...

if exist "%RAWRXD_HOME%\native_toolchain\minimal_assembler_v2.exe" (
    copy "%RAWRXD_HOME%\native_toolchain\minimal_assembler_v2.exe" "%RELEASE_PATH%\bin\" >NUL
    echo   ✓ minimal_assembler_v2.exe
)

if exist "%RAWRXD_HOME%\native_toolchain\linker_with_imports.exe" (
    copy "%RAWRXD_HOME%\native_toolchain\linker_with_imports.exe" "%RELEASE_PATH%\bin\" >NUL
    echo   ✓ linker_with_imports.exe
)

if exist "%RAWRXD_HOME%\build.bat" (
    copy "%RAWRXD_HOME%\build.bat" "%RELEASE_PATH%\" >NUL
    echo   ✓ build.bat
)

if exist "%RAWRXD_HOME%\run_tests.bat" (
    copy "%RAWRXD_HOME%\run_tests.bat" "%RELEASE_PATH%\" >NUL
    echo   ✓ run_tests.bat
)

if exist "%RAWRXD_HOME%\rpkg.bat" (
    copy "%RAWRXD_HOME%\rpkg.bat" "%RELEASE_PATH%\bin\" >NUL
    echo   ✓ rpkg.bat
)

echo.

REM =============================================================================
REM Phase 4: Copy Headers and Libraries
echo [Phase 4/6] Copying headers and libraries...

if exist "%RAWRXD_HOME%\native_toolchain\c_parser.h" (
    copy "%RAWRXD_HOME%\native_toolchain\c_parser.h" "%RELEASE_PATH%\include\" >NUL
    echo   ✓ c_parser.h
)

if exist "%RAWRXD_HOME%\tests\include\test_framework.h" (
    copy "%RAWRXD_HOME%\tests\include\test_framework.h" "%RELEASE_PATH%\include\" >NUL
    echo   ✓ test_framework.h
)

echo.

REM =============================================================================
REM Phase 5: Copy Documentation
echo [Phase 5/6] Copying documentation...

if exist "%RAWRXD_HOME%\README.md" (
    copy "%RAWRXD_HOME%\README.md" "%RELEASE_PATH%\docs\" >NUL
    echo   ✓ README.md
)

if exist "%RAWRXD_HOME%\docs\API_REFERENCE.md" (
    copy "%RAWRXD_HOME%\docs\API_REFERENCE.md" "%RELEASE_PATH%\docs\" >NUL
    echo   ✓ API_REFERENCE.md
)

if exist "%RAWRXD_HOME%\tests\README.md" (
    copy "%RAWRXD_HOME%\tests\README.md" "%RELEASE_PATH%\docs\TESTS.md" >NUL
    echo   ✓ TESTS.md
)

echo.

REM =============================================================================
REM Phase 6: Create Release Manifest
echo [Phase 6/6] Creating release manifest...

echo RawrXD Release !VERSION! > "%RELEASE_PATH%\RELEASE.txt"
echo Build Date: %date% %time% >> "%RELEASE_PATH%\RELEASE.txt"
echo Platform: Windows x64 >> "%RELEASE_PATH%\RELEASE.txt"
echo. >> "%RELEASE_PATH%\RELEASE.txt"
echo Contents: >> "%RELEASE_PATH%\RELEASE.txt"
dir /s /b "%RELEASE_PATH%" >> "%RELEASE_PATH%\RELEASE.txt" 2>NUL

REM Create version info
echo !VERSION! > "%RELEASE_PATH%\VERSION.txt"

REM Create installation script
echo @echo off > "%RELEASE_PATH%\install.bat"
echo echo Installing RawrXD !VERSION!... >> "%RELEASE_PATH%\install.bat"
echo echo. >> "%RELEASE_PATH%\install.bat"
echo echo Add the following to your PATH: >> "%RELEASE_PATH%\install.bat"
echo echo   %%CD%%\bin >> "%RELEASE_PATH%\install.bat"
echo echo. >> "%RELEASE_PATH%\install.bat"
echo echo Installation complete! >> "%RELEASE_PATH%\install.bat"
echo pause >> "%RELEASE_PATH%\install.bat"

echo   ✓ Release manifest created
echo.

REM =============================================================================
REM Create Archive
echo Creating release archive...

set "ARCHIVE_NAME=!RELEASE_NAME!.zip"
set "ARCHIVE_PATH=%RELEASE_DIR%\!ARCHIVE_NAME!"

REM Use PowerShell to create zip (Windows 10+)
powershell -Command "Compress-Archive -Path '%RELEASE_PATH%\*' -DestinationPath '%ARCHIVE_PATH%' -Force" >NUL 2>&1

if exist "%ARCHIVE_PATH%" (
    echo   ✓ Archive created: !ARCHIVE_NAME!
    
    REM Get file size
    for %%F in ("%ARCHIVE_PATH%") do (
        echo   Size: %%~zF bytes
    )
) else (
    echo   ⚠ Archive creation failed (manual zip required)
)

echo.

REM =============================================================================
REM Summary
echo =============================================================================
echo   RELEASE SUMMARY
echo =============================================================================
echo   Version:    !VERSION!
echo   Name:       !RELEASE_NAME!
echo   Location:   %RELEASE_PATH%
echo   Archive:    !ARCHIVE_NAME!
echo =============================================================================
echo   ✅ Release package created successfully!
echo =============================================================================

goto :end

:error
echo.
echo =============================================================================
echo   RELEASE FAILED
echo =============================================================================
exit /b 1

:end
echo.
exit /b 0
