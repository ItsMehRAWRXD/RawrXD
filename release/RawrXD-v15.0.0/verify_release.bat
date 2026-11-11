@echo off
echo RawrXD v15.0.0 Release Verification
echo ====================================
echo.

REM Check for required files
set MISSING=0

if not exist "RawrXD.exe" (
    echo [FAIL] RawrXD.exe not found
    set /a MISSING+=1
) else (
    echo [PASS] RawrXD.exe found
)

if not exist "evidence\RC0.2_CERTIFICATION.json" (
    echo [FAIL] Certification evidence not found
    set /a MISSING+=1
) else (
    echo [PASS] Certification evidence found
)

if not exist "RELEASE_MANIFEST.json" (
    echo [FAIL] Release manifest not found
    set /a MISSING+=1
) else (
    echo [PASS] Release manifest found
)

echo.
if %MISSING%==0 (
    echo ====================================
    echo RESULT: RELEASE VALID
    echo ====================================
    exit /b 0
) else (
    echo ====================================
    echo RESULT: RELEASE INCOMPLETE - %MISSING% checks failed
    echo ====================================
    exit /b 1
)
