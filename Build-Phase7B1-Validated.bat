@echo off
chcp 65001 > nul
title RawRamXD Phase 7B.1 - Validated Acceptance Gates Build
cls

echo ========================================
echo RawRamXD Phase 7B.1: VALIDATED
echo Acceptance Gates Implementation
echo ========================================
echo.
echo Gates Implemented:
echo   [#1] Residency correctness with CRC64 verification
echo   [#2] Real pressure sweep (A/B/C/D phases)
echo   [#3] Scheduler proof with per-token decisions
echo   [#4] Policy trace output (CSV/JSON/JSONL)
echo   [#5] Failure baseline comparison
echo.
echo Output Artifacts:
echo   - rawramxd_elastic_curve.csv
echo   - rawramxd_policy_trace.json
echo   - rawramxd_migrations.jsonl
echo.
echo Claim: "Memory capacity becomes elastic because
echo         residency is scheduled instead of fixed."
echo.
pause

set "SOURCE=RawRamXD_Phase7B1_Validated.cpp"
set "OUTPUT=RawRamXD_Phase7B1_Validated.exe"
set "BUILD_DIR=build_phase7b1_validated"

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo.
echo [+] Finding Visual C++ compiler...

set "VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
set "VCVARS="

if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
    )
)

if exist "%VCVARS%" (
    echo     Found VS at: %VCVARS%
    call "%VCVARS%" > nul
) else (
    echo     Checking for cl.exe in PATH...
    where cl.exe > nul 2>&1
    if %ERRORLEVEL% neq 0 (
        echo [!] Visual C++ not found!
        echo     Install Visual Studio 2022 with C++ workload
        pause
        exit /b 1
    )
)

echo.
echo [+] Compiling Validated Phase 7B.1...
echo     Source: %SOURCE%
echo.

cl.exe /O2 /EHsc /std:c++20 /arch:AVX2 /fp:fast ^
    %SOURCE% ^
    d3d12.lib dxgi.lib kernel32.lib user32.lib advapi32.lib ole32.lib ^
    /Fe:%BUILD_DIR%\%OUTPUT% ^
    /Fo:%BUILD_DIR%\ ^
    /link /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF ^
    2>&1

if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] Compilation failed!
    pause
    exit /b 1
)

echo.
echo [OK] Build successful: %BUILD_DIR%\%OUTPUT%
echo.

echo ========================================
echo Running Validated Phase 7B.1 Benchmark
echo ========================================
echo.
echo This will execute all 5 acceptance gates:
echo.
echo Gate #1: Residency Correctness
echo   - CRC64 checksums on every migration
echo   - Verify no data corruption
echo.
echo Gate #2: Pressure Sweep
echo   - Phase A: Under capacity (12GB/16GB)
echo   - Phase B: Boundary (16GB/16GB)
echo   - Phase C: Spill (20GB/16GB)
echo   - Phase D: Extreme (24GB/16GB)
echo.
echo Gate #3: Scheduler Proof
echo   - Per-token residency decisions
echo   - Migration timing breakdown
echo.
echo Gate #4: Policy Trace
echo   - CSV: Elastic curve data
echo   - JSON: Policy decisions
echo   - JSONL: Migration log
echo.
echo Gate #5: Failure Baseline
echo   - Compare against OOM scenario
echo   - Demonstrate graceful degradation
echo.
echo WARNING: This uses real system resources!
echo          Ensure you have 30GB+ free space.
echo.
pause

cd %BUILD_DIR%
.\%OUTPUT%

echo.
echo ========================================
echo Benchmark complete!
echo ========================================
echo.
echo Output files in %BUILD_DIR%:\
echo   - rawramxd_elastic_curve.csv
echo   - rawramxd_policy_trace.json
echo   - rawramxd_migrations.jsonl
echo.
echo View policy trace:
echo   type rawramxd_policy_trace.json
echo.
echo View migrations:
echo   type rawramxd_migrations.jsonl
echo.
pause