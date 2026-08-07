@echo off
chcp 65001 > nul
setlocal EnableDelayedExpansion

:: ============================================================================
:: RawrXD Dual GPU Smoke Test
:: ============================================================================
:: Comprehensive smoke test for dual GPU validation
:: ============================================================================

echo =========================================
echo RawrXD Dual GPU Smoke Test
echo =========================================
echo.

set "SMOKE_PASSED=0"
set "SMOKE_FAILED=0"
set "TOTAL_TESTS=0"

:: Test 1: GPU Enumeration
echo [TEST 1/10] GPU Enumeration...
set /a TOTAL_TESTS+=1
val071_dual_gpu.exe --test=enumerate > nul 2>&1
if %errorlevel% equ 0 (
    echo   [PASS] GPU enumeration successful
    set /a SMOKE_PASSED+=1
) else (
    echo   [FAIL] GPU enumeration failed
    set /a SMOKE_FAILED+=1
)

:: Test 2: P2P Access
echo [TEST 2/10] P2P Memory Access...
set /a TOTAL_TESTS+=1
val071_dual_gpu.exe --test=p2p > nul 2>&1
if %errorlevel% equ 0 (
    echo   [PASS] P2P access working
    set /a SMOKE_PASSED+=1
) else (
    echo   [FAIL] P2P access failed
    set /a SMOKE_FAILED+=1
)

:: Test 3: Memory Split 50/50
echo [TEST 3/10] Memory Split (50/50)...
set /a TOTAL_TESTS+=1
val071_dual_gpu.exe --memory-split=50 > nul 2>&1
if %errorlevel% equ 0 (
    echo   [PASS] 50/50 memory split working
    set /a SMOKE_PASSED+=1
) else (
    echo   [FAIL] Memory split failed
    set /a SMOKE_FAILED+=1
)

:: Test 4: Memory Split 70/30
echo [TEST 4/10] Memory Split (70/30)...
set /a TOTAL_TESTS+=1
val071_dual_gpu.exe --memory-split=70 > nul 2>&1
if %errorlevel% equ 0 (
    echo   [PASS] 70/30 memory split working
    set /a SMOKE_PASSED+=1
) else (
    echo   [FAIL] Memory split failed
    set /a SMOKE_FAILED+=1
)

:: Test 5: Load Balancing
echo [TEST 5/10] Load Balancing...
set /a TOTAL_TESTS+=1
val071_dual_gpu.exe --test=load-balance > nul 2>&1
if %errorlevel% equ 0 (
    echo   [PASS] Load balancing working
    set /a SMOKE_PASSED+=1
) else (
    echo   [FAIL] Load balancing failed
    set /a SMOKE_FAILED+=1
)

:: Test 6: Synchronization
echo [TEST 6/10] GPU Synchronization...
set /a TOTAL_TESTS+=1
val071_dual_gpu.exe --test=sync > nul 2>&1
if %errorlevel% equ 0 (
    echo   [PASS] Synchronization working
    set /a SMOKE_PASSED+=1
) else (
    echo   [FAIL] Synchronization failed
    set /a SMOKE_FAILED+=1
)

:: Test 7: Failover
echo [TEST 7/10] GPU Failover...
set /a TOTAL_TESTS+=1
val071_dual_gpu.exe --test=failover > nul 2>&1
if %errorlevel% equ 0 (
    echo   [PASS] Failover working
    set /a SMOKE_PASSED+=1
) else (
    echo   [FAIL] Failover failed
    set /a SMOKE_FAILED+=1
)

:: Test 8: Throughput Benchmark
echo [TEST 8/10] Throughput Benchmark...
set /a TOTAL_TESTS+=1
val071_dual_gpu.exe --benchmark=throughput > nul 2>&1
if %errorlevel% equ 0 (
    echo   [PASS] Throughput benchmark completed
    set /a SMOKE_PASSED+=1
) else (
    echo   [FAIL] Throughput benchmark failed
    set /a SMOKE_FAILED+=1
)

:: Test 9: Latency Benchmark
echo [TEST 9/10] Latency Benchmark...
set /a TOTAL_TESTS+=1
val071_dual_gpu.exe --benchmark=latency > nul 2>&1
if %errorlevel% equ 0 (
    echo   [PASS] Latency benchmark completed
    set /a SMOKE_PASSED+=1
) else (
    echo   [FAIL] Latency benchmark failed
    set /a SMOKE_FAILED+=1
)

:: Test 10: Full Validation
echo [TEST 10/10] Full Dual GPU Validation...
set /a TOTAL_TESTS+=1
val071_dual_gpu.exe > nul 2>&1
if %errorlevel% equ 0 (
    echo   [PASS] Full validation passed
    set /a SMOKE_PASSED+=1
) else (
    echo   [FAIL] Full validation failed
    set /a SMOKE_FAILED+=1
)

echo.
echo =========================================
echo Smoke Test Summary
echo =========================================
echo Total Tests:  %TOTAL_TESTS%
echo Passed:       %SMOKE_PASSED%
echo Failed:       %SMOKE_FAILED%
echo.

if %SMOKE_FAILED% equ 0 (
    echo [SUCCESS] All dual GPU smoke tests passed!
    exit /b 0
) else (
    echo [WARNING] %SMOKE_FAILED% test(s) failed
    exit /b 1
)
