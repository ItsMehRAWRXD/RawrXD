@echo off
REM Build script for all 4 layers of RawrXD Inference OS
REM Builds in dependency order: Scheduler → Router → Executor → Policy → Runtime

echo ============================================
echo RawrXD Inference OS - Layered Build System
echo ============================================
echo.

set MSVC_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717
set PATH=%MSVC_PATH%\bin\Hostx64\x64;%PATH%
set INCLUDE=%MSVC_PATH%\include;%INCLUDE%
set LIB=%MSVC_PATH%\lib\x64;%LIB%

set ROOT_DIR=%CD%
set BUILD_DIR=%ROOT_DIR%\build-layers

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

REM Build order: Scheduler (0) → Router (1) → Executor (2) → Policy (3) → Runtime (Integration)

echo [1/5] Building Layer 0: Scheduler...
cd %BUILD_DIR%
if not exist scheduler mkdir scheduler
cd scheduler
cmake ..\..\src\core\scheduler -G "Ninja" -DCMAKE_BUILD_TYPE=Release > nul 2>&1
if errorlevel 1 (
    echo FAILED: Scheduler configuration
    exit /b 1
)
ninja > nul 2>&1
if errorlevel 1 (
    echo FAILED: Scheduler build
    exit /b 1
)
echo SUCCESS: Scheduler built
cd %BUILD_DIR%

echo [2/5] Building Layer 1: Router...
if not exist router mkdir router
cd router
cmake ..\..\src\core\router -G "Ninja" -DCMAKE_BUILD_TYPE=Release > nul 2>&1
if errorlevel 1 (
    echo FAILED: Router configuration
    exit /b 1
)
ninja > nul 2>&1
if errorlevel 1 (
    echo FAILED: Router build
    exit /b 1
)
echo SUCCESS: Router built
cd %BUILD_DIR%

echo [3/5] Building Layer 2: Executor...
if not exist executor mkdir executor
cd executor
cmake ..\..\src\core\executor -G "Ninja" -DCMAKE_BUILD_TYPE=Release > nul 2>&1
if errorlevel 1 (
    echo FAILED: Executor configuration
    exit /b 1
)
ninja > nul 2>&1
if errorlevel 1 (
    echo FAILED: Executor build
    exit /b 1
)
echo SUCCESS: Executor built
cd %BUILD_DIR%

echo [4/5] Building Layer 3: Policy...
if not exist policy mkdir policy
cd policy
cmake ..\..\src\core\policy -G "Ninja" -DCMAKE_BUILD_TYPE=Release > nul 2>&1
if errorlevel 1 (
    echo FAILED: Policy configuration
    exit /b 1
)
ninja > nul 2>&1
if errorlevel 1 (
    echo FAILED: Policy build
    exit /b 1
)
echo SUCCESS: Policy built
cd %BUILD_DIR%

echo [5/5] Building Integration: Runtime...
if not exist runtime mkdir runtime
cd runtime
cmake ..\..\src\integration -G "Ninja" -DCMAKE_BUILD_TYPE=Release > nul 2>&1
if errorlevel 1 (
    echo FAILED: Runtime configuration
    exit /b 1
)
ninja > nul 2>&1
if errorlevel 1 (
    echo FAILED: Runtime build
    exit /b 1
)
echo SUCCESS: Runtime built
cd %BUILD_DIR%

echo.
echo ============================================
echo Build Complete!
echo ============================================
echo.
echo Layer 0 (Scheduler): %BUILD_DIR%\scheduler\RawrXD-Scheduler.lib
echo Layer 1 (Router):   %BUILD_DIR%\router\RawrXD-Router.lib
echo Layer 2 (Executor): %BUILD_DIR%\executor\RawrXD-Executor.lib
echo Layer 3 (Policy):   %BUILD_DIR%\policy\RawrXD-Policy.lib
echo Integration:        %BUILD_DIR%\runtime\RawrXD-Runtime.lib
echo Test Executable:    %BUILD_DIR%\runtime\RawrXD-Runtime-Test.exe
echo.
pause
