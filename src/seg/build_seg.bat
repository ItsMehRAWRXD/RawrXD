@echo off
REM Build script for Sovereign Execution Graph (Phase B.4 Batch 1/5)

echo ========================================
echo Building Sovereign Execution Graph
echo Phase B.4 Batch 1/5: Graph Model Core
echo ========================================

set SRC_DIR=%~dp0
set BUILD_DIR=%SRC_DIR%\build
set VCPKG_DIR=C:\vcpkg
set VCPKG_INCLUDE=%VCPKG_DIR%\installed\x64-windows\include

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo.
echo Compiling SovereignExecutionGraph.cpp...
cl.exe /c /EHsc /W4 /O2 /std:c++17 /I"%VCPKG_INCLUDE%" /Fo"%BUILD_DIR%\SovereignExecutionGraph.obj" "%SRC_DIR%\SovereignExecutionGraph.cpp"
if errorlevel 1 (
    echo ERROR: Failed to compile SovereignExecutionGraph.cpp
    exit /b 1
)

echo.
echo Compiling SovereignExecutionGraphSmokeTest.cpp...
cl.exe /c /EHsc /W4 /O2 /std:c++17 /I"%VCPKG_INCLUDE%" /Fo"%BUILD_DIR%\SovereignExecutionGraphSmokeTest.obj" "%SRC_DIR%\SovereignExecutionGraphSmokeTest.cpp"
if errorlevel 1 (
    echo ERROR: Failed to compile SovereignExecutionGraphSmokeTest.cpp
    exit /b 1
)

echo.
echo Linking smoke test executable...
link.exe /OUT:"%BUILD_DIR%\SEG_SmokeTest.exe" "%BUILD_DIR%\SovereignExecutionGraphSmokeTest.obj" "%BUILD_DIR%\SovereignExecutionGraph.obj"
if errorlevel 1 (
    echo ERROR: Failed to link smoke test executable
    exit /b 1
)

echo.
echo ========================================
echo Build successful!
echo ========================================
echo.
echo Running smoke test...
echo.

"%BUILD_DIR%\SEG_SmokeTest.exe"
set TEST_RESULT=%ERRORLEVEL%

echo.
echo ========================================
if %TEST_RESULT% == 0 (
    echo SMOKE TEST PASSED
) else (
    echo SMOKE TEST FAILED
)
echo ========================================

exit /b %TEST_RESULT%
