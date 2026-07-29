@echo off
REM ============================================================================
REM Build Token Estimator Swarm Demo
REM ============================================================================

echo Building Token Estimator Swarm Demo...
echo.

set SRC_DIR=%~dp0
set BUILD_DIR=%SRC_DIR%\bin

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo Compiling TokenEstimatorSwarm.cpp...
cl /c /EHsc /O2 /I"%SRC_DIR%\.." /Fo"%BUILD_DIR%\TokenEstimatorSwarm.obj" "%SRC_DIR%\TokenEstimatorSwarm.cpp"
if errorlevel 1 (
    echo ERROR: Failed to compile TokenEstimatorSwarm.cpp
    exit /b 1
)

echo Compiling TokenEstimatorDemo.cpp...
cl /c /EHsc /O2 /I"%SRC_DIR%\.." /Fo"%BUILD_DIR%\TokenEstimatorDemo.obj" "%SRC_DIR%\TokenEstimatorDemo.cpp"
if errorlevel 1 (
    echo ERROR: Failed to compile TokenEstimatorDemo.cpp
    exit /b 1
)

echo Linking TokenEstimatorDemo.exe...
link /OUT:"%BUILD_DIR%\TokenEstimatorDemo.exe" "%BUILD_DIR%\TokenEstimatorSwarm.obj" "%BUILD_DIR%\TokenEstimatorDemo.obj"
if errorlevel 1 (
    echo ERROR: Failed to link TokenEstimatorDemo.exe
    exit /b 1
)

echo.
echo Build successful!
echo Executable: %BUILD_DIR%\TokenEstimatorDemo.exe
echo.
echo Running demo...
echo.

"%BUILD_DIR%\TokenEstimatorDemo.exe"

exit /b 0
