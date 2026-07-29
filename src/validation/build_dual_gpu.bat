@echo off
chcp 65001 > nul
setlocal EnableDelayedExpansion

:: ============================================================================
:: RawrXD Dual GPU Validation Build Script
:: ============================================================================

echo =========================================
echo RawrXD Dual GPU Validation Build
echo =========================================

:: Configuration
set "SOURCE_DIR=%~dp0"
set "BUILD_DIR=%SOURCE_DIR%build_dual_gpu"
set "OUTPUT_DIR=%SOURCE_DIR%bin"

:: Compiler settings
set "CXX=cl.exe"
set "CXXFLAGS=/std:c++17 /O2 /W3 /EHsc /MP"
set "INCLUDES=/I. /I.. /I%CUDA_PATH%\include"
set "LIBS=kernel32.lib user32.lib"

:: CUDA settings (optional)
if defined CUDA_PATH (
    echo [INFO] CUDA found at: %CUDA_PATH%
    set "CUDA_LIBS=%CUDA_PATH%\lib\x64\cuda.lib %CUDA_PATH%\lib\x64\cudart.lib"
    set "CUDA_FLAGS=/D__CUDACC__"
) else (
    echo [WARNING] CUDA not found - building in simulation mode
    set "CUDA_LIBS="
    set "CUDA_FLAGS="
)

:: Create directories
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

:: Source files
set "SOURCES=^"
set "SOURCES=%SOURCES% gates\VAL071_DualGPU_Gate.cpp"
set "SOURCES=%SOURCES% gates\VAL039_Plus_Gates.cpp"
set "SOURCES=%SOURCES% ValidationGate_Master.cpp"

:: Build command
echo.
echo [1/3] Compiling Dual GPU Validation...

%CXX% %CXXFLAGS% %CUDA_FLAGS% %INCLUDES% ^
    gates\VAL071_DualGPU_Gate.cpp ^
    gates\VAL039_Plus_Gates.cpp ^
    ValidationGate_Master.cpp ^
    /Fe"%OUTPUT_DIR%\val071_dual_gpu.exe" ^
    /Fo"%BUILD_DIR%\\" ^
    %LIBS% %CUDA_LIBS%

if errorlevel 1 (
    echo [ERROR] Compilation failed
    exit /b 1
)

echo [2/3] Compilation successful
echo.

:: Run validation
echo [3/3] Running Dual GPU Validation...
echo.
"%OUTPUT_DIR%\val071_dual_gpu.exe"

if errorlevel 1 (
    echo [ERROR] Validation failed
    exit /b 1
)

echo.
echo =========================================
echo Dual GPU Validation Complete
echo =========================================
echo.
echo Output: %OUTPUT_DIR%\val071_dual_gpu.exe

endlocal
