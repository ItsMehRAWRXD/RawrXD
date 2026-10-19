@echo off
setlocal enabledelayedexpansion

:: Change to script directory so relative paths resolve correctly
pushd "%~dp0"

echo ========================================================
echo  RAWR XD Engine v2 - Build and Dispatch Script
echo ========================================================

:: 1. Initialize MSVC Environment (Visual Studio 2022 / 2019 x64)
if defined DevEnvDir (
    echo [Setup] MSVC environment already initialized.
) else (
    echo [Setup] Locating MSVC environment...
    if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
        call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    ) else if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
        call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    ) else if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" (
        call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    ) else (
        echo [ERROR] Could not find Visual Studio vcvars64.bat automatically. Please run from a Developer Command Prompt.
        exit /b 1
    )
)

:: Ensure output and build directories exist
if not exist rawrxd mkdir rawrxd
if not exist src\deep2 mkdir src\deep2

echo.
echo [1/6] Assembling Classify.asm zero-dependency module...
ml64.exe /c /Cx /Fo Classify.obj src\deep2\Classify.asm
if errorlevel 1 goto error

echo.
echo [2/6] Compiling AVX-512 VNNI Kernel (K2VNNIKernel.cpp)...
cl.exe /c /O2 /arch:AVX512 /std:c++17 /EHsc /openmp /I. ^
    src\deep2\K2VNNIKernel.cpp /Fo K2VNNIKernel.obj
if errorlevel 1 goto error

echo.
echo [3/6] Compiling AVX2 Fallback Kernel with ThreadPool (K2AVX2Kernel.cpp)...
cl.exe /c /O2 /arch:AVX2 /std:c++17 /EHsc /I. ^
    src\deep2\K2AVX2Kernel.cpp /Fo K2AVX2Kernel.obj
if errorlevel 1 goto error

echo.
echo [4/6] Compiling Weight Projection Engine (WeightProjection.cpp)...
cl.exe /c /O2 /arch:AVX2 /std:c++17 /EHsc /I. ^
    src\deep2\WeightProjection.cpp /Fo WeightProjection.obj
if errorlevel 1 goto error

echo.
echo [5/6] Compiling Monolith Dispatcher & Linking All Objects...
cl.exe /O2 /arch:AVX2 /std:c++17 /EHsc /I. ^
    rawr_dispatcher_v2.cpp ^
    WeightProjection.obj ^
    K2LogitsClimb.obj ^
    Classify.obj ^
    K2VNNIKernel.obj ^
    K2AVX2Kernel.obj ^
    /Fe:rawrxd\rawr_engine_v2_dispatch.exe
if errorlevel 1 goto error

echo.
echo [6/6] Executing Dispatch Validation Test...
echo --------------------------------------------------------
rawrxd\rawr_engine_v2_dispatch.exe
echo --------------------------------------------------------
echo [SUCCESS] Build and execution completed successfully!
goto end

:error
echo.
echo [ERROR] Build failed with error level %errorlevel%.
exit /b %errorlevel%

:end
popd
endlocal
