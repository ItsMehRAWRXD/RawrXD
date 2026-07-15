@echo off
REM ============================================================================
REM build_qkv_pipeline.bat - Build Complete QKV Inference Pipeline
REM ============================================================================
REM Assembles all MASM modules and compiles C++ bridge for the complete
REM tensor abstraction and QKV projection pipeline.
REM ============================================================================

setlocal enabledelayedexpansion

echo ============================================================================
echo QKV Inference Pipeline Build - Pure x64 MASM + C++
echo ============================================================================

REM Tool paths (using VS2022 BuildTools)
set ML64="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\ml64.exe"
set LINK="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe"
set CL="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe"

REM Source directory
set SRC_DIR=d:\rawrxd\src\lora
set BUILD_DIR=d:\rawrxd\build\qkv_pipeline

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo.
echo [1/6] Assembling TensorContext.asm...
%ML64% /c /W3 /nologo /Zi /Fo "%BUILD_DIR%\TensorContext.obj" "%SRC_DIR%\TensorContext.asm"
if errorlevel 1 (
    echo ERROR: TensorContext.asm assembly failed
    exit /b 1
)

echo.
echo [2/6] Assembling QKVProjection.asm...
%ML64% /c /W3 /nologo /Zi /Fo "%BUILD_DIR%\QKVProjection.obj" "%SRC_DIR%\QKVProjection.asm"
if errorlevel 1 (
    echo ERROR: QKVProjection.asm assembly failed
    exit /b 1
)

echo.
echo [3/6] Assembling GemmKernel.asm...
%ML64% /c /W3 /nologo /Zi /Fo "%BUILD_DIR%\GemmKernel.obj" "%SRC_DIR%\GemmKernel.asm"
if errorlevel 1 (
    echo ERROR: GemmKernel.asm assembly failed
    exit /b 1
)

echo.
echo [4/6] Assembling BlockedGemm_Single.asm...
%ML64% /c /W3 /nologo /Zi /Fo "%BUILD_DIR%\BlockedGemm_Single.obj" "%SRC_DIR%\BlockedGemm_Single.asm"
if errorlevel 1 (
    echo ERROR: BlockedGemm_Single.asm assembly failed
    exit /b 1
)

echo.
echo [5/6] Compiling BlockedGemm_CPP.cpp...
%CL% /c /O2 /std:c++17 /arch:AVX2 /nologo /DBLOCKEDGEMM_SINGLE_IMPLEMENTATION /Fo "%BUILD_DIR%\BlockedGemm_CPP.obj" "%SRC_DIR%\BlockedGemm_CPP.cpp"
if errorlevel 1 (
    echo ERROR: BlockedGemm_CPP.cpp compilation failed
    exit /b 1
)

echo.
echo [6/6] Linking...
%LINK% /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /LARGEADDRESSAWARE /OUT:"%BUILD_DIR%\test_qkv_pipeline.exe" ^
    "%BUILD_DIR%\TensorContext.obj" ^
    "%BUILD_DIR%\QKVProjection.obj" ^
    "%BUILD_DIR%\GemmKernel.obj" ^
    "%BUILD_DIR%\BlockedGemm_Single.obj" ^
    "%BUILD_DIR%\BlockedGemm_CPP.obj" ^
    kernel32.lib

if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

echo.
echo ============================================================================
echo BUILD SUCCESSFUL
echo ============================================================================
echo Output: %BUILD_DIR%\test_qkv_pipeline.exe
echo ============================================================================
echo.
echo Components built:
echo   - TensorContext.obj     (Arena allocator, Tensor struct)
echo   - QKVProjection.obj     (Forward_QKV, GELU activation)
echo   - GemmKernel.obj        (8x8 AVX microkernel)
echo   - BlockedGemm_Single.obj (C-callable entry point)
echo   - BlockedGemm_CPP.obj    (C++ blocking implementation)
echo ============================================================================

endlocal