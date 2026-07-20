@echo off
REM ============================================================================
REM Build Script: RawrXD NHWC Layout Converter
REM Integrates memory layout optimization into the compiler toolchain
REM ============================================================================

setlocal EnableDelayedExpansion

echo ============================================================================
echo RawrXD NHWC Layout Converter - Build Pipeline
echo ============================================================================
echo.

REM Tool paths
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set CL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe
set LIB_TOOL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\lib.exe

REM Directories
set SRC_DIR=d:\RawrXD\src\memory
set COMPILER_DIR=d:\RawrXD\src\compiler
set OBJ_DIR=d:\RawrXD\obj\memory
set LIB_DIR=d:\RawrXD\lib
set INC_DIR=d:\RawrXD\include

REM Create directories
if not exist %OBJ_DIR% mkdir %OBJ_DIR%
if not exist %LIB_DIR% mkdir %LIB_DIR%
if not exist %INC_DIR% mkdir %INC_DIR%

echo [1/4] Compiling NHWC Layout Converter...
echo.

"%CL%" /c /nologo /W4 /EHsc /O2 /Zi /MD /arch:AVX512 /Fo"%OBJ_DIR%\RawrXD_TensorLayout_NHWC.obj" ^
    /I"%SRC_DIR%" ^
    "%SRC_DIR%\RawrXD_TensorLayout_NHWC.cpp" 2>&1

if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)

echo         RawrXD_TensorLayout_NHWC.obj - OK
echo.

echo [2/4] Creating static library...
echo.

"%LIB_TOOL%" /nologo /out:"%LIB_DIR%\RawrXD_MemoryLayout.lib" ^
    "%OBJ_DIR%\RawrXD_TensorLayout_NHWC.obj" 2>&1

if errorlevel 1 (
    echo ERROR: Library creation failed
    exit /b 1
)

echo         RawrXD_MemoryLayout.lib - OK
echo.

echo [3/4] Copying headers...
echo.

copy /Y "%SRC_DIR%\RawrXD_TensorLayout_NHWC.hpp" "%INC_DIR%\" >nul
copy /Y "%COMPILER_DIR%\RawrXD_Universal_Compiler_Layout.hpp" "%INC_DIR%\" >nul

echo         RawrXD_TensorLayout_NHWC.hpp - OK
echo         RawrXD_Universal_Compiler_Layout.hpp - OK
echo.

echo [4/4] Running validation tests...
echo.

REM Create simple test program
echo #include "RawrXD_TensorLayout_NHWC.hpp" > %OBJ_DIR%\layout_test.cpp
echo #include ^<cstdio^> >> %OBJ_DIR%\layout_test.cpp
echo #include ^<cstring^> >> %OBJ_DIR%\layout_test.cpp
echo. >> %OBJ_DIR%\layout_test.cpp
echo int main() { >> %OBJ_DIR%\layout_test.cpp
echo     using namespace RawrXD::Memory; >> %OBJ_DIR%\layout_test.cpp
echo     printf("Testing NHWC Layout Converter...\n"); >> %OBJ_DIR%\layout_test.cpp
echo     >> %OBJ_DIR%\layout_test.cpp
echo     // Test 1: Basic conversion >> %OBJ_DIR%\layout_test.cpp
echo     float src[24] = {0}; // 1x2x3x4 >> %OBJ_DIR%\layout_test.cpp
echo     float dst[24] = {0}; >> %OBJ_DIR%\layout_test.cpp
echo     for (int i = 0; i ^< 24; i++) src[i] = (float)i; >> %OBJ_DIR%\layout_test.cpp
echo     >> %OBJ_DIR%\layout_test.cpp
echo     NHWCLayoutConverter::ConvertNCHWtoNHWC(src, dst, 1, 2, 3, 4); >> %OBJ_DIR%\layout_test.cpp
echo     >> %OBJ_DIR%\layout_test.cpp
echo     // Verify layout >> %OBJ_DIR%\layout_test.cpp
echo     bool success = true; >> %OBJ_DIR%\layout_test.cpp
echo     for (int h = 0; h ^< 3; h++) { >> %OBJ_DIR%\layout_test.cpp
echo         for (int w = 0; w ^< 4; w++) { >> %OBJ_DIR%\layout_test.cpp
echo             for (int c = 0; c ^< 2; c++) { >> %OBJ_DIR%\layout_test.cpp
echo                 size_t nchw_idx = ((0 * 2 + c) * 3 + h) * 4 + w; >> %OBJ_DIR%\layout_test.cpp
echo                 size_t nhwc_idx = ((0 * 3 + h) * 4 + w) * 2 + c; >> %OBJ_DIR%\layout_test.cpp
echo                 if (src[nchw_idx] != dst[nhwc_idx]) success = false; >> %OBJ_DIR%\layout_test.cpp
echo             } >> %OBJ_DIR%\layout_test.cpp
echo         } >> %OBJ_DIR%\layout_test.cpp
echo     } >> %OBJ_DIR%\layout_test.cpp
echo     >> %OBJ_DIR%\layout_test.cpp
echo     if (success) { >> %OBJ_DIR%\layout_test.cpp
echo         printf("[PASS] NCHW to NHWC conversion\n"); >> %OBJ_DIR%\layout_test.cpp
echo     } else { >> %OBJ_DIR%\layout_test.cpp
echo         printf("[FAIL] NCHW to NHWC conversion\n"); >> %OBJ_DIR%\layout_test.cpp
echo         return 1; >> %OBJ_DIR%\layout_test.cpp
echo     } >> %OBJ_DIR%\layout_test.cpp
echo     >> %OBJ_DIR%\layout_test.cpp
echo     // Test 2: Stride calculation >> %OBJ_DIR%\layout_test.cpp
echo     uint32_t strides[4]; >> %OBJ_DIR%\layout_test.cpp
echo     NHWCLayoutConverter::CalculateNHWCStrides(1, 64, 32, 32, strides); >> %OBJ_DIR%\layout_test.cpp
echo     if (strides[0] == 65536 && strides[1] == 2048 && strides[2] == 64 && strides[3] == 1) { >> %OBJ_DIR%\layout_test.cpp
echo         printf("[PASS] NHWC stride calculation\n"); >> %OBJ_DIR%\layout_test.cpp
echo     } else { >> %OBJ_DIR%\layout_test.cpp
echo         printf("[FAIL] NHWC stride calculation\n"); >> %OBJ_DIR%\layout_test.cpp
echo         return 1; >> %OBJ_DIR%\layout_test.cpp
echo     } >> %OBJ_DIR%\layout_test.cpp
echo     >> %OBJ_DIR%\layout_test.cpp
echo     printf("\nAll tests passed!\n"); >> %OBJ_DIR%\layout_test.cpp
echo     return 0; >> %OBJ_DIR%\layout_test.cpp
echo } >> %OBJ_DIR%\layout_test.cpp

"%CL%" /nologo /W4 /EHsc /O2 /Zi /MD /arch:AVX512 /Fe"%OBJ_DIR%\layout_test.exe" ^
    "%OBJ_DIR%\layout_test.cpp" ^
    /I"%INC_DIR%" ^
    "%LIB_DIR%\RawrXD_MemoryLayout.lib" 2>&1

if not errorlevel 1 (
    echo Running tests...
    %OBJ_DIR%\layout_test.exe
    if errorlevel 1 (
        echo ERROR: Tests failed
        exit /b 1
    )
) else (
    echo WARNING: Test compilation failed, but library is built
)

echo.
echo ============================================================================
echo Build Complete
echo ============================================================================
echo.
echo Output files:
echo   Library: %LIB_DIR%\RawrXD_MemoryLayout.lib
echo   Headers: %INC_DIR%\RawrXD_TensorLayout_NHWC.hpp
echo            %INC_DIR%\RawrXD_Universal_Compiler_Layout.hpp
echo.
echo Integration:
echo   Add --layout=nhwc to compiler flags for optimal inference performance
echo.

endlocal
