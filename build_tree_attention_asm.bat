@echo off
REM ═══════════════════════════════════════════════════════════════════════════════
REM Build script for RawrXD Tree Attention AVX-512 Assembly Kernel
REM VAL-032: Branchless speculative decoding kernel
REM ═══════════════════════════════════════════════════════════════════════════════

setlocal EnableDelayedExpansion

REM Tool paths from copilot-instructions.md
set ML64="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set LINK="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

REM Source and output paths
set SRC_DIR=d:\RawrXD\src\asm
set OBJ_DIR=d:\RawrXD\build_fix3\obj
set LIB_DIR=d:\RawrXD\build_fix3\lib

REM Create directories if they don't exist
if not exist %OBJ_DIR% mkdir %OBJ_DIR%
if not exist %LIB_DIR% mkdir %LIB_DIR%

echo ═══════════════════════════════════════════════════════════════════════════════
echo Building RawrXD Tree Attention AVX-512 Kernel
echo ═══════════════════════════════════════════════════════════════════════════════
echo.

REM Assemble the AVX-512 kernel
echo [1/3] Assembling RawrXD_TreeAttention_AVX512.asm...
%ML64% /c /W3 /nologo /Zi /Fo %OBJ_DIR%\RawrXD_TreeAttention_AVX512.obj %SRC_DIR%\RawrXD_TreeAttention_AVX512.asm

if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)

echo       Assembly successful: %OBJ_DIR%\RawrXD_TreeAttention_AVX512.obj

REM Create static library
echo.
echo [2/3] Creating static library...
%LINK% /lib /nologo /out:%LIB_DIR%\RawrXD_TreeAttention_AVX512.lib %OBJ_DIR%\RawrXD_TreeAttention_AVX512.obj

if errorlevel 1 (
    echo ERROR: Library creation failed
    exit /b 1
)

echo       Library created: %LIB_DIR%\RawrXD_TreeAttention_AVX512.lib

REM Generate exports file for DLL (optional)
echo.
echo [3/3] Generating exports...
echo EXPORTS > %OBJ_DIR%\TreeAttention.def
echo     TreeAttention_AVX512 >> %OBJ_DIR%\TreeAttention.def
echo     TreeAttention_ScoreBatch >> %OBJ_DIR%\TreeAttention.def
echo     TreeAttention_OnlineSoftmax >> %OBJ_DIR%\TreeAttention.def

echo       Exports defined: TreeAttention_AVX512, TreeAttention_ScoreBatch, TreeAttention_OnlineSoftmax

echo.
echo ═══════════════════════════════════════════════════════════════════════════════
echo Build Complete
echo ═══════════════════════════════════════════════════════════════════════════════
echo.
echo Output files:
echo   Object: %OBJ_DIR%\RawrXD_TreeAttention_AVX512.obj
echo   Library: %LIB_DIR%\RawrXD_TreeAttention_AVX512.lib
echo.
echo To link with your application:
echo   1. Include RawrXD_TreeAttention_AVX512.hpp
echo   2. Link against RawrXD_TreeAttention_AVX512.lib
echo   3. Call TreeAttention_AVX512() for branchless tree attention
echo.
echo Expected performance gain: 100-200us reduction in verification phase
echo Target TPS: 2,000+ with speculative decoding
echo ═══════════════════════════════════════════════════════════════════════════════

endlocal
