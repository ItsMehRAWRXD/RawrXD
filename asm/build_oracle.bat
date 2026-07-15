@echo off
REM ============================================================================
REM build_oracle.bat - Build Sovereign Transformer Oracle
REM ============================================================================

setlocal EnableDelayedExpansion

REM Auto-detect VS2022
for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VSINSTALLPATH=%%i"
)

if not defined VSINSTALLPATH (
    echo [ERROR] Visual Studio 2022 not found
    exit /b 1
)

echo [INFO] VS2022 found at: %VSINSTALLPATH%

REM Setup environment
call "%VSINSTALLPATH%\VC\Auxiliary\Build\vcvars64.bat"

REM Build paths
set "SRC_DIR=d:\src\asm"
set "OBJ_DIR=%SRC_DIR%\obj"
set "LIB_DIR=%SRC_DIR%\lib"

if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"
if not exist "%LIB_DIR%" mkdir "%LIB_DIR%"

REM ============================================================================
REM Build Sovereign_KernelDispatch.cpp
REM ============================================================================

echo [BUILD] Compiling Sovereign_KernelDispatch.cpp...

cl.exe /c /W3 /O2 /arch:AVX2 /nologo /EHsc /Fo"%OBJ_DIR%\Sovereign_KernelDispatch.obj" "%SRC_DIR%\Sovereign_KernelDispatch.cpp" 2>&1

if errorlevel 1 (
    echo [ERROR] KernelDispatch compilation failed
    exit /b 1
)

REM ============================================================================
REM Build Sovereign_Transformer_Oracle.cpp
REM ============================================================================

echo [BUILD] Compiling Sovereign_Transformer_Oracle.cpp...

cl.exe /c /W3 /O2 /arch:AVX2 /nologo /EHsc /Fo"%OBJ_DIR%\Sovereign_Transformer_Oracle.obj" "%SRC_DIR%\Sovereign_Transformer_Oracle.cpp" 2>&1

if errorlevel 1 (
    echo [ERROR] Oracle compilation failed
    exit /b 1
)

REM ============================================================================
REM Link executable
REM ============================================================================

echo [BUILD] Linking Sovereign_Transformer_Oracle.exe...

link.exe /SUBSYSTEM:CONSOLE /OUT:"%SRC_DIR%\Sovereign_Transformer_Oracle.exe" ^
    "%OBJ_DIR%\Sovereign_Transformer_Oracle.obj" ^
    "%OBJ_DIR%\Sovereign_KernelDispatch.obj" ^
    "%LIB_DIR%\Sovereign_RMSNorm.lib" ^
    "%LIB_DIR%\Sovereign_RoPE.lib" ^
    "%LIB_DIR%\Sovereign_ResidualAdd.lib" ^
    "%LIB_DIR%\Sovereign_LayerNorm.lib" ^
    "%LIB_DIR%\Sovereign_Q4K_Dequant.lib" ^
    legacy_stdio_definitions.lib kernel32.lib

if errorlevel 1 (
    echo [ERROR] Linking failed
    exit /b 1
)

echo [SUCCESS] Sovereign_Transformer_Oracle.exe built successfully
echo.
echo Run with: Sovereign_Transformer_Oracle.exe [hidden_dim] [num_layers] [seq_len]
echo Example:  Sovereign_Transformer_Oracle.exe 4096 32 5

endlocal
