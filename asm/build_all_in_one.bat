@echo off
REM ============================================================================
REM build_all_in_one.bat - Complete Oracle Build
REM ============================================================================

cd /d d:\src\asm

REM Find VS2022
for /f "delims=" %%i in ('"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set VSPATH=%%i

if not defined VSPATH (
    echo [ERROR] Visual Studio 2022 not found
    exit /b 1
)

echo [INFO] VS2022 found at: %VSPATH%

REM Setup environment
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat"

echo [INFO] Environment configured

REM ============================================================================
REM Build KernelDispatch
REM ============================================================================
echo.
echo [BUILD] Compiling Sovereign_KernelDispatch.cpp...

cl.exe /c /W3 /O2 /arch:AVX2 /nologo /EHsc /Foobj\Sovereign_KernelDispatch.obj Sovereign_KernelDispatch.cpp

if errorlevel 1 (
    echo [ERROR] KernelDispatch compilation failed
    exit /b 1
)
echo [OK] Sovereign_KernelDispatch.obj

REM ============================================================================
REM Build Oracle
REM ============================================================================
echo.
echo [BUILD] Compiling Sovereign_Transformer_Oracle.cpp...

cl.exe /c /W3 /O2 /arch:AVX2 /nologo /EHsc /Foobj\Sovereign_Transformer_Oracle.obj Sovereign_Transformer_Oracle.cpp

if errorlevel 1 (
    echo [ERROR] Oracle compilation failed
    exit /b 1
)
echo [OK] Sovereign_Transformer_Oracle.obj

REM ============================================================================
REM Link
REM ============================================================================
echo.
echo [BUILD] Linking Sovereign_Transformer_Oracle.exe...

link.exe /SUBSYSTEM:CONSOLE /OUT:Sovereign_Transformer_Oracle.exe obj\Sovereign_Transformer_Oracle.obj obj\Sovereign_KernelDispatch.obj lib\Sovereign_RMSNorm.lib lib\Sovereign_RoPE.lib lib\Sovereign_ResidualAdd.lib lib\Sovereign_LayerNorm.lib lib\Sovereign_Q4K_Dequant.lib msvcrt.lib kernel32.lib

if errorlevel 1 (
    echo [ERROR] Linking failed
    exit /b 1
)

echo.
echo ============================================
echo [SUCCESS] Build Complete
echo ============================================
echo.
echo Executable: Sovereign_Transformer_Oracle.exe
echo.
echo Run with: Sovereign_Transformer_Oracle.exe [hidden_dim] [num_layers] [seq_len]
echo Example:  Sovereign_Transformer_Oracle.exe 4096 32 5
echo.
