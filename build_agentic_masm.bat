@echo off
:: ============================================================================
:: build_agentic_masm.bat — Build Agentic MASM Bridge
:: ============================================================================
::
:: Builds the pure x64 MASM agentic core with C++ bridge
::
:: ============================================================================

echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  RawrXD Agentic MASM Bridge Build                                  ║
echo ║  Pure x64 MASM + C++ Integration                                   ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.

:: Setup paths
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set CL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe

:: Check for VS environment
if not exist "%ML64%" (
    echo ERROR: ml64.exe not found at expected path
    echo Please run from VS Developer Command Prompt
    exit /b 1
)

set SRC_DIR=D:\rawrxd\src\core
set BUILD_DIR=D:\rawrxd\build-agentic-masm

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/4] Assembling MASM agentic stubs...
"%ML64%" /c /Fo"%BUILD_DIR%\agentic_masm_stubs.obj" /W3 /Zd /Zi "%SRC_DIR%\agentic_masm_stubs.asm"
if errorlevel 1 (
    echo ERROR: MASM assembly failed
    exit /b 1
)
echo       ^> agentic_masm_stubs.obj created

echo.
echo [2/4] Compiling C++ bridge...
"%CL%" /c /Fo"%BUILD_DIR%\agentic_masm_bridge.obj" /EHsc /O2 /W4 /nologo "%SRC_DIR%\agentic_masm_bridge.cpp"
if errorlevel 1 (
    echo ERROR: C++ compilation failed
    exit /b 1
)
echo       ^> agentic_masm_bridge.obj created

echo.
echo [3/4] Linking executable...
"%LINK%" /OUT:"%BUILD_DIR%\AgenticMASM_Bridge.exe" /SUBSYSTEM:CONSOLE /DEBUG /PDB:"%BUILD_DIR%\AgenticMASM_Bridge.pdb" /MACHINE:X64 /nologo ^
    "%BUILD_DIR%\agentic_masm_stubs.obj" ^
    "%BUILD_DIR%\agentic_masm_bridge.obj" ^
    kernel32.lib ^
    user32.lib
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)
echo       ^> AgenticMASM_Bridge.exe created

echo.
echo [4/4] Verifying build...
if exist "%BUILD_DIR%\AgenticMASM_Bridge.exe" (
    echo       ^> Build SUCCESS
    for %%F in ("%BUILD_DIR%\AgenticMASM_Bridge.exe") do (
        echo       ^> Size: %%~zF bytes
    )
) else (
    echo       ^> Build FAILED
    exit /b 1
)

echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  Build Complete!                                                   ║
echo ║                                                                    ║
echo ║  Output: %BUILD_DIR%\AgenticMASM_Bridge.exe        ║
echo ║                                                                    ║
echo ║  To run:                                                           ║
echo ║    %BUILD_DIR%\AgenticMASM_Bridge.exe               ║
echo ╚═══════════════════════════════════════════════════════════════════╝

exit /b 0
