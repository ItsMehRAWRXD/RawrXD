@echo off
:: ============================================================================
:: build_agentic_sovereign.bat - Build Pure MASM Agentic Core
:: ============================================================================
::
:: NO C++. NO CRT. Just Windows API + MASM.
::
:: ============================================================================

echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  RawrXD Agentic Sovereign Core                                      ║
echo ║  Pure x64 MASM — Zero Dependencies                                  ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.

:: Setup paths
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe

:: Check for tools
if not exist "%ML64%" (
    echo ERROR: ml64.exe not found at expected path
    echo Looking for alternative...
    where ml64.exe >nul 2>&1
    if errorlevel 1 (
        echo ERROR: ml64.exe not found in PATH
        exit /b 1
    ) else (
        for /f "tokens=*" %%a in ('where ml64.exe') do set ML64=%%a
        echo Found ml64.exe at: %ML64%
    )
)

if not exist "%LINK%" (
    echo ERROR: link.exe not found at expected path
    where link.exe >nul 2>&1
    if errorlevel 1 (
        echo ERROR: link.exe not found in PATH
        exit /b 1
    ) else (
        for /f "tokens=*" %%a in ('where link.exe') do set LINK=%%a
        echo Found link.exe at: %LINK%
    )
)

set SRC_DIR=D:\rawrxd\src\core
set BUILD_DIR=D:\rawrxd\build-agentic-sovereign

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/3] Assembling Sovereign Agentic Core...
echo       Source: %SRC_DIR%\agentic_sovereign_entry.asm
"%ML64%" /c /Fo"%BUILD_DIR%\agentic_sovereign_entry.obj" /W3 /Zd /Zi "%SRC_DIR%\agentic_sovereign_entry.asm"
if errorlevel 1 (
    echo ERROR: MASM assembly failed
    exit /b 1
)
echo       ^> agentic_sovereign_entry.obj created

echo.
echo [2/3] Linking Sovereign Executable...
echo       Entry: AgenticMain
set LIBPATH=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64
"%LINK%" /OUT:"%BUILD_DIR%\AgenticSovereign.exe" ^
    /SUBSYSTEM:CONSOLE ^
    /ENTRY:AgenticMain ^
    /DEBUG ^
    /PDB:"%BUILD_DIR%\AgenticSovereign.pdb" ^
    /MACHINE:X64 /nologo ^
    /LIBPATH:"%LIBPATH%" ^
    "%BUILD_DIR%\agentic_sovereign_entry.obj" ^
    kernel32.lib ^
    user32.lib
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)
echo       ^> AgenticSovereign.exe created

echo.
echo [3/3] Verifying build...
if exist "%BUILD_DIR%\AgenticSovereign.exe" (
    echo       ^> Build SUCCESS
    for %%F in ("%BUILD_DIR%\AgenticSovereign.exe") do (
        echo       ^> Size: %%~zF bytes
    )
    
    :: Check for CRT dependencies
    echo.
    echo [4/3] Checking dependencies (should show NO CRT)...
    dumpbin /DEPENDENTS "%BUILD_DIR%\AgenticSovereign.exe" 2^>nul | findstr /V "KERNEL32" | findstr /V "USER32" | findstr /V "Summary" | findstr /V "Image" | findstr /V "file" | findstr /V "^$" || echo       ^> No CRT dependencies found (GOOD!)
) else (
    echo       ^> Build FAILED
    exit /b 1
)

echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  Build Complete!                                                     ║
echo ║                                                                    ║
echo ║  Output: %BUILD_DIR%\AgenticSovereign.exe          ║
echo ║                                                                    ║
echo ║  Features:                                                         ║
echo ║    ✓ Pure x64 MASM (no C++, no CRT)                               ║
echo ║    ✓ Windows API only                                             ║
echo ║    ✓ Agentic state machine (THINK/ACT/DONE)                       ║
echo ║    ✓ Tool simulation                                              ║
echo ║    ✓ Console I/O                                                  ║
echo ║                                                                    ║
echo ║  To run:                                                           ║
echo ║    %BUILD_DIR%\AgenticSovereign.exe                ║
echo ╚═══════════════════════════════════════════════════════════════════╝

exit /b 0
