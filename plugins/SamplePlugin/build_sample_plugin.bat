@echo off
REM ============================================================================
REM build_sample_plugin.bat - Build Sample MASM Plugin
REM ============================================================================
REM Builds the SamplePlugin.dll from SamplePlugin.asm
REM 
REM Requirements:
REM   - Visual Studio 2022 (or compatible MASM x64 tools)
REM   - ml64.exe and link.exe in PATH
REM
REM Output:
REM   - SamplePlugin.dll (place in RawrXD/plugins/)
REM ============================================================================

setlocal enabledelayedexpansion

echo =========================================
echo RawrXD Sample Plugin Build Script
echo =========================================
echo.

REM Find Visual Studio tools
set "VSTOOLS=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"

if not exist "%VSTOOLS%\ml64.exe" (
    echo ERROR: Could not find ml64.exe
    echo Please update VSTOOLS path in this script
    exit /b 1
)

set "ML64=%VSTOOLS%\ml64.exe"
set "LINK=%VSTOOLS%\link.exe"

echo Using MASM: %ML64%
echo Using LINK: %LINK%
echo.

REM Create output directory if needed
if not exist "bin" mkdir bin

REM Assemble the source
echo [1/3] Assembling SamplePlugin.asm...
"%ML64%" /c /W3 /nologo /Fo bin\SamplePlugin.obj SamplePlugin.asm
if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)
echo     Success: bin\SamplePlugin.obj created
echo.

REM Link the DLL
echo [2/3] Linking SamplePlugin.dll...
"%LINK%" /DLL /OUT:bin\SamplePlugin.dll bin\SamplePlugin.obj ^
    /SUBSYSTEM:WINDOWS ^
    /ENTRY:DllMain ^
    /NODEFAULTLIB ^
    kernel32.lib user32.lib
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)
echo     Success: bin\SamplePlugin.dll created
echo.

REM Verify exports
echo [3/3] Verifying exports...
dumpbin /EXPORTS bin\SamplePlugin.dll | findstr "RawrXD"
if errorlevel 1 (
    echo WARNING: Could not verify exports
) else (
    echo     Exports verified successfully
echo.

echo =========================================
echo BUILD SUCCESSFUL
echo =========================================
echo.
echo Output: bin\SamplePlugin.dll
echo.
echo To install:
echo   copy bin\SamplePlugin.dll ..\..\plugins\
echo.
echo Or manually copy to: RawrXD\plugins\SamplePlugin.dll
echo.

endlocal
