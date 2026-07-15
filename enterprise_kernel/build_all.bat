@echo off
REM ============================================================================
REM RAWRXD Win32IDE v14.7 - Production Build Script
REM Builds all 3 MASM modules and runs smoke tests
REM ============================================================================

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set LIBPATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64
set SRCDIR=d:\rawrxd\enterprise_kernel
set BINDIR=%SRCDIR%\bin

echo ============================================================================
echo   RAWRXD Win32IDE v14.7 - Production Build System
echo ============================================================================
echo.

REM Create bin directory if not exists
if not exist "%BINDIR%" mkdir "%BINDIR%"

REM ============================================================================
REM Module 1: IDE Integration (69 Compiler Backends)
REM ============================================================================
echo [BUILD] Module 1: IDE Integration...
"%ML64%" /c /W3 /nologo /Fo "%BINDIR%\RAWRXD_IDE_Integration_v3.obj" "%SRCDIR%\RAWRXD_IDE_Integration_v3.asm"
if errorlevel 1 goto build_fail

"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /MACHINE:X64 /NODEFAULTLIB /OUT:"%BINDIR%\IDE_Test_v3.exe" "%BINDIR%\RAWRXD_IDE_Integration_v3.obj" /LIBPATH:"%LIBPATH%" kernel32.lib
if errorlevel 1 goto link_fail

echo [PASS] IDE Integration compiled and linked
echo.

REM ============================================================================
REM Module 2: Roslyn CLI Bridge
REM ============================================================================
echo [BUILD] Module 2: Roslyn CLI Bridge...
"%ML64%" /c /W3 /nologo /Fo "%BINDIR%\RoslynCLI_Bridge.obj" "%SRCDIR%\RoslynCLI_Bridge.asm"
if errorlevel 1 goto build_fail

echo [PASS] Roslyn CLI Bridge compiled (library module)
echo.

REM ============================================================================
REM Module 3: Micro-Roslyn Syntax Engine
REM ============================================================================
echo [BUILD] Module 3: Micro-Roslyn Syntax Engine...
"%ML64%" /c /W3 /nologo /Fo "%BINDIR%\MicroRoslyn_Syntax_v2.obj" "%SRCDIR%\MicroRoslyn_Syntax_v2.asm"
if errorlevel 1 goto build_fail

echo [PASS] Micro-Roslyn Syntax Engine compiled (library module)
echo.

REM ============================================================================
REM Test Harness 1: MicroRoslyn Standalone Test
REM ============================================================================
echo [BUILD] Test Harness 1: MicroRoslyn Syntax Test...
"%ML64%" /c /W3 /nologo /Fo "%BINDIR%\MicroRoslyn_Test.obj" "%SRCDIR%\MicroRoslyn_Test.asm"
if errorlevel 1 goto build_fail

"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /MACHINE:X64 /NODEFAULTLIB /LARGEADDRESSAWARE:NO /OUT:"%BINDIR%\MicroRoslyn_Test.exe" "%BINDIR%\MicroRoslyn_Test.obj" "%BINDIR%\MicroRoslyn_Syntax_v2.obj" /LIBPATH:"%LIBPATH%" kernel32.lib
if errorlevel 1 goto link_fail

echo [PASS] MicroRoslyn test harness linked
echo.

REM ============================================================================
REM Test Harness 2: RoslynCLI Standalone Test
REM ============================================================================
echo [BUILD] Test Harness 2: RoslynCLI Bridge Test...
"%ML64%" /c /W3 /nologo /Fo "%BINDIR%\RoslynCLI_Test.obj" "%SRCDIR%\RoslynCLI_Test.asm"
if errorlevel 1 goto build_fail

"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /MACHINE:X64 /NODEFAULTLIB /OUT:"%BINDIR%\RoslynCLI_Test.exe" "%BINDIR%\RoslynCLI_Test.obj" "%BINDIR%\RoslynCLI_Bridge.obj" /LIBPATH:"%LIBPATH%" kernel32.lib
if errorlevel 1 goto link_fail

echo [PASS] RoslynCLI test harness linked
echo.

REM ============================================================================
REM Smoke Tests
REM ============================================================================
echo [SMOKE] Running IDE Integration Test...
"%BINDIR%\IDE_Test_v3.exe"
if errorlevel 1 goto smoke_fail

echo.
echo [SMOKE] Running MicroRoslyn Syntax Test...
"%BINDIR%\MicroRoslyn_Test.exe"
if errorlevel 1 goto smoke_fail

echo.
echo [SMOKE] Running RoslynCLI Bridge Test...
"%BINDIR%\RoslynCLI_Test.exe"
if errorlevel 1 goto smoke_fail

echo.
echo [PASS] All smoke tests passed with exit code 0
echo.

REM ============================================================================
REM Summary
REM ============================================================================
echo ============================================================================
echo   BUILD COMPLETE - ALL MODULES VERIFIED
echo ============================================================================
echo   IDE_Test_v3.exe      : 69 compilers verified, exit code 0
echo   MicroRoslyn_Test.exe : Syntax engine verified, exit code 0
echo   RoslynCLI_Test.exe   : Bridge exports verified, exit code 0
echo   RoslynCLI_Bridge.obj : Library module (pipe-based compiler invocation)
echo   MicroRoslyn_Syntax_v2.obj : Library module (C# syntax validation)
echo ============================================================================
goto end

:build_fail
echo [FAIL] Assembly failed
goto end

:link_fail
echo [FAIL] Link failed
goto end

:smoke_fail
echo [FAIL] Smoke test failed with exit code %errorlevel%
goto end

:end
echo.
pause
