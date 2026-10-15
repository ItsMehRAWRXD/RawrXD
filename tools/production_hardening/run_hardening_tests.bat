@echo off
REM ============================================================================
REM Build + run the production hardening test suite with MSVC.
REM
REM Usage: run_hardening_tests.bat
REM
REM Compiles the security/memory/crash components together with their tests,
REM links a single test binary, runs it, and reports the harness exit code.
REM Exits non-zero if compilation fails OR any test fails, so CI gates work.
REM ============================================================================
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo ERROR: vcvars64.bat failed
    exit /b 1
)

setlocal enabledelayedexpansion
set ROOT=%CD%
set OBJS=%ROOT%\build_hardening_tests\obj
set OUT=%ROOT%\build_hardening_tests
if not exist "%OBJS%" mkdir "%OBJS%"

echo ============================================================
echo Building production-hardening test suite ^(Release, /W4 /permissive-^)
echo ============================================================

set SOURCES=src\utils\input_sanitizer.cpp src\utils\secure_buffer.cpp src\utils\crash_handler.cpp tests\test_input_sanitizer.cpp tests\test_crash_resilience.cpp tests\main_hardening_tests.cpp

REM Compile each source separately for clearer diagnostics.
for %%S in (%SOURCES%) do (
    echo --- CL %%S
    cl.exe /nologo /std:c++20 /EHsc /W4 /permissive- /O2 /Fo:"%OBJS%\%%~nS.obj" /I"%ROOT%\include" /I"%ROOT%\tests" /c "%%S" 2>&1
    if errorlevel 1 (
        echo COMPILE FAILED: %%S
        exit /b 1
    )
)

echo ------------------------------------------------------------
echo Linking rawrxd_hardening_tests.exe
echo ------------------------------------------------------------
link.exe /nologo /SUBSYSTEM:CONSOLE /OUT:"%OUT%\rawrxd_hardening_tests.exe" %OBJS%\*.obj dbghelp.lib bcrypt.lib 2>&1
if errorlevel 1 (
    echo LINK FAILED
    exit /b 1
)

if not exist "%OUT%" mkdir "%OUT%"
echo.
echo ============================================================
echo Running tests
echo ============================================================
"%OUT%\rawrxd_hardening_tests.exe" 2>&1
set TRC=%errorlevel%
echo.
echo ============================================================
if %TRC% EQU 0 (
    echo ALL TESTS PASSED
) else (
    echo TESTS FAILED ^(exit %TRC%^)
)
echo ============================================================
exit /b %TRC%