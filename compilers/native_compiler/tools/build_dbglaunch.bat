@echo off
REM ============================================================================
REM  Build the debug launcher.
REM
REM  The launcher starts a program under the Windows debug API and prints the
REM  first exception it takes: the faulting address, the register state, the
REM  stack and the bytes at the instruction pointer.
REM
REM  It is a diagnostic, not a gate. It is the tool that turns "the program
REM  crashed" into "the program jumped to the wrong address" or "the stack
REM  was not 16 byte aligned".
REM
REM  Usage:  dbglaunch.exe <program> [arguments]
REM ============================================================================
setlocal enabledelayedexpansion

for %%I in ("%~dp0..") do set "ROOT=%%~fI"
set "OUT=%~1"
if "%OUT%"=="" for %%I in ("%ROOT%\..\build\rawr_stage1") do set "OUT=%%~fI"
if not exist "%OUT%" mkdir "%OUT%" 2>nul

call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] failed to initialise MSVC environment
    exit /b 1
)

cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /Fe:"%OUT%\dbglaunch.exe" ^
   "%~dp0dbglaunch.c" 2>&1
if errorlevel 1 ( echo [FAIL] dbglaunch build & exit /b 1 )

REM The greater than sign has to be escaped, because the shell would read it
REM as a redirection and send the echo output into the executable.
echo [OK] dbglaunch written to "%OUT%\dbglaunch.exe"
exit /b 0
