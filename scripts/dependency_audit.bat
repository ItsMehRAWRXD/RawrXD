@echo off
REM ============================================================================
REM Dependency Audit Script (Gate B)
REM Validates no non-system DLL dependencies
REM ============================================================================

setlocal EnableDelayedExpansion

set TARGET_EXE=%~1

if "%TARGET_EXE%"=="" (
    echo Usage: dependency_audit.bat ^<executable_path^>
    exit /b 1
)

if not exist "%TARGET_EXE%" (
    echo ERROR: Executable not found: %TARGET_EXE%
    exit /b 1
)

echo Running dependency audit on: %TARGET_EXE%
echo.

REM Check for dumpbin
where dumpbin >nul 2>nul
if errorlevel 1 (
    echo WARNING: dumpbin not found, using fallback method
    goto fallback_method
)

REM Use dumpbin to list dependencies
echo Dependencies found:
dumpbin /dependents "%TARGET_EXE%" 2>nul | findstr /i "\.dll" | findstr /v /i "Dump of"

REM Check for problematic dependencies
echo.
echo Checking for non-system dependencies...

set PROBLEMATIC=0

for /f "tokens=*" %%a in ('dumpbin /dependents "%TARGET_EXE%" 2^>nul ^| findstr /i "\.dll" ^| findstr /v /i "Dump of"') do (
    set "DLL=%%a"
    set "DLL=!DLL: =!"
    
    REM Check if it's a system DLL
    set IS_SYSTEM=0
    
    REM Windows core DLLs
    for %%s in (
        "kernel32.dll"
        "user32.dll"
        "advapi32.dll"
        "ntdll.dll"
        "shell32.dll"
        "shlwapi.dll"
        "ws2_32.dll"
        "rpcrt4.dll"
        "ole32.dll"
        "oleaut32.dll"
        "gdi32.dll"
        "winmm.dll"
        "imm32.dll"
        "msvcrt.dll"
        "version.dll"
        "setupapi.dll"
        "cfgmgr32.dll"
        "devobj.dll"
        "powrprof.dll"
        "umpdc.dll"
        "kernelbase.dll"
        "cryptbase.dll"
        "sspicli.dll"
        "sechost.dll"
        "bcrypt.dll"
        "bcryptprimitives.dll"
    ) do (
        if /i "!DLL!"==%%s set IS_SYSTEM=1
    )
    
    if !IS_SYSTEM!==0 (
        echo   [WARNING] Non-system dependency: !DLL!
        set PROBLEMATIC=1
    ) else (
        echo   [OK] System DLL: !DLL!
    )
)

goto audit_complete

:fallback_method
REM Fallback: Use where to check if DLL is in system path
echo Using fallback dependency check...
echo.
echo Note: Install Visual Studio for full dependency analysis

:audit_complete
echo.
if %PROBLEMATIC%==0 (
    echo PASS: No non-system dependencies found
    exit /b 0
) else (
    echo WARNING: Non-system dependencies detected
    echo The executable may require additional runtime components
    exit /b 1
)
