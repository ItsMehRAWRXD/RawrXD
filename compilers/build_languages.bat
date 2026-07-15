@echo off
setlocal enabledelayedexpansion
cd /d d:\rawrxd\compilers\languages

echo ============================================
echo RawrXD Multi-Language Compiler Build System
echo ============================================
echo.

set "NASM=C:\Program Files\NASM\nasm.exe"
set "LINK=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"
set "LIBSPATH=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"

set /a BUILT=0
set /a FAILED=0

if not exist "..\built" mkdir "..\built"

:build_loop
if "%~1"=="" goto :done

set "SRC=%~1"
set "BASE=%~n1"

echo Building %BASE%...

"%NASM%" -f win64 "%SRC%" -o "%BASE%.obj" 2>nul
if %ERRORLEVEL% neq 0 (
    echo   [FAIL] Assembly failed for %BASE%
    set /a FAILED+=1
    shift
    goto :build_loop
)

"%LINK%" "%BASE%.obj" /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:"..\built\%BASE%.exe" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib" 2>nul
if %ERRORLEVEL% neq 0 (
    echo   [FAIL] Link failed for %BASE%
    set /a FAILED+=1
    del "%BASE%.obj" 2>nul
    shift
    goto :build_loop
)

echo   [OK] Built %BASE%.exe
del "%BASE%.obj" 2>nul
set /a BUILT+=1

shift
goto :build_loop

:done
echo.
echo ============================================
echo Build Complete: %BUILT% succeeded, %FAILED% failed
echo ============================================

if %FAILED% gtr 0 exit /b 1
exit /b 0
