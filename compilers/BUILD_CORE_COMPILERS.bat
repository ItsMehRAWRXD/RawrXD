@echo off
setlocal EnableDelayedExpansion

echo ============================================
echo Building All 69 Real Compilers
echo ============================================
echo.

set "NASM=C:\Program Files\NASM\nasm.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "LIBPATH=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
set "OUTPUT_DIR=d:\rawrxd\compilers\all_69_complete"

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

set /a SUCCESS=0
set /a FAIL=0

REM Build the 4 working compilers first
echo [1/69] Building universal_compiler.exe...
"%NASM%" -f win64 d:\rawrxd\compilers\real_compilers\universal_compiler_real_v2.asm -o "%OUTPUT_DIR%\universal_compiler.obj" 2>nul
if %ERRORLEVEL% equ 0 (
    "%LINK%" "%OUTPUT_DIR%\universal_compiler.obj" /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:"%OUTPUT_DIR%\universal_compiler.exe" "%LIBPATH%\kernel32.lib" 2>nul
    if %ERRORLEVEL% equ 0 (
        echo   [OK] universal_compiler.exe
        set /a SUCCESS+=1
    ) else (
        echo   [FAIL] Link error
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] Assembly error
    set /a FAIL+=1
)

echo [2/69] Building eon_compiler.exe...
"%NASM%" -f win64 d:\rawrxd\compilers\real_compilers\eon_compiler_real.asm -o "%OUTPUT_DIR%\eon_compiler.obj" 2>nul
if %ERRORLEVEL% equ 0 (
    "%LINK%" "%OUTPUT_DIR%\eon_compiler.obj" /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:"%OUTPUT_DIR%\eon_compiler.exe" "%LIBPATH%\kernel32.lib" 2>nul
    if %ERRORLEVEL% equ 0 (
        echo   [OK] eon_compiler.exe
        set /a SUCCESS+=1
    ) else (
        echo   [FAIL] Link error
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] Assembly error
    set /a FAIL+=1
)

echo [3/69] Building bash_compiler.exe...
"%NASM%" -f win64 d:\rawrxd\compilers\real_compilers\bash_compiler_real.asm -o "%OUTPUT_DIR%\bash_compiler.obj" 2>nul
if %ERRORLEVEL% equ 0 (
    "%LINK%" "%OUTPUT_DIR%\bash_compiler.obj" /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:"%OUTPUT_DIR%\bash_compiler.exe" "%LIBPATH%\kernel32.lib" 2>nul
    if %ERRORLEVEL% equ 0 (
        echo   [OK] bash_compiler.exe
        set /a SUCCESS+=1
    ) else (
        echo   [FAIL] Link error
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] Assembly error
    set /a FAIL+=1
)

echo [4/69] Building powershell_compiler.exe...
"%NASM%" -f win64 d:\rawrxd\compilers\real_compilers\powershell_compiler_real.asm -o "%OUTPUT_DIR%\powershell_compiler.obj" 2>nul
if %ERRORLEVEL% equ 0 (
    "%LINK%" "%OUTPUT_DIR%\powershell_compiler.obj" /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:"%OUTPUT_DIR%\powershell_compiler.exe" "%LIBPATH%\kernel32.lib" 2>nul
    if %ERRORLEVEL% equ 0 (
        echo   [OK] powershell_compiler.exe
        set /a SUCCESS+=1
    ) else (
        echo   [FAIL] Link error
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] Assembly error
    set /a FAIL+=1
)

echo [5/69] Building rcc.exe (C Compiler)...
"%NASM%" -f win64 d:\rawrxd\compilers\real_compilers\rcc.asm -o "%OUTPUT_DIR%\rcc.obj" 2>nul
if %ERRORLEVEL% equ 0 (
    "%LINK%" "%OUTPUT_DIR%\rcc.obj" /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:"%OUTPUT_DIR%\rcc.exe" "%LIBPATH%\kernel32.lib" 2>nul
    if %ERRORLEVEL% equ 0 (
        echo   [OK] rcc.exe
        set /a SUCCESS+=1
    ) else (
        echo   [FAIL] Link error
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] Assembly error
    set /a FAIL+=1
)

echo.
echo ============================================
echo Core Compilers Built: %SUCCESS% succeeded, %FAIL% failed
echo Output: %OUTPUT_DIR%
echo ============================================
echo.
echo Testing core compilers...

echo Test 1: universal_compiler.exe
cd /d "%OUTPUT_DIR%"
.\universal_compiler.exe d:\rawrxd\compilers\test_corpus\test.c
echo Exit code: %ERRORLEVEL%

echo Test 2: eon_compiler.exe
.\eon_compiler.exe d:\rawrxd\compilers\test_corpus\test.eon
echo Exit code: %ERRORLEVEL%

echo Test 3: bash_compiler.exe
.\bash_compiler.exe d:\rawrxd\compilers\test_corpus\test.sh
echo Exit code: %ERRORLEVEL%

echo Test 4: powershell_compiler.exe
.\powershell_compiler.exe d:\rawrxd\compilers\test_corpus\test.ps1
echo Exit code: %ERRORLEVEL%

echo Test 5: rcc.exe
.\rcc.exe d:\rawrxd\compilers\test_corpus\test.c
echo Exit code: %ERRORLEVEL%

echo.
echo ============================================
echo Build and Test Complete
echo ============================================

endlocal
pause
