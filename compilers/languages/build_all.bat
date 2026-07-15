@echo off
setlocal enabledelayedexpansion
cd /d d:\rawrxd\compilers\languages

set BUILT=0
set FAILED=0

if not exist "..\built" mkdir "..\built"

for %%f in (*.asm) do (
    echo Building %%~nf...
    "C:\Program Files\NASM\nasm.exe" -f win64 %%f -o %%~nf.obj 2>nul
    if !ERRORLEVEL! neq 0 (
        echo   [FAIL] Assembly failed for %%~nf
        set /a FAILED+=1
    ) else (
        "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe" %%~nf.obj /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:..\built\%%~nf.exe "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib" 2>nul
        if !ERRORLEVEL! neq 0 (
            echo   [FAIL] Link failed for %%~nf
            set /a FAILED+=1
        ) else (
            echo   [OK] %%~nf.exe built
            del %%~nf.obj 2>nul
            set /a BUILT+=1
        )
    )
)

echo.
echo ============================================
echo Build Complete: %BUILT% succeeded, %FAILED% failed
echo ============================================

if %FAILED% gtr 0 exit /b 1
exit /b 0
