; RawrXD-Script MASM Build Script
; Build.bat - Assembles and links the interpreter

@echo off
setlocal enabledelayedexpansion

echo RawrXD-Script MASM Build System
echo ==============================
echo.

; Find ML64
set ML64_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
if not exist "%ML64_PATH%" (
    echo ERROR: ML64 not found at %ML64_PATH%
    echo Please install Visual Studio Build Tools with MASM support
    exit /b 1
)

; Find LINK
set LINK_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
if not exist "%LINK_PATH%" (
    echo ERROR: LINK not found at %LINK_PATH%
    exit /b 1
)

; Find LIB
set LIB_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\lib.exe
if not exist "%LIB_PATH%" (
    echo ERROR: LIB not found at %LIB_PATH%
    exit /b 1
)

echo Found ML64: %ML64_PATH%
echo Found LINK: %LINK_PATH%
echo.

; Create output directory
if not exist "..\..\..\build\script" mkdir "..\..\..\build\script"

; Assemble interpreter.asm
echo Assembling interpreter.asm...
"%ML64_PATH%" /c /nologo /Zi /Fo"..\..\..\build\script\interpreter.obj" interpreter.asm
if errorlevel 1 (
    echo FAILED: interpreter.asm
    exit /b 1
)
echo OK: interpreter.obj

; Assemble runtime.asm
echo Assembling runtime.asm...
"%ML64_PATH%" /c /nologo /Zi /Fo"..\..\..\build\script\runtime.obj" runtime.asm
if errorlevel 1 (
    echo FAILED: runtime.asm
    exit /b 1
)
echo OK: runtime.obj

; Create static library
echo Creating static library...
"%LIB_PATH%" /nologo /out:"..\..\..\build\script\rawrxd-script.lib" "..\..\..\build\script\interpreter.obj" "..\..\..\build\script\runtime.obj"
if errorlevel 1 (
    echo FAILED: Creating library
    exit /b 1
)
echo OK: rawrxd-script.lib

echo.
echo Build Complete!
echo Output: ..\..\..\build\script\rawrxd-script.lib
echo.

; Optional: Create DLL instead of static lib
echo Creating DLL...
"%LINK_PATH%" /nologo /dll /out:"..\..\..\build\script\rawrxd-script.dll" "..\..\..\build\script\interpreter.obj" "..\..\..\build\script\runtime.obj" kernel32.lib
if errorlevel 1 (
    echo WARNING: DLL creation failed (may need exports)
) else (
    echo OK: rawrxd-script.dll
)

echo.
echo All done!
pause
