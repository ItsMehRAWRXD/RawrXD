@echo off
REM Build Comprehensive Tier Tests for RawrXD-Script
setlocal enabledelayedexpansion

echo Building Comprehensive Tier Tests...
echo.

REM Set paths
set VSPATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717
set ML64=%VSPATH%\bin\Hostx64\x64\ml64.exe
set CL=%VSPATH%\bin\Hostx64\x64\cl.exe
set LINK=%VSPATH%\bin\Hostx64\x64\link.exe
set INCLUDE=%VSPATH%\include
set LIB=%VSPATH%\lib\x64

REM Create output directory
if not exist d:\rawrxd\bin mkdir d:\rawrxd\bin

REM Assemble interpreter
echo Assembling interpreter.asm...
%ML64% /c /W3 /nologo /Zi /Fo d:\rawrxd\bin\interpreter.obj d:\rawrxd\src\script\masm\interpreter.asm
if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)

REM Compile C++ test suite
echo Compiling comprehensive_tier_tests.cpp...
%CL% /c /nologo /EHsc /Zi /O2 /I%INCLUDE% /Id:\rawrxd\src\script /Fd:\rawrxd\bin\tests.pdb /Fo d:\rawrxd\bin\comprehensive_tier_tests.obj d:\rawrxd\src\script\tests\comprehensive_tier_tests.cpp
if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)

REM Link
echo Linking...
%LINK% /nologo /subsystem:console /debug /out:d:\rawrxd\bin\comprehensive_tier_tests.exe d:\rawrxd\bin\comprehensive_tier_tests.obj d:\rawrxd\bin\interpreter.obj /LIBPATH:%LIB% kernel32.lib legacy_stdio_definitions.lib
if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

echo.
echo Build successful!
echo.
echo Running comprehensive tier tests...
d:\rawrxd\bin\comprehensive_tier_tests.exe

endlocal
