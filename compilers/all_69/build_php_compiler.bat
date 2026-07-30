@echo off
REM Build PHP Compiler v2.0
REM ======================

echo Building PHP Compiler v2.0...
echo.

set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

if not exist "%ML64%" (
    echo ERROR: ml64.exe not found
    exit /b 1
)

echo [1/2] Assembling php_compiler_from_scratch_v2.asm...
"%ML64%" /c /nologo /Fo php_compiler_v2.obj php_compiler_from_scratch_v2.asm
if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)

echo [2/2] Linking php_compiler_v2.exe...
"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /OUT:php_compiler_v2.exe php_compiler_v2.obj kernel32.lib
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)

echo.
echo ==========================================
echo BUILD SUCCESSFUL
echo ==========================================
echo.
echo Testing php_compiler_v2.exe...
echo.
php_compiler_v2.exe
echo.
echo Testing with sample input...
echo.
echo ^<?php echo "Hello World"; ?^> > test_input.php
php_compiler_v2.exe test_input.php test_output.exe
echo.
echo ==========================================
pause
