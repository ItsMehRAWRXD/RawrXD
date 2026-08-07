@echo off
echo Building PHP Compiler v2.0 (Working)...
echo.

set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

echo [1/2] Assembling...
"%ML64%" /c /nologo /Fo php_compiler_working.obj php_compiler_working.asm
if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)

echo [2/2] Linking...
"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:MAIN /NODEFAULTLIB /OUT:php_compiler_working.exe php_compiler_working.obj kernel32.lib
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)

echo.
echo ==========================================
echo BUILD SUCCESSFUL
echo ==========================================
echo.
echo Testing php_compiler_working.exe...
php_compiler_working.exe
echo.
echo Testing with sample PHP file...
echo ^<?php echo "Hello World"; ?^> > test_input.php
php_compiler_working.exe test_input.php
echo.
pause
