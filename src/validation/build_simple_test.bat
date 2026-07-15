@echo off
setlocal

echo Building Q4_0 simple test...

set "CL=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe"
set "INCLUDE=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um"
set "LIB=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"

cd /d "%~dp0"

echo [1/2] Compiling test...
"%CL%" /std:c++17 /EHsc /O2 /Fe:q4_0_simple_test.exe q4_0_simple_test.cpp kernels\masm\q4_0_dequant.obj /link
if errorlevel 1 (
    echo Build failed
    exit /b 1
)

echo   [OK] q4_0_simple_test.exe

echo.
echo [2/2] Running test...
q4_0_simple_test.exe

echo.
pause
