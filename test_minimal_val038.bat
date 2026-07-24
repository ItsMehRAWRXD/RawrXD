@echo off
setlocal

echo === VAL-038 Minimal Kernel Test ===
echo.

set ML64="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set LIBTOOL="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\lib.exe"
set CL="C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64\cl.exe"

cd /d d:\RawrXD

echo Step 1: Assembling minimal kernel...
%ML64% /c /W3 /nologo /Zi /Fo TreeAttention_Fused_VAL038_Minimal.obj src\validation\kernels\masm\TreeAttention_Fused_VAL038_Minimal.asm
if errorlevel 1 goto :error

echo Step 2: Creating library...
%LIBTOOL% /OUT:TreeAttention_Minimal.lib TreeAttention_Fused_VAL038_Minimal.obj
if errorlevel 1 goto :error

echo Step 3: Compiling test...
%CL% /O2 /W3 /nologo /Fe:VAL038_Minimal_Test.exe src\benchmark\VAL038_Minimal_Test.cpp /link TreeAttention_Minimal.lib
if errorlevel 1 goto :error

echo Step 4: Running test...
VAL038_Minimal_Test.exe
if errorlevel 1 goto :fail

echo.
echo [SUCCESS] All tests passed!
goto :end

:error
echo.
echo [ERROR] Build failed!
exit /b 1

:fail
echo.
echo [FAIL] Test failed!
exit /b 1

:end
endlocal
