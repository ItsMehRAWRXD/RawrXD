@echo off
REM Build C++ test for RDNA3 kernels

echo ========================================
echo  RDNA3 C++ Integration Test Build
echo ========================================
echo.

set "VS_TOOLS=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717"
set "CL=%VS_TOOLS%\bin\Hostx64\x64\cl.exe"
set "LINK=%VS_TOOLS%\bin\Hostx64\x64\link.exe"

if not exist bin mkdir bin

echo [1/2] Compiling test_rdna3_cpp.cpp...
"%CL%" /std:c++20 /O2 /EHsc /Zi /Foobj\test_rdna3_cpp.obj /c test_rdna3_cpp.cpp
if errorlevel 1 goto :error

echo [2/2] Linking test_rdna3_cpp.exe...
"%LINK%" /SUBSYSTEM:CONSOLE /OUT:bin\test_rdna3_cpp.exe obj\test_rdna3_cpp.obj obj\RDNA3_AllInOne.obj kernel32.lib
if errorlevel 1 goto :error

echo.
echo ========================================
echo  BUILD SUCCESSFUL
echo ========================================
echo.
echo Running test...
bin\test_rdna3_cpp.exe
echo.
goto :end

:error
echo.
echo [!] BUILD FAILED
echo.
exit /b 1

:end
