@echo off
REM Build integration test for RDNA3 kernels

echo ========================================
echo  RDNA3 Integration Test Build
echo ========================================
echo.

set "VS_TOOLS=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717"
set "ML64=%VS_TOOLS%\bin\Hostx64\x64\ml64.exe"
set "LINK=%VS_TOOLS%\bin\Hostx64\x64\link.exe"

if not exist obj mkdir obj
if not exist bin mkdir bin

echo [1/2] Assembling test_integration_simple.asm...
"%ML64%" /c /W3 /nologo /Zi /Foobj\test_integration_simple.obj test_integration_simple.asm
if errorlevel 1 goto :error

echo [2/2] Linking RDNA3_Integration_Test.exe...
"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB /LARGEADDRESSAWARE:NO /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64" /OUT:bin\RDNA3_Integration_Test.exe obj\test_integration_simple.obj obj\RDNA3_AllInOne.obj kernel32.lib
if errorlevel 1 goto :error

echo.
echo ========================================
echo  BUILD SUCCESSFUL
echo ========================================
echo.
echo Running integration test...
bin\RDNA3_Integration_Test.exe
echo.
goto :end

:error
echo.
echo [!] BUILD FAILED
echo.
exit /b 1

:end
