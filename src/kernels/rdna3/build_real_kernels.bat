@echo off
REM Build real RDNA3 kernels with gfx1101 opcodes

echo ========================================
echo  RDNA3 Real Kernel Build
echo  Target: RX 7800 XT (gfx1101)
echo  Using AMD ISA Document 57019 encodings
echo ========================================
echo.

set "VS_TOOLS=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717"
set "ML64=%VS_TOOLS%\bin\Hostx64\x64\ml64.exe"
set "LINK=%VS_TOOLS%\bin\Hostx64\x64\link.exe"

if not exist obj mkdir obj
if not exist bin mkdir bin

echo [1/2] Assembling Q4MatMul_RDNA3_Real.asm...
"%ML64%" /c /W3 /nologo /Zi /Foobj\Q4MatMul_RDNA3_Real.obj Q4MatMul_RDNA3_Real.asm
if errorlevel 1 goto :error

echo [2/2] Linking test executable...
"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB /LARGEADDRESSAWARE:NO /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64" /OUT:bin\Q4MatMul_Test.exe obj\Q4MatMul_RDNA3_Real.obj kernel32.lib
if errorlevel 1 goto :error

echo.
echo ========================================
echo  BUILD SUCCESSFUL
echo ========================================
echo.
echo Kernel binary size:
for %%I in (obj\Q4MatMul_RDNA3_Real.obj) do echo   Q4MatMul_RDNA3_Real.obj: %%~zI bytes
echo.
goto :end

:error
echo.
echo [!] BUILD FAILED
echo.
exit /b 1

:end
