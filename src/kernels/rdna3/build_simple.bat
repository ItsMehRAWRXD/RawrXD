@echo off
REM RDNA3 Kernel Harness Build - Simplified

echo ========================================
echo  RDNA3 Kernel Harness Build - Simple
echo  Target: RX 7800 XT (gfx1101)
echo ========================================
echo.

set "VS_TOOLS=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717"
set "ML64=%VS_TOOLS%\bin\Hostx64\x64\ml64.exe"
set "LINK=%VS_TOOLS%\bin\Hostx64\x64\link.exe"

if not exist obj mkdir obj
if not exist bin mkdir bin

echo [1/3] Assembling RDNA3_Kernels_Simple.asm...
"%ML64%" /c /W3 /nologo /Zi /Foobj\RDNA3_Kernels.obj RDNA3_Kernels_Simple.asm
if errorlevel 1 goto :error

echo [2/3] Assembling RDNA3_Test_Simple.asm...
"%ML64%" /c /W3 /nologo /Zi /Foobj\RDNA3_Test.obj RDNA3_Test_Simple.asm
if errorlevel 1 goto :error

echo [3/3] Linking RDNA3_Kernel_Harness.exe...
"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB /LARGEADDRESSAWARE:NO /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64" /OUT:bin\RDNA3_Kernel_Harness.exe obj\RDNA3_Kernels.obj obj\RDNA3_Test.obj kernel32.lib
if errorlevel 1 goto :error

echo.
echo ========================================
echo  BUILD SUCCESSFUL
echo ========================================
echo.
echo Output: bin\RDNA3_Kernel_Harness.exe
echo.
goto :end

:error
echo.
echo [!] BUILD FAILED
echo.
exit /b 1

:end
