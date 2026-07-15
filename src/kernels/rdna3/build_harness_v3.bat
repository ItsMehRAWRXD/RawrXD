@echo off
REM RDNA3 Kernel Harness Build Script v3
REM Builds x64 host dispatcher with embedded GPU kernel binaries

echo ========================================
echo  RDNA3 Kernel Harness Build v3
echo  Target: RX 7800 XT (gfx1101)
echo  Mode: x64 host + embedded GPU binaries
echo ========================================
echo.

set "VS_TOOLS=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717"
set "ML64=%VS_TOOLS%\bin\Hostx64\x64\ml64.exe"
set "LINK=%VS_TOOLS%\bin\Hostx64\x64\link.exe"
set "CL=%VS_TOOLS%\bin\Hostx64\x64\cl.exe"

REM Create directories
if not exist obj mkdir obj
if not exist bin mkdir bin

echo [1/3] Assembling RDNA3_Kernel_Dispatcher.asm...
"%ML64%" /c /W3 /nologo /Zi /Foobj\RDNA3_Kernel_Dispatcher.obj RDNA3_Kernel_Dispatcher.asm
if errorlevel 1 goto :error

echo [2/3] Compiling RDNA3_Hardware_Probe.cpp...
"%CL%" /std:c++23 /O2 /Isrc /I..\..\.. /D_WIN32_WINNT=0x0A00 /DNDEBUG /Zi /Foobj\RDNA3_Hardware_Probe.obj /c RDNA3_Hardware_Probe.cpp
if errorlevel 1 goto :error

echo [3/3] Linking RDNA3_Kernel_Harness.exe...
"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB /LARGEADDRESSAWARE:NO /OPT:REF /OPT:ICF /OUT:bin\RDNA3_Kernel_Harness.exe obj\RDNA3_Kernel_Dispatcher.obj obj\RDNA3_Hardware_Probe.obj kernel32.lib user32.lib
if errorlevel 1 goto :error

echo.
echo ========================================
echo  BUILD SUCCESSFUL
echo ========================================
echo.
echo Output: bin\RDNA3_Kernel_Harness.exe
echo.
echo Next steps:
echo   1. Run: bin\RDNA3_Kernel_Harness.exe
echo   2. Verify: "KERNEL STABLE" message
echo   3. Integrate: Copy *.obj to src\kernels\
echo   4. Seal Gate: Automatic fingerprint validation
echo.
goto :end

:error
echo.
echo [!] BUILD FAILED
echo.
exit /b 1

:end
