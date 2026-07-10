@echo off
REM Direct build with explicit paths

cd /d d:\src\asm

set "VCROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"
set "SDKROOT=C:\Program Files (x86)\Windows Kits\10"
set "SDKVER=10.0.26100.0"

set "INCLUDE=%VCROOT%\include;%SDKROOT%\Include\%SDKVER%\ucrt;%SDKROOT%\Include\%SDKVER%\um;%SDKROOT%\Include\%SDKVER%\shared"
set "LIB=%VCROOT%\lib\x64;%SDKROOT%\Lib\%SDKVER%\ucrt\x64;%SDKROOT%\Lib\%SDKVER%\um\x64"
set "PATH=%VCROOT%\bin\Hostx64\x64;%PATH%"

echo INCLUDE=%INCLUDE%
echo.
echo Building KernelDispatch...
"%VCROOT%\bin\Hostx64\x64\cl.exe" /c /W3 /O2 /arch:AVX2 /nologo /EHsc /Foobj\Sovereign_KernelDispatch.obj Sovereign_KernelDispatch.cpp
if errorlevel 1 exit /b 1

echo Building Oracle...
"%VCROOT%\bin\Hostx64\x64\cl.exe" /c /W3 /O2 /arch:AVX2 /nologo /EHsc /Foobj\Sovereign_Transformer_Oracle.obj Sovereign_Transformer_Oracle.cpp
if errorlevel 1 exit /b 1

echo Linking...
"%VCROOT%\bin\Hostx64\x64\link.exe" /SUBSYSTEM:CONSOLE /OUT:Sovereign_Transformer_Oracle.exe obj\Sovereign_Transformer_Oracle.obj obj\Sovereign_KernelDispatch.obj lib\Sovereign_RMSNorm.lib lib\Sovereign_RoPE.lib lib\Sovereign_ResidualAdd.lib lib\Sovereign_LayerNorm.lib lib\Sovereign_Q4K_Dequant.lib legacy_stdio_definitions.lib kernel32.lib
if errorlevel 1 exit /b 1

echo SUCCESS!
pause
