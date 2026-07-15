@echo off
REM Simple build script for Oracle

call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64

cd /d d:\src\asm

echo Building KernelDispatch...
cl.exe /c /W3 /O2 /arch:AVX2 /nologo /EHsc /Foobj\Sovereign_KernelDispatch.obj Sovereign_KernelDispatch.cpp
if errorlevel 1 exit /b 1

echo Building Oracle...
cl.exe /c /W3 /O2 /arch:AVX2 /nologo /EHsc /Foobj\Sovereign_Transformer_Oracle.obj Sovereign_Transformer_Oracle.cpp
if errorlevel 1 exit /b 1

echo Linking...
link.exe /SUBSYSTEM:CONSOLE /OUT:Sovereign_Transformer_Oracle.exe obj\Sovereign_Transformer_Oracle.obj obj\Sovereign_KernelDispatch.obj lib\Sovereign_RMSNorm.lib lib\Sovereign_RoPE.lib lib\Sovereign_ResidualAdd.lib lib\Sovereign_LayerNorm.lib lib\Sovereign_Q4K_Dequant.lib legacy_stdio_definitions.lib kernel32.lib
if errorlevel 1 exit /b 1

echo SUCCESS!
pause
