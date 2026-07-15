@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\build-master

"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe" /c /W3 /Zi /Fo:trace_collector_masm.obj ..\src\script\trace_collector_masm.asm
if %ERRORLEVEL% neq 0 echo Assembly failed & exit /b 1

dir trace_collector_masm.obj
