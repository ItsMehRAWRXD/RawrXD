@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
echo Assembling trace_collector_masm.asm...
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Zi /Fo:trace_collector_masm.obj ..\src\script\trace_collector_masm.asm
echo trace_collector_masm.asm exit code: %ERRORLEVEL%

echo Assembling interpreter_full.asm...
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Zi /Fo:interpreter_full.obj ..\src\script\masm\interpreter_full.asm
echo interpreter_full.asm exit code: %ERRORLEVEL%

dir *.obj | findstr interpreter
