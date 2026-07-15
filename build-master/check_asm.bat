@echo off
cd /d d:\rawrxd\build-master
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Zi /Fo:interpreter_test.obj ..\src\script\masm\interpreter.asm 2>&1
