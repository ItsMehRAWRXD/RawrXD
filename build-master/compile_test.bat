@echo off
setlocal

"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe" /nologo /W3 /O2 /Fe:test_full.exe ..\src\script\test_full_interpreter.c ..\src\script\masm\interpreter_full.obj /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" /link /SUBSYSTEM:CONSOLE /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" kernel32.lib libcmt.lib libucrt.lib /LARGEADDRESSAWARE:NO

if %ERRORLEVEL% == 0 (
    echo Compilation successful!
    test_full.exe
) else (
    echo Compilation failed with error %ERRORLEVEL%
)
