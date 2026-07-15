@echo off
cd /d d:\rawrxd\build-master

REM Assemble
echo Assembling interpreter.asm...
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Zi /Fo:interpreter_seal.obj ..\src\script\masm\interpreter.asm
if errorlevel 1 goto :error

REM Compile golden_master.cpp
echo Compiling golden_master.cpp...
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe" /c /std:c++20 /W3 /O2 /nologo /Fo:golden_master.obj ..\src\script\golden_master.cpp /I..\src\script /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt"
if errorlevel 1 goto :error

REM Compile sealing tool
echo Compiling seal_full_corpus.cpp...
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe" /c /std:c++20 /W3 /O2 /nologo /Fo:seal_corpus.obj ..\src\script\seal_full_corpus.cpp /I..\src\script /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt"
if errorlevel 1 goto :error

REM Link
echo Linking...
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe" /nologo seal_corpus.obj golden_master.obj interpreter_seal.obj /out:seal_corpus.exe /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" /LIBPATH:"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64" kernel32.lib user32.lib /subsystem:console /machine:x64
if errorlevel 1 goto :error

REM Run
echo Running seal_corpus.exe...
seal_corpus.exe

exit /b %errorlevel%

:error
echo BUILD FAILED
exit /b 1
