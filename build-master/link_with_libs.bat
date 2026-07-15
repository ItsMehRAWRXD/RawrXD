@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\build-master

set "LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64"

echo Linking with library paths...
link /nologo seal_corpus.obj golden_master.obj interpreter_seal.obj /out:seal_corpus.exe /subsystem:console

if %ERRORLEVEL% neq 0 (
    echo Link failed with error %ERRORLEVEL%
    exit /b 1
)

echo Link successful!
