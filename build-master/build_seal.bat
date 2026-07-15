@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\build-master

set "LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64"

echo === Building Seal Corpus ===

echo Compiling seal_full_corpus.cpp...
cl /c /std:c++20 /I..\src\script /EHsc /nologo /O2 /Fo:seal_full_corpus.obj ..\src\script\seal_full_corpus.cpp
if %ERRORLEVEL% neq 0 goto :fail

echo Compiling trace_collector_stub.cpp...
cl /c /std:c++20 /I..\src\script /EHsc /nologo /O2 /Fo:trace_collector_stub.obj ..\src\script\trace_collector_stub.cpp
if %ERRORLEVEL% neq 0 goto :fail

echo Compiling golden_master.cpp...
cl /c /std:c++20 /I..\src\script /EHsc /nologo /O2 /Fo:golden_master.obj ..\src\script\golden_master.cpp
if %ERRORLEVEL% neq 0 goto :fail

echo Linking seal_corpus.exe...
link /nologo seal_full_corpus.obj trace_collector_stub.obj golden_master.obj /out:seal_corpus.exe
if %ERRORLEVEL% neq 0 goto :fail

echo === Build Successful ===
echo Running seal_corpus.exe...
seal_corpus.exe

goto :end

:fail
echo Failed with error %ERRORLEVEL%
:end
