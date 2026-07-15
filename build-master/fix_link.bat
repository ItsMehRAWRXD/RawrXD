@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\build-master

echo Compiling seal_full_corpus.cpp...
cl /c /std:c++20 /I..\src\script /EHsc /nologo /O2 /Fo:seal_full_corpus.obj ..\src\script\seal_full_corpus.cpp
if %ERRORLEVEL% neq 0 goto :fail

echo Linking...
link /nologo seal_full_corpus.obj interpreter_full.obj trace_collector_masm.obj /out:seal_corpus.exe
if %ERRORLEVEL% neq 0 goto :fail

echo Success!
goto :end

:fail
echo Failed with error %ERRORLEVEL%
:end
