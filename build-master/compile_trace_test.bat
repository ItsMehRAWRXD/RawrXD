@echo off
setlocal enabledelayedexpansion

call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

set "LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64;%LIB%"

echo Compiling test file...
cl /nologo /W3 /O2 /EHsc /c /Fo:test_trace_collector.obj ..\src\script\test_trace_collector.cpp /I..\src\script
if %ERRORLEVEL% neq 0 goto :fail

echo Compiling C++ file...
cl /nologo /W3 /O2 /EHsc /c /Fo:trace_collector.obj ..\src\script\trace_collector.cpp /I..\src\script
if %ERRORLEVEL% neq 0 goto :fail

echo Linking...
cl /nologo /Fe:test_trace_collector.exe test_trace_collector.obj trace_collector.obj
if %ERRORLEVEL% neq 0 goto :fail

echo Compilation successful!
test_trace_collector.exe
if %ERRORLEVEL% neq 0 goto :fail

goto :end

:fail
echo Failed with error %ERRORLEVEL%
:end
