@echo off
setlocal

echo Building RawrXD-Script Trace Collector MASM Integration
echo ========================================================

call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

set "ML64=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe"

echo.
echo Assembling trace_collector_masm.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo:trace_collector_masm.obj ..\src\script\trace_collector_masm.asm
if %ERRORLEVEL% neq 0 goto :fail

echo.
echo Assembling interpreter_full.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo:interpreter_full.obj ..\src\script\masm\interpreter_full.asm
if %ERRORLEVEL% neq 0 goto :fail

echo.
echo Compiling test_trace_collector.cpp...
cl /nologo /W3 /O2 /EHsc /c /Fo:test_trace_collector.obj ..\src\script\test_trace_collector.cpp /I..\src\script
if %ERRORLEVEL% neq 0 goto :fail

echo.
echo Compiling trace_collector.cpp...
cl /nologo /W3 /O2 /EHsc /c /Fo:trace_collector.obj ..\src\script\trace_collector.cpp /I..\src\script
if %ERRORLEVEL% neq 0 goto :fail

echo.
echo Linking test_trace_collector.exe...
link /nologo /OUT:test_trace_collector.exe test_trace_collector.obj trace_collector.obj trace_collector_masm.obj interpreter_full.obj
if %ERRORLEVEL% neq 0 goto :fail

echo.
echo ========================================================
echo Build successful!
echo Running test...
echo ========================================================
test_trace_collector.exe
if %ERRORLEVEL% neq 0 goto :fail

goto :end

:fail
echo.
echo Build failed with error %ERRORLEVEL%
:end
