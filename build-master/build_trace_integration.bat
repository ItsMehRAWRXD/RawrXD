@echo off
setlocal

set ML64="C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe"
set CL="C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe"
set LINK="C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"

set SRCDIR=d:\rawrxd\src\script
set BUILDDIR=d:\rawrxd\build-master

echo Building Trace Collector Integration...
echo ========================================

REM Assemble the interpreter with trace collector
echo [1/3] Assembling interpreter.asm...
%ML64% /c /W3 /nologo /Zi /Fo:%BUILDDIR%\interpreter_trace.obj %SRCDIR%\masm\interpreter.asm
if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)

REM Compile the C++ test
echo [2/3] Compiling test_trace_collector_integration.cpp...
%CL% /c /std:c++20 /W3 /O2 /nologo /Fo:%BUILDDIR%\test_trace_integration.obj %SRCDIR%\test_trace_collector_integration.cpp /I%SRCDIR% /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt"
if errorlevel 1 (
    echo ERROR: C++ compilation failed
    exit /b 1
)

REM Link the test executable
echo [3/3] Linking test executable...
%LINK% /nologo %BUILDDIR%\test_trace_integration.obj %BUILDDIR%\interpreter_trace.obj /out:%BUILDDIR%\test_trace_integration.exe /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" /LIBPATH:"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64" kernel32.lib user32.lib /subsystem:console /machine:x64
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)

echo.
echo Build successful!
echo Running tests...
echo.

%BUILDDIR%\test_trace_integration.exe

exit /b %errorlevel%
