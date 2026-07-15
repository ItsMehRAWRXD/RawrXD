@echo off
setlocal

set ML64="C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe"
set CL="C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe"
set LINK="C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"

set SRCDIR=d:\rawrxd\src\script
set BUILDDIR=d:\rawrxd\build-master

echo Building Golden Master System...
echo ========================================

REM Assemble the interpreter with trace collector
echo [1/4] Assembling interpreter.asm with trace collector...
%ML64% /c /W3 /nologo /Zi /D"RAWRXD_TRACE_COLLECTOR=1" /Fo:%BUILDDIR%\interpreter_gm.obj %SRCDIR%\masm\interpreter.asm
if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)

REM Compile golden_master.cpp
echo [2/4] Compiling golden_master.cpp...
%CL% /c /std:c++20 /W3 /O2 /nologo /Fo:%BUILDDIR%\golden_master.obj %SRCDIR%\golden_master.cpp /I%SRCDIR% /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt"
if errorlevel 1 (
    echo ERROR: golden_master.cpp compilation failed
    exit /b 1
)

REM Compile the test
echo [3/4] Compiling test_golden_master_sealing.cpp...
%CL% /c /std:c++20 /W3 /O2 /nologo /Fo:%BUILDDIR%\test_golden_master.obj %SRCDIR%\test_golden_master_sealing.cpp /I%SRCDIR% /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt"
if errorlevel 1 (
    echo ERROR: Test compilation failed
    exit /b 1
)

REM Link the test executable
echo [4/4] Linking test executable...
%LINK% /nologo %BUILDDIR%\test_golden_master.obj %BUILDDIR%\golden_master.obj %BUILDDIR%\interpreter_gm.obj /out:%BUILDDIR%\test_golden_master.exe /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" /LIBPATH:"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64" kernel32.lib user32.lib /subsystem:console /machine:x64
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)

echo.
echo Build successful!
echo Running Golden Master Sealing Test...
echo.

%BUILDDIR%\test_golden_master.exe

exit /b %errorlevel%
