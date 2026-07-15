@echo off
setlocal

set CL="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
set OUTDIR=d:\rawrxd\build-master\CMakeFiles\RawrXD_Script.dir\src\script\compiler
set SRCDIR=d:\rawrxd\src\script\compiler

if not exist %OUTDIR% mkdir %OUTDIR%

%CL% /c /std:c++20 /I%SRCDIR%\.. /I%SRCDIR%\..\..\include /I"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" /EHsc /nologo /O2 /Fo%OUTDIR%\compiler.cpp.obj %SRCDIR%\compiler.cpp

echo Compile complete with exit code: %ERRORLEVEL%
