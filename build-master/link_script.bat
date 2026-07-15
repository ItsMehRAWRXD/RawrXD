@echo off
setlocal

set LINK="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set LIBPATH1="C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
set LIBPATH2="C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
set LIBPATH3="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64"

cd /d d:\rawrxd\build-master\CMakeFiles\RawrXD_Script.dir

%LINK% /nologo ^
  src\script\runtime\main_full.cpp.obj ^
  src\script\runtime\runtime_minimal.cpp.obj ^
  src\script\lexer\lexer.cpp.obj ^
  src\script\parser\parser.cpp.obj ^
  src\script\bytecode\bytecode.cpp.obj ^
  /out:..\bin\RawrXD_Script.exe ^
  /LIBPATH:%LIBPATH1% ^
  /LIBPATH:%LIBPATH2% ^
  /LIBPATH:%LIBPATH3% ^
  kernel32.lib user32.lib ^
  /subsystem:console /machine:x64

echo Link complete with exit code: %ERRORLEVEL%
