@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

cd /d d:\rawrxd\build-master

cl /c /std:c++20 /I..\src\script /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" /EHsc /nologo /O2 /Fo:CMakeFiles\RawrXD_Script.dir\src\script\runtime\runtime_minimal.cpp.obj ..\src\script\runtime\runtime_minimal.cpp

if %ERRORLEVEL% neq 0 goto :fail

echo Rebuild successful!
goto :end

:fail
echo Rebuild failed with error %ERRORLEVEL%
:end
