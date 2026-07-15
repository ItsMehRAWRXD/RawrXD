@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\build-master

echo === Rebuilding Compiler ===
cl /c /std:c++20 /I..\src\script /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" /EHsc /nologo /O2 /Fo:CMakeFiles\RawrXD_Script.dir\src\script\compiler\compiler.cpp.obj ..\src\script\compiler\compiler.cpp
if %ERRORLEVEL% neq 0 goto :fail

echo === Relinking ===
link /nologo /OUT:bin\RawrXD_Script.exe CMakeFiles\RawrXD_Script.dir\src\script\runtime\main_full.cpp.obj CMakeFiles\RawrXD_Script.dir\src\script\runtime\runtime_minimal.cpp.obj CMakeFiles\RawrXD_Script.dir\src\script\lexer\lexer.cpp.obj CMakeFiles\RawrXD_Script.dir\src\script\parser\parser.cpp.obj CMakeFiles\RawrXD_Script.dir\src\script\bytecode\bytecode.cpp.obj CMakeFiles\RawrXD_Script.dir\src\script\compiler\compiler.cpp.obj interpreter_full.obj /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" /LIBPATH:"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64" kernel32.lib user32.lib /subsystem:console /machine:x64 /LARGEADDRESSAWARE:NO
if %ERRORLEVEL% neq 0 goto :fail

echo === Running ALU Verification ===
bin\RawrXD_Script.exe bin\test_add2.js
echo.
bin\RawrXD_Script.exe bin\test_sub.js
echo.
bin\RawrXD_Script.exe bin\test_mul.js
echo.
bin\RawrXD_Script.exe bin\test_div.js

goto :end

:fail
echo Build failed with error %ERRORLEVEL%
:end
