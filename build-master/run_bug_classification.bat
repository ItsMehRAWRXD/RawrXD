@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\build-master

set "LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64;%LIB%"

echo Compiling bug classification test...
cl /nologo /W3 /O2 /Fe:test_bug_classification.exe ..\src\script\test_bug_classification.cpp /I..\src\script
if %ERRORLEVEL% neq 0 goto :fail

echo.
echo Running bug classification test...
test_bug_classification.exe

goto :end

:fail
echo Compilation failed
:end
