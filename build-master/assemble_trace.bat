@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\src\script

echo Assembling trace_collector_masm.asm...
ml64 /c /W3 /Zi /Fo:trace_collector_masm.obj trace_collector_masm.asm
if %ERRORLEVEL% neq 0 goto :fail

echo Copying to build directory...
copy /y trace_collector_masm.obj d:\rawrxd\build-master\
if %ERRORLEVEL% neq 0 goto :fail

echo Success!
goto :end

:fail
echo Failed with error %ERRORLEVEL%
:end
