@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" -arch=x64 -no_logo < nul
echo VSCALL_EXIT=%ERRORLEVEL%
where cl
echo WHERE_EXIT=%ERRORLEVEL%
