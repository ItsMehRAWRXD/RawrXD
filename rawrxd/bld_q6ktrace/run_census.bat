@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d F:\~dev\rawrxd
cl /nologo /std:c++17 /EHsc /O2 /W3 /Fe:bld_q6ktrace\fp16_census.exe fp16_census.cpp /Fo:bld_q6ktrace\
if errorlevel 1 exit /b 1
bld_q6ktrace\fp16_census.exe