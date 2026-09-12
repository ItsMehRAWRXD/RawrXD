@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS blind_oracle.c /Feblind_oracle.exe
if errorlevel 1 exit /b 1
echo BLIND_ORACLE_BUILT=1
echo NOTE=no production objects linked
exit /b 0
