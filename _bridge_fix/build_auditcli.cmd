@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (echo VCVARS_FAILED & exit /b 2)
cd /d F:\rawrxd\_bridge_fix
cl /nologo /EHsc /O2 /std:c++20 /W3 /permissive- audit_cli.cpp /Fe:rawr_audit_cli.exe /Fo:audit_cli.obj > auditcli_build.log 2>&1
echo BUILD_EXIT=%errorlevel%
if errorlevel 1 findstr /R /C:"error" auditcli_build.log
exit /b 0
