@echo off
setlocal
cl /nologo /O2 /W4 /TC wsc15.c wsc15_probe.c /Fe:wsc15_probe.exe
if errorlevel 1 exit /b %errorlevel%
wsc15_probe.exe
if errorlevel 1 exit /b %errorlevel%
echo WSC15_WIN64=PASS
exit /b 0
