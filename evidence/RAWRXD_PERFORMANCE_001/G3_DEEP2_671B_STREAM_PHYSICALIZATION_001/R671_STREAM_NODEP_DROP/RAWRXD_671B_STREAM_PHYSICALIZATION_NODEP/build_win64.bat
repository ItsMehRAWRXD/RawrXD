@echo off
setlocal
cl /nologo /O2 /W4 /TC r671_stream.c r671_probe.c /Fe:r671_probe.exe
if errorlevel 1 exit /b %errorlevel%
r671_probe.exe
if errorlevel 1 exit /b %errorlevel%
echo R671_NODEP_WIN64=PASS
exit /b 0
