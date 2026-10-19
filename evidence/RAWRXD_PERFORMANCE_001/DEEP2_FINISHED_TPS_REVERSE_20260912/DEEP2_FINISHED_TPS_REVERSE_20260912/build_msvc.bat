@echo off
setlocal
if not exist out mkdir out
cl /nologo /TC /O2 /W4 /Iinclude src\d2_perf_authority.c src\d2_perf_cli.c /Fe:out\d2_perf_gate.exe
if errorlevel 1 exit /b %errorlevel%
out\d2_perf_gate.exe --mode project --weight-bytes 25000000000 --peak-bw-gbs 640
