@echo off
cd /d "%~dp0"
echo ---- thunk 2351 ----
findstr /c:"000000014000235" RUNTIME_E2E_probe_disasm.txt
echo ---- data headers ----
findstr /i /c:".data" /c:"virtual address" RUNTIME_E2E_probe_headers.txt
echo ---- bytes at string target via dumpbin /section:.data ----
for %%I in ("C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe") do set DUMPBIN=%%~sI
"%DUMPBIN%" /section:.data runtime_auth_e2e_probe.exe
echo ---- skip OutputDebug: rebuild probe without ODS path by patching? ----
exit /b 0
