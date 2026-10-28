@echo off
setlocal EnableExtensions
cd /d "%~dp0"
for %%I in ("C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe") do set DUMPBIN=%%~sI
"%DUMPBIN%" /imports runtime_auth_e2e_probe.exe > RUNTIME_E2E_probe_imports.txt
findstr /i "OutputDebug Crypt BCrypt GetComputer VirtualAlloc" RUNTIME_E2E_probe_imports.txt
echo ----
rem Show disasm lines containing 1580-ish set_key: dump around RVA
findstr /c:"000015" /c:"000016" /c:"000017" /c:"000018" /c:"000019" /c:"00001A" /c:"00001B" /c:"00001C" /c:"00001D" /c:"00001E" /c:"00001F" RUNTIME_E2E_probe_disasm.txt > RUNTIME_E2E_probe_rva15.txt
echo ---- first 60 of rva15 ----
powershell -NoProfile -Command "Get-Content -Path RUNTIME_E2E_probe_rva15.txt -TotalCount 60"
exit /b 0
