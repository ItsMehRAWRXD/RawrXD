@echo off
setlocal EnableExtensions
set EVID=%~dp0
cd /d "%EVID%"
for %%I in ("C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe") do set DUMPBIN=%%~sI
"%DUMPBIN%" /disasm runtime_auth_e2e_probe.exe > RUNTIME_E2E_probe_disasm.txt
"%DUMPBIN%" /headers runtime_auth_e2e_probe.exe > RUNTIME_E2E_probe_headers.txt
findstr /i "cam_sbox1 cam_sigma cam_debug_init_ok cam_master_key" RUNTIME_E2E_probe_disasm.txt > RUNTIME_E2E_probe_lea.txt
echo ==== LEA targets ====
type RUNTIME_E2E_probe_lea.txt
echo ==== set_key label ====
findstr /c:"set_key" RUNTIME_E2E_probe_disasm.txt | more
echo ==== headers data ====
findstr /i ".data .text size" RUNTIME_E2E_probe_headers.txt
exit /b 0
