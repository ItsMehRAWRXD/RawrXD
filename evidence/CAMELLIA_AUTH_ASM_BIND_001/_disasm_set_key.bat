@echo off
setlocal EnableExtensions
set EVID=%~dp0
cd /d "%EVID%"
for %%I in ("C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe") do set DUMPBIN=%%~sI
"%DUMPBIN%" /disasm RawrXD_Camellia256_e2e.obj > RUNTIME_E2E_cam_disasm.txt
findstr /n /c:"asm_camellia256_set_key" /c:"cam_F" /c:"OutputDebugStringA" /c:"cam_sbox" RUNTIME_E2E_cam_disasm.txt > RUNTIME_E2E_set_key_syms.txt
echo ---- symbols ----
type RUNTIME_E2E_set_key_syms.txt
echo ---- set_key head ----
rem Extract a window around set_key — use findstr context via powershell-free approach
"%DUMPBIN%" /disasm /nobanner runtime_auth_e2e_probe.exe > RUNTIME_E2E_probe_disasm.txt 2>&1
findstr /c:"00007FF" RUNTIME_E2E_probe_disasm.txt | more
echo DONE
exit /b 0
