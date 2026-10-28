@echo off
cd /d "%~dp0"
findstr /c:"0000000140001580" RUNTIME_E2E_probe_disasm.txt
findstr /c:"000000014000158" RUNTIME_E2E_probe_disasm.txt > RUNTIME_E2E_setkey_window.txt
findstr /c:"000000014000159" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"00000001400015A" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"00000001400015B" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"00000001400015C" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"00000001400015D" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"00000001400015E" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"00000001400015F" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"000000014000160" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"000000014000161" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"000000014000162" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"000000014000163" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"000000014000164" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"000000014000165" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"000000014000166" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"000000014000167" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"000000014000168" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"000000014000169" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"00000001400016A" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"00000001400016B" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"00000001400016C" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"00000001400016D" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"00000001400016E" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"00000001400016F" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"000000014000170" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"000000014000171" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
findstr /c:"000000014000172" RUNTIME_E2E_probe_disasm.txt >> RUNTIME_E2E_setkey_window.txt
echo ---- window ----
type RUNTIME_E2E_setkey_window.txt
exit /b 0
