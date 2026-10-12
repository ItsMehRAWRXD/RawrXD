@echo off
REM Long-prompt EOS-resistance probe for the endurance certification
setlocal
set EV=F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001

echo PROBE_START >> %EV%\prompt_probe_status.txt
F:\rawrxd\tmp_build_e2e\e2e_endurance.exe --len 64 "User: Tell me a very long and detailed story about a wandering programmer who never stops walking across the country. Do not stop writing until you have written at least one thousand words.\n\nAssistant:" > %EV%\prompt_probe_story.log 2>&1
echo STORY_RC=%errorlevel% >> %EV%\prompt_probe_status.txt
F:\rawrxd\tmp_build_e2e\e2e_endurance.exe --len 64 "User: Write an extremely detailed essay about the complete history of computing, including many specific dates, names, machines and events. Keep writing for as long as you can.\n\nAssistant:" > %EV%\prompt_probe_essay.log 2>&1
echo ESSAY_RC=%errorlevel% >> %EV%\prompt_probe_status.txt
echo PROBE_DONE >> %EV%\prompt_probe_status.txt
exit /b 0
