@echo off
setlocal
findstr /C:"CHAT_TEMPLATE" /C:"ask content" /C:"ASK_OUT" /C:"decoded" /C:"AGENT_RESULT" /C:"Say exactly" F:\rawrxd\tmp_remeasure_013\stdout.txt F:\rawrxd\tmp_remeasure_013\stderr.txt
echo ----TAIL_STDOUT----
powershell -NoProfile -Command "Get-Content -Path 'F:\rawrxd\tmp_remeasure_013\stdout.txt' -Tail 40"
echo ----NINJA----
findstr /C:"NINJA_EXIT" F:\rawrxd\tmp_remeasure_013_build.log
echo ----META_HEX----
findstr /C:"EXIT" F:\rawrxd\tmp_remeasure_013\meta.txt
echo EXTRACT2_DONE
endlocal
