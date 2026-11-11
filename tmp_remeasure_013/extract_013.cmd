@echo off
setlocal
findstr /C:"GEMMA_NUMERIC" /C:"GREEDY" /C:"ASK_PATH" /C:"PREFILL_DONE" /C:"[ask]" /C:"HEADDIM" /C:"CHAT_TEMPLATE" /C:"B3_WARN" /C:"sampled token" F:\rawrxd\tmp_remeasure_013\stdout.txt F:\rawrxd\tmp_remeasure_013\stderr.txt > F:\rawrxd\tmp_remeasure_013\key_extract.txt
findstr /C:"B3_WARN" F:\rawrxd\tmp_remeasure_013\stdout.txt F:\rawrxd\tmp_remeasure_013\stderr.txt > F:\rawrxd\tmp_remeasure_013\b3_warn.txt
findstr /C:"sampled token" F:\rawrxd\tmp_remeasure_013\stdout.txt > F:\rawrxd\tmp_remeasure_013\tokens_all.txt
echo EXTRACT_DONE
endlocal
