@echo off
tasklist /FI "IMAGENAME eq qwen32_accepted_tps_gate.exe" /FO CSV > F:\~dev\tasklist_gate.txt 2>&1
echo EXIT_CODE=0 >> F:\~dev\tasklist_gate.txt
