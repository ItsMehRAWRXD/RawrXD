@echo off
cd /d F:\
git add ~dev/tests/qwen32_accepted_tps_gate.cpp 2> nul
git commit -m "Add accepted TPS authority gate source" 2> nul
git push origin main 2> nul
git log origin/main -1 --oneline > f:\~dev\_git_remote_after.txt 2> nul
echo done > f:\~dev\_git_remote_done.txt
