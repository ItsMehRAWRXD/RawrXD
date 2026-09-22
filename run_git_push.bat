@echo off
cd /d F:\
echo === GIT STATUS === > F:\~dev\git_status_now.txt
git status --short >> F:\~dev\git_status_now.txt 2>&1
echo === GIT ADD === >> F:\~dev\git_status_now.txt
git add -A >> F:\~dev\git_status_now.txt 2>&1
echo === GIT COMMIT === >> F:\~dev\git_status_now.txt
git commit -m "Batch 11: Decode Allocation Hardening for Qwen32 TPS Gate" >> F:\~dev\git_status_now.txt 2>&1
echo === GIT PUSH === >> F:\~dev\git_status_now.txt
git push >> F:\~dev\git_status_now.txt 2>&1
echo DONE >> F:\~dev\git_status_now.txt
