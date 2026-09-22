@echo off
cd /d F:\
git status --short > F:\~dev\git_status_f.txt 2>&1
echo DONE_STATUS >> F:\~dev\git_status_f.txt
