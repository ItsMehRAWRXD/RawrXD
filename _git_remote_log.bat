@echo off
cd /d F:\
git log origin/main -1 --oneline > f:\~dev\_git_remote_log.txt 2> nul
echo done >> f:\~dev\_git_remote_log.txt
