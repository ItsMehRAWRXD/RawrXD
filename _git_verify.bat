@echo off
cd /d F:\
git log -1 --oneline > f:\~dev\_git_verify.txt 2>&1
git status >> f:\~dev\_git_verify.txt 2>&1
echo done >> f:\~dev\_git_verify.txt
