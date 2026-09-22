@echo off
cd /d F:\
git log -1 --format="%%H %%s" > f:\~dev\_git_msg.txt 2> nul
git log origin/main -1 --format="%%H %%s" >> f:\~dev\_git_msg.txt 2> nul
