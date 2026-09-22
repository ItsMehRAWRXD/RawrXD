@echo off
"C:\Program Files\Git\cmd\git.exe" -C F:\ log --oneline -1 > F:\~dev\git_out.txt 2>&1
echo done >> F:\~dev\git_out.txt
