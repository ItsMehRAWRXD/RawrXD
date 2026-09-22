@echo off
git -C F:\ status --short ~dev/ > f:\~dev\_git_status_out.txt 2> nul
echo done > f:\~dev\_git_status_done.txt
