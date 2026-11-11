@echo off
setlocal
set OUT=F:\rawrxd\evidence\RAWRXD_GIT_RECOVERY_001\commit_graph_status_now.txt
echo === commit-graph status %DATE% %TIME% > "%OUT%"
if exist F:\rawrxd\.git\objects\info\commit-graph (echo CG_FILE=PRESENT>>"%OUT%") else (echo CG_FILE=ABSENT>>"%OUT%")
if exist F:\rawrxd\.git\objects\info\commit-graphs (echo CG_DIR=PRESENT>>"%OUT%") else (echo CG_DIR=ABSENT>>"%OUT%")
dir /b F:\rawrxd\.git\objects\info >>"%OUT%" 2>&1
type "%OUT%"
