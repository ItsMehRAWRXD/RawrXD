@echo off
setlocal
mkdir "F:\rawrxd\evidence\RAWRXD_GIT_RECOVERY_001" 2>nul
set OUT=F:\rawrxd\evidence\RAWRXD_GIT_RECOVERY_001\process_probe.txt
echo === git process probe %DATE% %TIME% > "%OUT%"
wmic process where "name='git.exe'" get ProcessId,ParentProcessId,CommandLine,CreationDate /FORMAT:LIST >> "%OUT%" 2>&1
echo. >> "%OUT%"
echo === tasklist >> "%OUT%"
tasklist /FI "IMAGENAME eq git.exe" /V >> "%OUT%" 2>&1
type "%OUT%"
