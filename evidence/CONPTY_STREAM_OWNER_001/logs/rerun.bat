call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64
cd /d "g:\~dev\rawrxd\evidence\CONPTY_STREAM_OWNER_001\logs"
cl /nologo /EHsc /Fe:conpty_owner_smoke.exe conpty_owner_smoke.cpp > smoke_rebuild.txt 2>&1
conpty_owner_smoke.exe > smoke_rerun.txt 2>&1
echo RC=%ERRORLEVEL%
type smoke_rerun.txt
