call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64
cd /d "g:\~dev\rawrxd\evidence\FOUR_PANEL_COMPLETION_001"
cl /nologo /EHsc /Fe:bin\conpty_verify_winner.exe harness\conpty_verify_winner.cpp > logs\cl_verify.txt 2>&1
bin\conpty_verify_winner.exe > logs\run_verify_winner.txt 2>&1
echo RC=%ERRORLEVEL%
type logs\run_verify_winner.txt
