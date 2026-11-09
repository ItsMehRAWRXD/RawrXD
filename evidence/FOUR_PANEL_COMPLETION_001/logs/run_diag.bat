call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64
cd /d "g:\~dev\rawrxd\evidence\FOUR_PANEL_COMPLETION_001"
cl /nologo /EHsc /Fe:bin\terminal_diag.exe harness\terminal_diag.cpp > logs\cl_terminal_diag.txt 2>&1
bin\terminal_diag.exe > logs\run_terminal_diag.txt 2>&1
echo RC=%ERRORLEVEL%
type logs\run_terminal_diag.txt
