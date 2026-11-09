call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64
cd /d "g:\~dev\rawrxd\evidence\FOUR_PANEL_COMPLETION_001"
cl /nologo /EHsc /O2 /Fe:bin\conpty_capture_matrix2.exe harness\conpty_capture_matrix2.cpp > logs\cl_matrix2.txt 2>&1
echo CL=%ERRORLEVEL%
bin\conpty_capture_matrix2.exe > logs\run_matrix2.txt 2>&1
echo RC=%ERRORLEVEL%
type logs\run_matrix2.txt
