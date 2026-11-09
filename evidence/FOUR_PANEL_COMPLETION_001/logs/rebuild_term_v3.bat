call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64
cd /d "g:\~dev\rawrxd\evidence\FOUR_PANEL_COMPLETION_001"
cl /nologo /EHsc /std:c++17 /Fe:bin\terminal_gate.exe harness\terminal_gate.cpp ..\..\src\win32app\Win32TerminalManager.cpp /I..\..\src\win32app > logs\cl_terminal_gate_v3.txt 2>&1
echo CL=%ERRORLEVEL%
bin\terminal_gate.exe > logs\run_terminal_gate_v3.txt 2>&1
echo RC=%ERRORLEVEL%
type logs\run_terminal_gate_v3.txt
