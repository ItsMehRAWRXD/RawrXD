@echo on
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64
cd /d "g:\~dev\rawrxd\evidence\FOUR_PANEL_COMPLETION_001"
if not exist bin mkdir bin
if not exist logs mkdir logs
where cl
cl /nologo /EHsc /std:c++17 /Fe:bin\output_gate.exe harness\output_gate.cpp > logs\cl_output_gate.txt 2>&1
echo RC_OUTPUT=%ERRORLEVEL%
cl /nologo /EHsc /std:c++17 /Fe:bin\debug_console_gate.exe harness\debug_console_gate.cpp > logs\cl_debug_gate.txt 2>&1
echo RC_DEBUG=%ERRORLEVEL%
cl /nologo /EHsc /std:c++17 /Fe:bin\problems_gate.exe harness\problems_gate.cpp ..\..\src\core\problems_aggregator.cpp /I..\..\src > logs\cl_problems_gate.txt 2>&1
echo RC_PROBLEMS=%ERRORLEVEL%
cl /nologo /EHsc /std:c++17 /Fe:bin\terminal_gate.exe harness\terminal_gate.cpp ..\..\src\win32app\Win32TerminalManager.cpp /I..\..\src\win32app > logs\cl_terminal_gate.txt 2>&1
echo RC_TERMINAL=%ERRORLEVEL%
dir bin
