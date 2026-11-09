@echo on
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64
cd /d "g:\~dev\rawrxd\evidence\FOUR_PANEL_COMPLETION_001"
bin\output_gate.exe > logs\run_output_gate.txt 2>&1
echo OUT_RC=%ERRORLEVEL%
bin\problems_gate.exe > logs\run_problems_gate.txt 2>&1
echo PROB_RC=%ERRORLEVEL%
bin\debug_console_gate.exe > logs\run_debug_gate.txt 2>&1
echo DBG_RC=%ERRORLEVEL%
cl /nologo /EHsc /Zi /Od /Fe:bin\debug_fixture.exe fixtures\debug_fixture.cpp > logs\cl_debug_fixture.txt 2>&1
echo FIX_RC=%ERRORLEVEL%
cl /nologo /EHsc /W4 /Fe:bin\broken_space.exe "fixtures\path with spaces\broken file.cpp" > logs\cl_broken_space.txt 2>&1
echo BROKEN_RC=%ERRORLEVEL%
cl /nologo /EHsc /Fe:bin\fixed.exe fixtures\fixed.cpp > logs\cl_fixed.txt 2>&1
bin\fixed.exe > logs\run_fixed.txt 2>&1
bin\terminal_gate.exe > logs\run_terminal_gate.txt 2>&1
echo TERM_RC=%ERRORLEVEL%
