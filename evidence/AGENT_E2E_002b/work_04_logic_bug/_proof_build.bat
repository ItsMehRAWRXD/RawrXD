@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\work_04_logic_bug"
cmake -S . -B "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\work_04_logic_bug\_proof_build" -G Ninja -DCMAKE_BUILD_TYPE=Release > "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\work_04_logic_bug\_proof_build.txt" 2>&1
if errorlevel 1 exit /b 1
cmake --build "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\work_04_logic_bug\_proof_build" >> "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\work_04_logic_bug\_proof_build.txt" 2>&1
if errorlevel 1 exit /b 1
exit /b 0
