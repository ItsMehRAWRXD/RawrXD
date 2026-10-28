@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul
cd /d "g:\~dev\rawrxd\evidence\CLI_AGENT_WAL_CONTINUOUS_001\bin"
cl /nologo /EHsc /std:c++20 /W3 /O2 /DAGENT_WAL_SMOKE_MAIN=1 /I"g:\~dev\rawrxd\src\core" /Fe:agent_wal_cli_smoke.exe /Fo:agent_wal_cli_smoke.obj "g:\~dev\rawrxd\src\core\agent_wal_cli_smoke_test.cpp" > "g:\~dev\rawrxd\evidence\CLI_AGENT_WAL_CONTINUOUS_001\logs\compile_smoke.txt" 2>&1
echo CL_EXIT=%ERRORLEVEL%>> "g:\~dev\rawrxd\evidence\CLI_AGENT_WAL_CONTINUOUS_001\logs\compile_smoke.txt"
if exist agent_wal_cli_smoke.exe (
  agent_wal_cli_smoke.exe > "g:\~dev\rawrxd\evidence\CLI_AGENT_WAL_CONTINUOUS_001\logs\smoke_run.txt" 2>&1
  echo SMOKE_EXIT=%ERRORLEVEL%>> "g:\~dev\rawrxd\evidence\CLI_AGENT_WAL_CONTINUOUS_001\logs\smoke_run.txt"
)
