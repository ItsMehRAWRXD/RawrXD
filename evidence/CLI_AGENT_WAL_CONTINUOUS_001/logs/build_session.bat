@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul
cd /d "g:\~dev\rawrxd\evidence\CLI_AGENT_WAL_CONTINUOUS_001\bin"
cl /nologo /EHsc /std:c++20 /W3 /O2 /I"g:\~dev\rawrxd\src\cli" /Fe:rawrxd_agent_session_001.exe /Fo:sess.obj "g:\~dev\rawrxd\certs\rawrxd_agent_session_001.cpp" > "g:\~dev\rawrxd\evidence\CLI_AGENT_WAL_CONTINUOUS_001\logs\compile_session.txt" 2>&1
echo CL_EXIT=%ERRORLEVEL%>> "g:\~dev\rawrxd\evidence\CLI_AGENT_WAL_CONTINUOUS_001\logs\compile_session.txt"
if exist rawrxd_agent_session_001.exe (
  rawrxd_agent_session_001.exe > "g:\~dev\rawrxd\evidence\CLI_AGENT_WAL_CONTINUOUS_001\logs\session_run.txt" 2>&1
  echo SESSION_EXIT=%ERRORLEVEL%>> "g:\~dev\rawrxd\evidence\CLI_AGENT_WAL_CONTINUOUS_001\logs\session_run.txt"
)
