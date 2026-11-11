@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64
if errorlevel 1 exit /b 91
cd /d F:\rawrxd\build_repair_candidate
del /q "CMakeFiles\rawrxd_agentic_backend.dir\src\backend\ollama_client.cpp.obj" 2>nul
ninja bin-msvc\rawr.exe
echo NINJA_EXIT=%ERRORLEVEL%
exit /b %ERRORLEVEL%
