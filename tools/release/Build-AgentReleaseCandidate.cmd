@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul
if errorlevel 1 exit /b 1
cmake --build "%~dp0..\..\build_tip_chat_ctrl_enter_002" --target deep2_agentic_loop --parallel 4
exit /b %errorlevel%
