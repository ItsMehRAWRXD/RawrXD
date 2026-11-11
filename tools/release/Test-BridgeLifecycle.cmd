@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul
if errorlevel 1 exit /b 1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-BridgeLifecycle.ps1" -BuildDirectory "%~dp0..\..\build_tip_chat_ctrl_enter_002" -ModelPath "%~dp0..\..\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" -EvidenceDirectory "%~dp0..\..\evidence\IDE_RELEASE_READINESS_001\bridge_003"
exit /b %errorlevel%
