@echo off
cd /d "G:\~dev\rawrxd\build_win32ide_link001\bin"
set RAWRXD_GHOST_OLLAMA=1
set RAWRXD_OLLAMA_URL=http://127.0.0.1:11434
RawrXD-Win32IDE.exe --test-ghost-text
echo EXIT=%ERRORLEVEL%> "G:\~dev\rawrxd\evidence\RAWRXD_MULTI_MODEL_AGENTIC_GHOSTTEXT_001\ghost_probe_5540_exit.txt"
if exist feature_probe_breadcrumb.txt copy /y feature_probe_breadcrumb.txt "G:\~dev\rawrxd\evidence\RAWRXD_MULTI_MODEL_AGENTIC_GHOSTTEXT_001\ghost_probe_5540_breadcrumb.txt"
if exist feature_probe_last.txt copy /y feature_probe_last.txt "G:\~dev\rawrxd\evidence\RAWRXD_MULTI_MODEL_AGENTIC_GHOSTTEXT_001\ghost_probe_5540_last.txt"
