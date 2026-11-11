@echo off
setlocal
taskkill /IM deep2_agentic_loop.exe /F >nul 2>&1
taskkill /IM "ollama app.exe" /F >nul 2>&1
taskkill /IM ollama.exe /F >nul 2>&1
ping -n 4 127.0.0.1 >nul
start "" "C:\Users\Garrett\AppData\Local\Programs\Ollama\ollama.exe" serve
ping -n 8 127.0.0.1 >nul
curl -s -m 30 http://127.0.0.1:11434/api/tags > F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\loop_placeholder_fix_001\tags_recheck.txt
echo TAGS_RC=%ERRORLEVEL%
for %%A in (F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\loop_placeholder_fix_001\tags_recheck.txt) do echo TAGS_BYTES=%%~zA
curl -s -m 240 -H "Content-Type: application/json" --data-binary @F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\loop_placeholder_fix_001\chat_probe.json http://127.0.0.1:11434/api/chat > F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\loop_placeholder_fix_001\chat_probe3.out
echo CHAT_RC=%ERRORLEVEL%
for %%A in (F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\loop_placeholder_fix_001\chat_probe3.out) do echo CHAT_BYTES=%%~zA
findstr /C:"content" /C:"error" /C:"done" F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\loop_placeholder_fix_001\chat_probe3.out
endlocal
