@echo off
"F:\rawrxd\build-modelgenie-tools\bin\gguf_inspector.exe" "G:\~dev\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf" --json "F:\rawrxd\evidence\gguf_tensors.json" > "F:\rawrxd\evidence\gguf_json_export.log" 2>&1
echo Run EXIT=%ERRORLEVEL%