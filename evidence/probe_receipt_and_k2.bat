@echo off
setlocal
echo === receipt + k2 probe
if exist F:\rawrxd-native-agent-001\evidence\independent_reference_receipt.json (echo RECEIPT=PRESENT) else (echo RECEIPT=MISSING)
for %%A in (F:\rawrxd-native-agent-001\evidence\independent_reference_receipt.json) do echo RECEIPT_BYTES=%%~zA
powershell -NoProfile -Command "$j=Get-Content -LiteralPath 'F:\rawrxd-native-agent-001\evidence\independent_reference_receipt.json' -Raw | ConvertFrom-Json; Write-Output ('TOKEN_COUNT=' + $j.token_ids.Count); Write-Output ('RECEIPT_MODEL=' + $j.model); Write-Output ('ENGINE_VER=' + $j.engine_version); Write-Output ('MODEL_SHA=' + $j.model_first_shard_sha256)"
if exist F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M (echo SHARDDIR=PRESENT) else (echo SHARDDIR=MISSING)
dir /b F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\*of-00013.gguf 2>nul | find /c /v ""
dir /b F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\*00001-of-00013.gguf 2>nul
