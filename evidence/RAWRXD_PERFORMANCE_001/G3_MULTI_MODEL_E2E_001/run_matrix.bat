@echo off
set RAWRXD_HOST_DECODE=1
set DEEP2_MINIMAL_ENHANCE=1
set RAWRXD_NO_OLLAMA=1
powershell -NoProfile -ExecutionPolicy Bypass -File "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_MULTI_MODEL_E2E_001\Run-MultiModelE2E.ps1" > "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_MULTI_MODEL_E2E_001\runner.log" 2>&1
echo EXIT=!ERRORLEVEL!>> "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_MULTI_MODEL_E2E_001\runner.log"
