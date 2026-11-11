@echo off
setlocal
cd /d F:\rawrxd-native-agent-001\evidence
set REPLAY=F:\rawrxd\build_ide\bin-msvc\rawr-reap-replay.exe
set MODEL=F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf
set CORPUS=F:\rawrxd-native-agent-001\corpus.jsonl
set REF=F:\rawrxd-native-agent-001\evidence\independent_reference_receipt.json
set OUT=F:\rawrxd-native-agent-001\evidence\reap_calibration_continuous_001.json
set LOG=F:\rawrxd-native-agent-001\evidence\gate2_continuous_replay_meta.txt

echo === gate2 continuous replay %DATE% %TIME% > "%LOG%"
echo MODEL=%MODEL%>> "%LOG%"
echo REF=%REF%>> "%LOG%"
echo NOTE=no_mla_bypass_no_k2_mount_receipt_bound_to_lite>> "%LOG%"
echo NOTE=omit_require_mla_for_dense_control_path>> "%LOG%"
echo START=%TIME%>> "%LOG%"

if not exist "%REPLAY%" (echo MISSING_REPLAY>> "%LOG%" & exit /b 2)
if not exist "%REF%" (echo MISSING_REF>> "%LOG%" & exit /b 2)
if not exist "%MODEL%" (echo MISSING_MODEL>> "%LOG%" & exit /b 2)

"%REPLAY%" "%MODEL%" "%CORPUS%" "%OUT%" 256 --continuous --parity --reference-receipt "%REF%" 1>>"%LOG%" 2>&1
set EC=%ERRORLEVEL%
echo EXIT=%EC%>> "%LOG%"
echo END=%TIME%>> "%LOG%"
if exist "%OUT%" for %%A in ("%OUT%") do echo OUT_BYTES=%%~zA>> "%LOG%"
echo EXIT=%EC%
type "%LOG%"
exit /b %EC%
