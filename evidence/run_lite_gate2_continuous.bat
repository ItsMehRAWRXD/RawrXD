@echo off
setlocal
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
set LOG=F:\rawrxd-native-agent-001\evidence\gate2_lite_continuous_meta.txt
set OUT=F:\rawrxd-native-agent-001\evidence\reap_calibration_continuous_lite_001.json
set REF=F:\rawrxd-native-agent-001\evidence\independent_reference_receipt.json
set MODEL=F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf
set CORPUS=F:\rawrxd-native-agent-001\corpus.jsonl
set REPLAY=F:\rawrxd\build_ide\bin-msvc\rawr-reap-replay.exe

echo === LITE gate2 continuous %DATE% %TIME% > "%LOG%"
echo CHOICE=LITE_CONTINUOUS_REPLAY_NOT_K2_ORACLE>> "%LOG%"
echo K2_CAPTURE=DEFERRED_OOM_HOLD>> "%LOG%"
echo START=%TIME%>> "%LOG%"

call "%VCVARS%"
if errorlevel 1 (echo VCVARS_FAIL>> "%LOG%" & exit /b 1)

cmake --build F:\rawrxd\build_ide --config Release --target rawr-reap-replay
if errorlevel 1 (echo BUILD_FAIL>> "%LOG%" & exit /b 1)

"%REPLAY%" "%MODEL%" "%CORPUS%" "%OUT%" 256 --continuous --parity --reference-receipt "%REF%" 1>>"%LOG%" 2>&1
set EC=%ERRORLEVEL%
echo EXIT=%EC%>> "%LOG%"
echo END=%TIME%>> "%LOG%"
if exist "%OUT%" for %%A in ("%OUT%") do echo OUT_BYTES=%%~zA>> "%LOG%"
echo EXIT=%EC%
exit /b %EC%
