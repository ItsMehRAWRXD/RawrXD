@echo off
REM RAWRXD_CORE_DLL_NATIVE_E2E_001 - final E2E evidence chain.
REM A long-form prompt is required: under the corrected numerics the model
REM finishes a 300-number listing at its own EOS (~165-191 tokens), which
REM never reaches the 512-token endurance budget (verified: both story and
REM essay prompts generate the full 64-token probe run without early EOS).
setlocal
set EV=F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001
set BIN=F:\rawrxd\tmp_build_e2e
set PROMPT=User: Tell me a very long and detailed story about a wandering programmer who never stops walking across the country. Do not stop writing until you have written at least one thousand words.

echo FINAL_START >> %EV%\chain_status.txt

%BIN%\e2e_endurance.exe --len 512 "%PROMPT%" > %EV%\endurance_512.log 2>&1
echo FINAL_ENDURANCE_RC=%errorlevel% >> %EV%\chain_status.txt
%BIN%\e2e_endurance.exe --stream 64 "%PROMPT%" > %EV%\streaming_64.log 2>&1
echo FINAL_STREAM_RC=%errorlevel% >> %EV%\chain_status.txt
%BIN%\e2e_endurance.exe --cancel 40 "%PROMPT%" > %EV%\cancellation.log 2>&1
echo FINAL_CANCEL_RC=%errorlevel% >> %EV%\chain_status.txt
%BIN%\e2e_endurance.exe --reuse 8 "%PROMPT%" > %EV%\context_reuse6.log 2>&1
echo FINAL_REUSE_RC=%errorlevel% >> %EV%\chain_status.txt
echo FINAL_COMPLETE >> %EV%\chain_status.txt
exit /b 0
