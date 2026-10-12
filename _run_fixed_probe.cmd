@echo off
REM Fixed RAWRXD_STREAM_CANCEL_001 probe (run 2 requests 64 tokens so the
REM client cancellation at token 20 is exercised before any early EOS)
setlocal
set EV=F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001
F:\rawrxd\tmp_build_cap\stream_cancel_probe.exe F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf 20 > %EV%\stream_cancel_probe_run.log 2>&1
echo FIXED_PROBE_RC=%errorlevel% >> %EV%\chain_status.txt
exit /b 0
