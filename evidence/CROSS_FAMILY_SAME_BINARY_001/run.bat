@echo off
setlocal EnableExtensions
set EVID=G:\~dev\rawrxd\evidence\CROSS_FAMILY_SAME_BINARY_001
set FREEZE=G:\~dev\rawrxd\evidence\TIP_FREEZE_001
powershell -NoProfile -ExecutionPolicy Bypass -File "%FREEZE%\resolve_tip_exe.ps1" > "%EVID%\resolve.txt" 2>&1
if errorlevel 1 (echo DISPOSITION=FAIL_CLOSED_SHA> "%EVID%\RECEIPT.txt" & exit /b 3)
cd /d "%FREEZE%\bin"
set LOCAL_ONLY=1
set RAWRXD_HEADLESS=1
echo START_UTC=%DATE% %TIME%> "%EVID%\run_meta.txt"
echo AUTHORITY_EXE=%FREEZE%\bin\RawrXD-Win32IDE.exe>> "%EVID%\run_meta.txt"
echo AUTHORITY_SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145>> "%EVID%\run_meta.txt"
echo REBUILD_THIS_DISPATCH=0>> "%EVID%\run_meta.txt"
echo === FAMILY_A TinyLlama 16 ===>> "%EVID%\run_meta.txt"
RawrXD-Win32IDE.exe --headless --local --no-server --model G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --prompt "Say hi in one word." --max-tokens 16 --backend local --verbose > "%EVID%\tinyllama_stdout.log" 2> "%EVID%\tinyllama_stderr.log"
echo TINYLLAMA_EXIT=%ERRORLEVEL%>> "%EVID%\run_meta.txt"
powershell -NoProfile -ExecutionPolicy Bypass -File "%FREEZE%\resolve_tip_exe.ps1" >> "%EVID%\resolve.txt" 2>&1
if errorlevel 1 (echo SHA_DRIFT_AFTER_TINYLLAMA=1>> "%EVID%\run_meta.txt" & echo DISPOSITION=FAIL_CLOSED_SHA_DRIFT> "%EVID%\RECEIPT.txt" & exit /b 3)
echo === FAMILY_B Gemma3 16 ===>> "%EVID%\run_meta.txt"
RawrXD-Win32IDE.exe --headless --local --no-server --model G:\~dev\rawrxd\models\gemma3-1b-Q2_K.gguf --prompt "Say hi in one word." --max-tokens 16 --backend local --verbose > "%EVID%\gemma3_stdout.log" 2> "%EVID%\gemma3_stderr.log"
echo GEMMA3_EXIT=%ERRORLEVEL%>> "%EVID%\run_meta.txt"
powershell -NoProfile -ExecutionPolicy Bypass -File "%FREEZE%\resolve_tip_exe.ps1" >> "%EVID%\resolve.txt" 2>&1
if errorlevel 1 (echo SHA_DRIFT_AFTER_GEMMA3=1>> "%EVID%\run_meta.txt" & echo DISPOSITION=FAIL_CLOSED_SHA_DRIFT> "%EVID%\RECEIPT.txt" & exit /b 3)
echo END_UTC=%DATE% %TIME%>> "%EVID%\run_meta.txt"
echo DONE
endlocal
