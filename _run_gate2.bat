@echo off
setlocal
set RAWRXD_GPU_FORWARD=1
set DEEP2_RESIDENT_FIRST=1
set DEEP2_DISABLE_VULKAN=0
"F:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe" --cert-inference --headless > "F:\~dev\_gate_stdout2.txt" 2>"F:\~dev\_gate_stderr2.txt"
echo EXIT_CODE=%ERRORLEVEL% > "F:\~dev\_gate_exit2.txt"
endlocal
