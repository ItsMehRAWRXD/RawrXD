@echo off
setlocal
set RAWRXD_GPU_FORWARD=1
set DEEP2_RESIDENT_FIRST=0
set DEEP2_DISABLE_VULKAN=1
"F:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe" --cert-inference --headless > "F:\~dev\_gate_cpu_stdout.txt" 2>"F:\~dev\_gate_cpu_stderr.txt"
echo EXIT_CODE=%ERRORLEVEL% > "F:\~dev\_gate_cpu_exit.txt"
endlocal
