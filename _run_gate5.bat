@echo off
set RAWRXD_GPU_FORWARD=1
set DEEP2_RESIDENT_FIRST=1
set DEEP2_DISABLE_VULKAN=0
set DEEP2_GPU_FINITE_TRACE=1
"F:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe" --cert-inference --headless 1>"F:\~dev\_gate5_stdout.txt" 2>"F:\~dev\_gate5_stderr.txt"
echo EXIT_CODE=%ERRORLEVEL% > "F:\~dev\_gate5_exit.txt"
