@echo off
F:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe --cert-agent --headless > F:\~dev\rawrxd\gate16_out.txt 2>&1
echo EXIT_CODE=%ERRORLEVEL% > F:\~dev\rawrxd\gate16_exit.txt
