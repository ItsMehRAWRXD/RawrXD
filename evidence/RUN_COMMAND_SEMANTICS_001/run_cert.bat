@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
"F:\~dev\rawrxd\build-win32ide-fresh\bin\RawrXD-Agentic.exe" --run-command-cert --schema-cert-out "F:\~dev\rawrxd\evidence\RUN_COMMAND_SEMANTICS_001" > "F:\~dev\rawrxd\evidence\RUN_COMMAND_SEMANTICS_001\cert.console.txt" 2>&1
echo CERT_EXIT=%ERRORLEVEL%>> "F:\~dev\rawrxd\evidence\RUN_COMMAND_SEMANTICS_001\cert.console.txt"
exit /b %ERRORLEVEL%