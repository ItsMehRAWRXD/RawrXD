@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
dumpbin /DEPENDENTS "G:\~dev\rawrxd\build-fd\bin\deep2_streamer_parity.exe" > "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\PRE_RUNTIME_ENV_MANIFEST_001\PE_DEPENDENTS.txt"
dumpbin /IMPORTS "G:\~dev\rawrxd\build-fd\bin\deep2_streamer_parity.exe" > "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\PRE_RUNTIME_ENV_MANIFEST_001\PE_IMPORTS.txt"
echo DUMPBIN_EXIT=%ERRORLEVEL%