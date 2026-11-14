@echo off
setlocal EnableDelayedExpansion
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 >nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001"
set /p CLINE=<"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\A8_MODEL_WIRE_PEER\cline_run.txt"
call %%CLINE%%
echo CL_EXIT=%ERRORLEVEL%
