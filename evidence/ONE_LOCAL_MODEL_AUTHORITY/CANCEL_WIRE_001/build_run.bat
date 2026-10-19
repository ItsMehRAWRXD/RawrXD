@echo off
cd /d G:\~dev\rawrxd
cmake --build build-fd --config Release --target cancel_wire_001
if errorlevel 1 exit /b 1
set RAWRXD_HOST_DECODE=1
set RAWRXD_GREEDY=1
set EXE=build-fd\bin\cancel_wire_001.exe
if exist build-fd\bin\Release\cancel_wire_001.exe set EXE=build-fd\bin\Release\cancel_wire_001.exe
"%EXE%" %*
echo RUN_EXIT=%ERRORLEVEL%
