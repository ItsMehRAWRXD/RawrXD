@echo off
setlocal EnableExtensions
set EVID=G:\~dev\rawrxd\evidence\SWARM_16_RUNTIME_002_PATH_A
set ROOT=G:\~dev\rawrxd
set BT=%ROOT%\build_win32ide_link001
set LOG=%EVID%\logs
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" > "%LOG%\vcvars.txt" 2>&1
echo CMAKE_RECONFIGURE:
cmake -S "%ROOT%" -B "%BT%" -G Ninja -DCMAKE_BUILD_TYPE=Release -DRAWRXD_BUILD_WIN32IDE=ON > "%LOG%\cmake_reconfig.log" 2>&1
set RC=%ERRORLEVEL%
echo CMAKE_RECONFIG_EXIT=%RC%
if not "%RC%"=="0" ( echo RECONFIG_FAIL & exit /b 1 )
echo Building RawrXD-Win32IDE -j2 (SWARM_16_RUNTIME_002_PATH_A)...
cmake --build "%BT%" --target RawrXD-Win32IDE --config Release -j 2 > "%LOG%\relink_j2.log" 2>&1
set RC=%ERRORLEVEL%
echo CMAKE_BUILD_EXIT=%RC%
if not "%RC%"=="0" ( echo RELINK_FAIL & tail -n 80 "%LOG%\relink_j2.log" & exit /b 1 )
certutil -hashfile "%BT%\bin\RawrXD-Win32IDE.exe" SHA256 > "%LOG%\post_exe_sha.txt"
type "%LOG%\post_exe_sha.txt"
for %%A in ("%BT%\bin\RawrXD-Win32IDE.exe") do echo EXE_SIZE=%%~zA
echo RELINK_OK
exit /b 0
