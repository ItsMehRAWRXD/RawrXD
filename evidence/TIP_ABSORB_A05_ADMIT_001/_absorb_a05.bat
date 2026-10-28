@echo off
setlocal EnableExtensions
set EVID=G:\~dev\rawrxd\evidence\TIP_ABSORB_A05_ADMIT_001
set ROOT=G:\~dev\rawrxd
set BT=%ROOT%\build_win32ide_link001
set LOG=%EVID%\logs
if not exist "%LOG%" mkdir "%LOG%"

call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" > "%LOG%\vcvars.txt" 2>&1

echo PRE_EXE_SHA:
certutil -hashfile "%BT%\bin\RawrXD-Win32IDE.exe" SHA256 > "%LOG%\pre_exe_sha.txt"
type "%LOG%\pre_exe_sha.txt"

echo Building RawrXD-Win32IDE -j2 (TIP_ABSORB_A05_ADMIT_001 Admit+UI+ShellLayout+ConPty)...
cmake --build "%BT%" --target RawrXD-Win32IDE --config Release -j 2 > "%LOG%\relink_j2.log" 2>&1
set RC=%ERRORLEVEL%
echo CMAKE_BUILD_EXIT=%RC%
type "%LOG%\relink_j2.log"
if not "%RC%"=="0" (
  echo RELINK_FAIL
  exit /b 1
)

echo POST_EXE_SHA:
certutil -hashfile "%BT%\bin\RawrXD-Win32IDE.exe" SHA256 > "%LOG%\post_exe_sha.txt"
type "%LOG%\post_exe_sha.txt"
for %%A in ("%BT%\bin\RawrXD-Win32IDE.exe") do echo EXE_SIZE=%%~zA
echo RELINK_OK
exit /b 0
