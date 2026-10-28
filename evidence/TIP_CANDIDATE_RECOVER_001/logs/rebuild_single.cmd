@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001"
echo START=%DATE% %TIME%
echo CONTENTION_CLEAR=1
echo SINGLE_CANDIDATE=1
echo NINJA_J=2
where ninja
where link
ninja -j2 bin\RawrXD-Win32IDE.exe
set RC=%ERRORLEVEL%
echo NINJA_EXIT=%RC%
echo END=%DATE% %TIME%
if exist bin\RawrXD-Win32IDE.exe (
  powershell -NoProfile -Command "(Get-FileHash 'bin\RawrXD-Win32IDE.exe' -Algorithm SHA256).Hash" > "%~dp0..\sha_post.txt"
  echo SHA_FILE_WRITTEN
) else (
  echo EXE_MISSING_AFTER_NINJA
)
exit /b %RC%
