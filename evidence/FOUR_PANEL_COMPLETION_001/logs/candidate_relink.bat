call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64
cd /d "g:\~dev\rawrxd\build-win32ide-p1-candidate"
echo START %DATE% %TIME%
"C:\Users\Garrett\AppData\Local\Microsoft\WinGet\Packages\Ninja-build.Ninja_Microsoft.Winget.Source_8wekyb3d8bbwe\ninja.exe" -v CMakeFiles/RawrXD-Win32IDE.dir/src/win32app/Win32TerminalManager.cpp.obj
echo OBJ_RC=%ERRORLEVEL%
"C:\Users\Garrett\AppData\Local\Microsoft\WinGet\Packages\Ninja-build.Ninja_Microsoft.Winget.Source_8wekyb3d8bbwe\ninja.exe" -v bin/RawrXD-Win32IDE.exe
echo LINK_RC=%ERRORLEVEL%
echo END %DATE% %TIME%
if exist bin\RawrXD-Win32IDE.exe (
  powershell -NoProfile -Command "(Get-FileHash 'bin\RawrXD-Win32IDE.exe' -Algorithm SHA256).Hash"
  dir bin\RawrXD-Win32IDE.exe
) else (
  echo EXE_MISSING=1
)
