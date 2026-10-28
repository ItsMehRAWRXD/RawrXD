call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001"
"C:\Users\Garrett\AppData\Local\Microsoft\WinGet\Packages\Ninja-build.Ninja_Microsoft.Winget.Source_8wekyb3d8bbwe\ninja.exe" -j1 CMakeFiles/RawrXD-Win32IDE.dir/src/deep2/Deep2Engine.cpp.obj CMakeFiles/RawrXD-Win32IDE.dir/src/win32app/Win32IDE.cpp.obj CMakeFiles/RawrXD-Win32IDE.dir/src/win32app/AgentHttpRun.cpp.obj CMakeFiles/RawrXD-Win32IDE.dir/src/win32app/HeadlessIDE_AgentRun.cpp.obj CMakeFiles/RawrXD-Win32IDE.dir/src/win32app/HeadlessIDE_SwarmOrch.cpp.obj CMakeFiles/RawrXD-Win32IDE.dir/src/terminal/embedded_terminal.cpp.obj bin/RawrXD-Win32IDE.exe
echo NINJA_EXIT=%ERRORLEVEL%
