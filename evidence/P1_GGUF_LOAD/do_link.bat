@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64
cd /d "F:\~dev\rawrxd\build-win32ide-p1"
echo LIB=%LIB%
link /nologo /OUT:bin\RawrXD-Win32IDE.exe.new /FORCE:MULTIPLE /LARGEADDRESSAWARE:NO @CMakeFiles\RawrXD-Win32IDE.p0.rsp
echo LINK_EXIT=%ERRORLEVEL%
