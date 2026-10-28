call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001"
ninja bin\RawrXD-Win32IDE.exe
echo NINJA_EXIT=%ERRORLEVEL%
