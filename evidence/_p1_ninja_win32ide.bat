@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "F:\~dev\rawrxd\build-win32ide-p1" || exit /b 1
taskkill /F /IM cl.exe >nul 2>&1
taskkill /F /IM mspdbsrv.exe >nul 2>&1
ping -n 3 127.0.0.1 >nul
del /f /q "bin\RawrXD-Win32IDE.pdb" >nul 2>&1
echo starting ninja -j1 > "F:\~dev\rawrxd\evidence\_p1_ide_build_out.txt"
ninja -j 1 RawrXD-Win32IDE >> "F:\~dev\rawrxd\evidence\_p1_ide_build_out.txt" 2>&1
echo RC=%ERRORLEVEL% >> "F:\~dev\rawrxd\evidence\_p1_ide_build_out.txt"
exit /b %ERRORLEVEL%
