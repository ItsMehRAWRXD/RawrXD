@echo off
setlocal
taskkill /IM rawr.exe /F >nul 2>&1
taskkill /IM findstr.exe /F >nul 2>&1
timeout /t 2 /nobreak >nul
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d F:\rawrxd\build_tip_debug_rel || exit /b 1
ninja RawrXD-CLI-V2 > F:\rawrxd\tmp_remeasure_014_rebuild.log 2>&1
echo NINJA_EXIT=%ERRORLEVEL%>> F:\rawrxd\tmp_remeasure_014_rebuild.log
echo NINJA_EXIT=%ERRORLEVEL%
certutil -hashfile bin-msvc\rawr.exe SHA256 > F:\rawrxd\tmp_remeasure_014\sha.txt
echo REBUILD_DONE
endlocal
