@echo off
taskkill /F /PID 43096
timeout /t 2 /nobreak >nul
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d F:\rawrxd\build_tip_debug_rel
ninja RawrXD-CLI-V2 > F:\rawrxd\tmp_remeasure_010_build.log 2>&1
echo NINJA_EXIT=%ERRORLEVEL%
certutil -hashfile bin-msvc\rawr.exe SHA256
findstr /i "Building Linking Deep2Engine no work LNK" F:\rawrxd\tmp_remeasure_010_build.log
