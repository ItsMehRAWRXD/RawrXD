@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cmake --build F:\rawrxd\build_tip_chat_ctrl_enter_002 --target RawrXD-Win32IDE-Native-Ext -j 8
echo NINJA_RC=%ERRORLEVEL%
exit /b %ERRORLEVEL%
