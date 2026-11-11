@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cmake --build F:\rawrxd\build_tip_debug_rel --target rawrxd_computer_use_tools_cli -j 4
exit /b %ERRORLEVEL%
