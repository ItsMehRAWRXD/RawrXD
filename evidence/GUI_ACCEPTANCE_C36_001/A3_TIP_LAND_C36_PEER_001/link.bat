@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001"
echo LINK_START %DATE% %TIME%>"G:\~dev\rawrxd\evidence\GUI_ACCEPTANCE_C36_001\A3_TIP_LAND_C36_PEER_001\link.txt"
link.exe /nologo @"CMakeFiles\RawrXD-Win32IDE_tip_land_c36_peer.rsp" >>"G:\~dev\rawrxd\evidence\GUI_ACCEPTANCE_C36_001\A3_TIP_LAND_C36_PEER_001\link.txt" 2>&1
echo LINK_RC=%ERRORLEVEL%>>"G:\~dev\rawrxd\evidence\GUI_ACCEPTANCE_C36_001\A3_TIP_LAND_C36_PEER_001\link.txt"
exit /b %ERRORLEVEL%
