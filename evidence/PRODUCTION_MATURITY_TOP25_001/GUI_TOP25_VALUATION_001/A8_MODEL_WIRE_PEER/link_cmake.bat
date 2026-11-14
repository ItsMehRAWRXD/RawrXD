@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 >nul
cd /d G:\~dev\rawrxd\build_win32ide_link001
link.exe /nologo @CMakeFiles\RawrXD-Win32IDE.rsp /OUT:"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\A8_MODEL_WIRE_PEER\RawrXD-Win32IDE_tip_land_a8_modelwire.exe" /PDB:"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\A8_MODEL_WIRE_PEER\a8_modelwire.pdb" /INCREMENTAL:NO /LTCG:OFF
echo LINK_EXIT=%ERRORLEVEL%
