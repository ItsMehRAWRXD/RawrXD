@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 >nul
cd /d G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\obj080_tip_land_avfix
link.exe @"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\A8_MODEL_WIRE_PEER\link_a8_modelwire.rsp"
echo LINK_EXIT=%ERRORLEVEL%
