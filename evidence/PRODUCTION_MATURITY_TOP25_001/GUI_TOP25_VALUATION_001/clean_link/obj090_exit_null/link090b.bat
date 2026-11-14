@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
set ROOT=G:\~dev\rawrxd
set OUT=%ROOT%\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\obj090_exit_null
set BUILD=%ROOT%\build_win32ide_link001
cd /d "%BUILD%"
powershell -NoProfile -Command ^
  "$src='%ROOT%\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\obj089_aa4f_bisect\link089.rsp';" ^
  "$dst='%OUT%\link090b.rsp';" ^
  "$c=Get-Content $src -Raw;" ^
  "$c=$c -replace [regex]::Escape('g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\obj075_gemma_seal\Deep2Engine_GpuForward.cpp.obj'),'%OUT%\Deep2Engine_GpuForward.cpp.obj';" ^
  "$c=$c -replace 'RawrXD-Win32IDE_tip_land_aa4f_r69','RawrXD-Win32IDE_tip_land_aa4f_r75b';" ^
  "Set-Content -Path $dst -Value $c -NoNewline"
link.exe @"%OUT%\link090b.rsp" >"%OUT%\link090b.log" 2>&1
echo LINK_RC=%ERRORLEVEL%
if exist "%ROOT%\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\RawrXD-Win32IDE_tip_land_aa4f_r75b.exe" (
  copy /Y "%ROOT%\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\RawrXD-Win32IDE_tip_land_aa4f_r75b.exe" "%ROOT%\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_tip_land_aa4f_r75b.exe" >nul
)
endlocal
