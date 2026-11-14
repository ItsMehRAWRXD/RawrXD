@echo off
setlocal EnableDelayedExpansion
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001"
set LOG=G:\~dev\rawrxd\evidence\GUI_ACCEPTANCE_C36_001\PHASE_INSTRUMENT_001\build.txt
echo BUILD_START %DATE% %TIME%>"%LOG%"
cl.exe @c36_lsp.rsp >>"%LOG%" 2>&1
echo CL_RC=!ERRORLEVEL!>>"%LOG%"
if not !ERRORLEVEL! ==0 exit /b !ERRORLEVEL!
if not exist "CMakeFiles\RawrXD-Win32IDE_phase_instrument001.rsp" (
  powershell -NoProfile -Command "$r=Get-Content 'CMakeFiles\RawrXD-Win32IDE_absorb075c.rsp' -Raw; $r=$r -replace 'RawrXD-Win32IDE_absorb075c.exe','RawrXD-Win32IDE_phase_instrument001.exe'; Set-Content -Path 'CMakeFiles\RawrXD-Win32IDE_phase_instrument001.rsp' -Value $r -NoNewline"
)
link.exe /nologo @"CMakeFiles\RawrXD-Win32IDE_phase_instrument001.rsp" >>"%LOG%" 2>&1
echo LINK_RC=!ERRORLEVEL!>>"%LOG%"
exit /b !ERRORLEVEL!
