@echo off
setlocal EnableDelayedExpansion
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001"
set SEAL=G:\~dev\rawrxd\evidence\GUI_ACCEPTANCE_C36_001\PHASE_INSTRUMENT_001
set LOG=%SEAL%\build.txt
echo BUILD_START %DATE% %TIME%>"%LOG%"
cl.exe @c36_lsp.rsp >>"%LOG%" 2>&1
set CLRC=!ERRORLEVEL!
echo CL_LSP_RC=!CLRC!>>"%LOG%"
if not !CLRC! ==0 exit /b !CLRC!
powershell -NoProfile -Command "$r=Get-Content 'CMakeFiles\RawrXD-Win32IDE_absorb075c.rsp' -Raw; $r=$r -replace 'RawrXD-Win32IDE_absorb075c.exe','RawrXD-Win32IDE_phase_instrument001.exe'; Set-Content -Path 'CMakeFiles\RawrXD-Win32IDE_phase_instrument001.rsp' -Value $r -NoNewline"
link.exe /nologo @"CMakeFiles\RawrXD-Win32IDE_phase_instrument001.rsp" >>"%LOG%" 2>&1
set LRC=!ERRORLEVEL!
echo LINK_RC=!LRC!>>"%LOG%"
echo BUILD_END %DATE% %TIME%>>"%LOG%"
exit /b !LRC!
