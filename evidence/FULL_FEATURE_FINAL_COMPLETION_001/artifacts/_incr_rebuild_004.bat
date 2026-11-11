@echo off
setlocal
set LOG=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_integ_004_followup_incr.log
echo ====RESTART %DATE% %TIME%>>"%LOG%"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >>"%LOG%" 2>&1
cd /d F:\rawrxd\build_tip_debug_rel
echo PWD=%CD%>>"%LOG%"
where ninja >>"%LOG%" 2>&1
echo NINJA_INCR_START>>"%LOG%"
ninja -d explain RawrXD-Win32IDE-Native-Ext >>"%LOG%" 2>&1
echo NINJA_EXIT=%ERRORLEVEL%>>"%LOG%"
exit /b %ERRORLEVEL%
