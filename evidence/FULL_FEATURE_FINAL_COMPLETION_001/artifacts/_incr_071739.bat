@echo off
setlocal
echo START %DATE% %TIME%>"F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_incr_071739.log"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >>"F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_incr_071739.log" 2>&1
cd /d F:\rawrxd\build_tip_debug_rel || (echo CD_FAIL>>"F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_incr_071739.log" & exit /b 92)
where ninja >>"F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_incr_071739.log" 2>&1
echo BEFORE_NINJA>>"F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_incr_071739.log"
ninja -d explain RawrXD-Win32IDE-Native-Ext >>"F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_incr_071739.log" 2>&1
set RC=%ERRORLEVEL%
echo NINJA_EXIT=%RC%>>"F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_incr_071739.log"
exit /b %RC%
