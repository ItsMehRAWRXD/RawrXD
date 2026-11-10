@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >>"F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\tip_integ_candidate_001_rebuild_r7.log" 2>&1
cd /d "F:\rawrxd\build_tip_debug_rel"
echo BEGIN %DATE% %TIME%>>"F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\tip_integ_candidate_001_rebuild_r7.log"
ninja RawrXD-Win32IDE-Native-Ext >>"F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\tip_integ_candidate_001_rebuild_r7.log" 2>&1
echo NINJA_RC=%ERRORLEVEL% %DATE% %TIME%>>"F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\tip_integ_candidate_001_rebuild_r7.log"

