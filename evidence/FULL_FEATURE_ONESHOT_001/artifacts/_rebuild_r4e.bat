call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "F:\rawrxd\build_tip_debug_rel"
ninja RawrXD-Win32IDE-Native-Ext > "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\tip_integ_candidate_001_rebuild_r4e.log" 2>&1
echo NINJA_RC=%ERRORLEVEL% >> "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\tip_integ_candidate_001_rebuild_r4e.log"
