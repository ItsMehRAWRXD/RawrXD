call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
echo VCVARS_OK>>"F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\exactly_once\ext_relink_absorb.log"
cmake --build "F:\rawrxd\build_tip_debug_rel" --config Release --target RawrXD-Win32IDE-Native-Ext -j 4 >>"F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\exactly_once\ext_relink_absorb.log" 2>&1
echo BUILD_EXIT=%ERRORLEVEL%>>"F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\exactly_once\ext_relink_absorb.log"
