call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
echo VCVARS_OK>>"F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\wave1_rebuild_prove.log"
cmake -S F:\rawrxd -B "F:\rawrxd\build_tip_debug_rel" -DRAWRXD_BUILD_DEEP2_ENGINE=ON >>"F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\wave1_rebuild_prove.log" 2>&1
echo CMAKE_RECONFIG_EXIT=%ERRORLEVEL%>>"F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\wave1_rebuild_prove.log"
cmake --build "F:\rawrxd\build_tip_debug_rel" --target rawrxd_computer_use rawrxd_computer_use_ide_verify rawrxd_computer_use_tools_cli RawrXD-Win32IDE-Native-Ext -j 4 >>"F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\wave1_rebuild_prove.log" 2>&1
echo BUILD_CORE_EXIT=%ERRORLEVEL%>>"F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\wave1_rebuild_prove.log"
cmake --build "F:\rawrxd\build_tip_debug_rel" --target RawrXD-CLI-V2 -j 4 >>"F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\wave1_rebuild_prove.log" 2>&1
echo BUILD_CLI_EXIT=%ERRORLEVEL%>>"F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\wave1_rebuild_prove.log"
