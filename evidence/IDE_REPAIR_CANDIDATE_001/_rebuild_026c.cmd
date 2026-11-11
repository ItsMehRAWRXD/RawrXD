@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" > "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\_rebuild_saveidesession_026c.log" 2>&1
cd /d "F:\rawrxd\build_tip_ext_host_001"
echo NINJA_START %DATE% %TIME%>> "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\_rebuild_saveidesession_026c.log"
ninja -j2 RawrXD-Win32IDE-Native-Ext >> "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\_rebuild_saveidesession_026c.log" 2>&1
echo NINJA_EXIT=%ERRORLEVEL%>> "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\_rebuild_saveidesession_026c.log"
echo NINJA_END %DATE% %TIME%>> "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\_rebuild_saveidesession_026c.log"