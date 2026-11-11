@echo off
setlocal EnableExtensions
echo BUILD_START %DATE% %TIME%> "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\_rebuild_saveidesession_026b.log"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >> "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\_rebuild_saveidesession_026b.log" 2>&1
if errorlevel 1 (
  echo VCVARS_FAIL>> "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\_rebuild_saveidesession_026b.log"
  exit /b 90
)
echo Building Ext -j2 from F:\rawrxd\build_tip_ext_host_001>> "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\_rebuild_saveidesession_026b.log"
cmake --build "F:\rawrxd\build_tip_ext_host_001" --config RelWithDebInfo --target RawrXD-Win32IDE-Native-Ext -j 2 >> "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\_rebuild_saveidesession_026b.log" 2>&1
set RC=%ERRORLEVEL%
echo BUILD_EXIT=%RC%>> "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\_rebuild_saveidesession_026b.log"
echo BUILD_END %DATE% %TIME%>> "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\_rebuild_saveidesession_026b.log"
exit /b %RC%
