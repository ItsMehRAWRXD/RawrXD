@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "G:\~dev\rawrxd\evidence\TOOL_ACTION_STATUS_E2E_003"
copy /Y "G:\~dev\rawrxd\evidence\TOOL_ACTION_STATUS_E2E_002\probe_admit_unit.cpp" probe_admit_unit.cpp >nul
cl /nologo /EHsc /std:c++17 /O2 /DWIN32 /D_CRT_SECURE_NO_WARNINGS /I "G:\~dev\rawrxd\src" /Fe:logs\probe_admit_unit.exe probe_admit_unit.cpp "G:\~dev\rawrxd\src\ui\tool_action_status.cpp" > logs\compile_admit.txt 2>&1
echo CL_EXIT=%ERRORLEVEL%>> logs\compile_admit.txt
if exist logs\probe_admit_unit.exe (
  logs\probe_admit_unit.exe > logs\admit_unit.txt 2>&1
  echo ADMIT_EXIT=%ERRORLEVEL%>> logs\admit_unit.txt
)
