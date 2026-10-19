@echo off
setlocal
cd /d G:\~dev\rawrxd
if not exist "evidence\ONE_LOCAL_MODEL_AUTHORITY\LOCAL_MODEL_E2E_FINISH_001" mkdir "evidence\ONE_LOCAL_MODEL_AUTHORITY\LOCAL_MODEL_E2E_FINISH_001"
set MODEL=G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
if not "%~1"=="" set MODEL=%~1
cmake --build build-fd --config Release --target local_model_e2e_finish_001
echo CMAKE_EXIT=%ERRORLEVEL%
if errorlevel 1 (
  echo Reconfigure may be required if target missing...
  cmake -S . -B build-fd -DRAWRXD_AGENTIC_CLI=ON
  cmake --build build-fd --config Release --target local_model_e2e_finish_001
)
set EXE=
if exist "build-fd\bin\Release\local_model_e2e_finish_001.exe" set EXE=build-fd\bin\Release\local_model_e2e_finish_001.exe
if exist "build-fd\bin\local_model_e2e_finish_001.exe" set EXE=build-fd\bin\local_model_e2e_finish_001.exe
if "%EXE%"=="" (
  echo MISSING_EXE
  exit /b 2
)
set RAWRXD_HOST_DECODE=1
set RAWRXD_GREEDY=1
"%EXE%" "%MODEL%"
echo RUN_EXIT=%ERRORLEVEL%
endlocal
