@echo off
REM Build P1 observation + tuner authority certs (MSVC)
setlocal
cd /d "%~dp0\.."
if not defined VSCMD_VER (
  echo Run from VS Developer Command Prompt, or call vcvars64.bat first.
)

set INCLUDES=/I. /Iexecution_policy /Imars
set CXXFLAGS=/nologo /EHsc /std:c++17 /W3 /D_CRT_SECURE_NO_WARNINGS /DNOMINMAX /DWIN32_LEAN_AND_MEAN

cl %CXXFLAGS% %INCLUDES% ^
  execution_policy\P1_EXEC_OBSERVATION_INTEGRITY_001.cpp ^
  execution_policy\ExecutionPolicy.cpp ^
  execution_policy\ExecutionPolicyStore.cpp ^
  /Fe:P1_EXEC_OBSERVATION_INTEGRITY_001.exe ^
  /link psapi.lib
if errorlevel 1 exit /b 1

cl %CXXFLAGS% %INCLUDES% ^
  execution_policy\P1_TUNER_AUTHORITY_001.cpp ^
  execution_policy\ExecutionPolicy.cpp ^
  execution_policy\ExecutionPolicyStore.cpp ^
  /Fe:P1_TUNER_AUTHORITY_001.exe
if errorlevel 1 exit /b 1

cl %CXXFLAGS% %INCLUDES% ^
  execution_policy\P1_EXEC_TELEMETRY_INTEGRITY_001.cpp ^
  /Fe:P1_EXEC_TELEMETRY_INTEGRITY_001.exe ^
  /link psapi.lib
if errorlevel 1 exit /b 1

cl %CXXFLAGS% %INCLUDES% ^
  execution_policy\P1_REAL_SPEEDUP_ATTRIBUTION_001.cpp ^
  /Fe:P1_REAL_SPEEDUP_ATTRIBUTION_001.exe
if errorlevel 1 exit /b 1

cl %CXXFLAGS% %INCLUDES% ^
  execution_policy\P1_REALTIME_STATE_IMAGE_001.cpp ^
  /Fe:P1_REALTIME_STATE_IMAGE_001.exe
if errorlevel 1 exit /b 1

cl %CXXFLAGS% %INCLUDES% ^
  execution_policy\P1_REALTIME_GENERATION_CONSISTENCY_001.cpp ^
  /Fe:P1_REALTIME_GENERATION_CONSISTENCY_001.exe
if errorlevel 1 exit /b 1

cl %CXXFLAGS% %INCLUDES% ^
  execution_policy\P1_UNSTATIC_PROMOTION_CAUSALITY_001.cpp ^
  /Fe:P1_UNSTATIC_PROMOTION_CAUSALITY_001.exe
if errorlevel 1 exit /b 1

cl %CXXFLAGS% %INCLUDES% ^
  execution_policy\P1_NUCOLD_HOTPATCH_001.cpp ^
  /Fe:P1_NUCOLD_HOTPATCH_001.exe
if errorlevel 1 exit /b 1

cl %CXXFLAGS% %INCLUDES% ^
  execution_policy\P1_LAZY_REGION_HOTPATCH_001.cpp ^
  /Fe:P1_LAZY_REGION_HOTPATCH_001.exe
if errorlevel 1 exit /b 1

echo.
echo Running certs...
P1_EXEC_OBSERVATION_INTEGRITY_001.exe
set R1=%ERRORLEVEL%
P1_TUNER_AUTHORITY_001.exe
set R2=%ERRORLEVEL%
P1_EXEC_TELEMETRY_INTEGRITY_001.exe
set R3=%ERRORLEVEL%
P1_REAL_SPEEDUP_ATTRIBUTION_001.exe
set R4=%ERRORLEVEL%
P1_REALTIME_STATE_IMAGE_001.exe
set R5=%ERRORLEVEL%
P1_REALTIME_GENERATION_CONSISTENCY_001.exe
set R6=%ERRORLEVEL%
P1_UNSTATIC_PROMOTION_CAUSALITY_001.exe
set R7=%ERRORLEVEL%
P1_NUCOLD_HOTPATCH_001.exe
set R8=%ERRORLEVEL%
P1_LAZY_REGION_HOTPATCH_001.exe
set R9=%ERRORLEVEL%
echo.
if not "%R1%%R2%%R3%%R4%%R5%%R6%%R7%%R8%%R9%"=="000000000" (
  echo CERT SUITE FAILED r1=%R1% r2=%R2% r3=%R3% r4=%R4% r5=%R5% r6=%R6% r7=%R7% r8=%R8% r9=%R9%
  exit /b 1
)
echo CERT SUITE PASSED
exit /b 0
