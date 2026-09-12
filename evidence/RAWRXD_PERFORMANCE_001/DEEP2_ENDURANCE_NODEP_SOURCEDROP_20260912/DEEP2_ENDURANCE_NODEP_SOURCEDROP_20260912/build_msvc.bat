@echo off
setlocal
REM Side smoke only — never linked into TARGET=64 cert binary.
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
  echo MSVC_VCVARS_NOT_FOUND
  exit /b 2
)
call "%VCVARS%" >nul
if errorlevel 1 (
  echo MSVC_VCVARS_INIT_FAILED
  exit /b 3
)
where cl >nul 2>&1
if errorlevel 1 (
  echo MSVC_CL_NOT_FOUND_AFTER_VCVARS
  exit /b 4
)
if not exist build mkdir build
cl /nologo /TC /O2 /W4 /WX /MT /D_CRT_SECURE_NO_WARNINGS /Isrc ^
 src\deep2_decode_invariant.c src\deep2_arena_guard.c src\deep2_kv_guard.c ^
 src\deep2_tensor_range_guard.c src\deep2_residency_backpressure.c src\deep2_range_queue.c ^
 src\deep2_epoch.c src\deep2_lifetime.c src\deep2_fence_ring.c src\deep2_descriptor_ring.c ^
 src\deep2_device_health.c src\deep2_progress_watch.c src\deep2_state_digest.c ^
 src\deep2_longrun_stats.c src\deep2_receipt_journal.c src\deep2_destub_audit.c ^
 tests\smoke.c /Fe:build\deep2_endurance_smoke.exe
if errorlevel 1 exit /b %errorlevel%
pushd build
 deep2_endurance_smoke.exe
set RC=%ERRORLEVEL%
popd
exit /b %RC%
