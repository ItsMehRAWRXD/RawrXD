@echo off
setlocal EnableExtensions
where cl >nul 2>&1
if errorlevel 1 (
  set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
  if not exist "%VCVARS%" (echo MSVC_VCVARS_NOT_FOUND& exit /b 2)
  call "%VCVARS%" >nul
  if errorlevel 1 (echo MSVC_VCVARS_INIT_FAILED& exit /b 3)
)
where cl >nul 2>&1 || (echo MSVC_CL_NOT_FOUND_AFTER_VCVARS& exit /b 4)
cl /nologo /TC /O2 /W4 /WX /MT /Isrc src\d2_range.c src\d2_locality.c src\d2_residency.c src\d2_dual_gpu.c src\d2_stream.c src\d2_plan.c src\d2_runtime.c tests\smoke.c /Fe:deep2_locality_stream_dualgpu_smoke.exe
if errorlevel 1 exit /b %errorlevel%
deep2_locality_stream_dualgpu_smoke.exe
