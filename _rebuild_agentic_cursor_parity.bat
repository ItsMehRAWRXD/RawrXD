@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d F:\rawrxd\build_ide 2>nul || cd /d F:\rawrxd\build 2>nul || (
  echo CRITICAL: no build_ide/build dir
  exit /b 2
)
echo === building rawrxd_agentic_backend ===
ninja rawrxd_agentic_backend 2>&1
set EC=%ERRORLEVEL%
echo EXIT=%EC%
exit /b %EC%
