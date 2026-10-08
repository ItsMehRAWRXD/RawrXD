@echo off
setlocal
set "ROOT=%~dp0..\.."
if not exist "%ROOT%\compile_ir_executor.bat" (
  echo BUILD_SCRIPT_MISSING=%ROOT%\compile_ir_executor.bat
  exit /b 2
)
if not defined VSCMD_VER (
  where cl >nul 2>nul
  if errorlevel 1 (
    set "VSDEV=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
    if not exist "%VSDEV%" (
      echo MSVC_NOT_FOUND=1
      exit /b 3
    )
    call "%VSDEV%" -arch=amd64
    if errorlevel 1 exit /b 4
  )
)
pushd "%ROOT%"
call "%ROOT%\compile_ir_executor.bat"
set "STATUS=%ERRORLEVEL%"
popd
exit /b %STATUS%
