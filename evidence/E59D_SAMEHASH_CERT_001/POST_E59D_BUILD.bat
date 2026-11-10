@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64
if errorlevel 1 (
  echo VSDEVCMD_FAIL=%ERRORLEVEL%
  exit /b 1
)
cmake --build "F:\rawrxd\build_post_e59d_candidate" --target RawrXD-Win32IDE-Native --parallel 8
echo BUILD_EXIT=%ERRORLEVEL%
exit /b %ERRORLEVEL%
