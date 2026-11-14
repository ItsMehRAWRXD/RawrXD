@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd
git rev-parse HEAD
cmake --build build_ninja --target rawr --config Release
set EC=%ERRORLEVEL%
echo BUILD_EXIT=%EC%
if exist build_ninja\bin\rawr.exe (
  powershell -NoProfile -Command "(Get-FileHash build_ninja\bin\rawr.exe -Algorithm SHA256).Hash"
)
exit /b %EC%
