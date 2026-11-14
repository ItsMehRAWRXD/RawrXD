@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd
echo HEAD_AT_BUILD=3d0928e748885a20968d9f3283c7faf720ec8c05
cmake --build build_ninja --target rawr --config Release
echo BUILD_EXIT=%ERRORLEVEL%
if exist build_ninja\bin\rawr.exe (
  powershell -NoProfile -Command "(Get-FileHash build_ninja\bin\rawr.exe -Algorithm SHA256).Hash"
)
