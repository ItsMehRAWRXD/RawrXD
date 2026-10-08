@echo off
setlocal
where cl >nul 2>nul
if errorlevel 1 (
  if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64
  ) else (
    echo ERROR: cl.exe not in PATH and VS2022 BuildTools not located.
    exit /b 2
  )
)
cl /nologo /std:c++17 /EHsc /O2 /W4 /Fe:"%~dp0rawrxd_q6_lmhead_audit.exe" "%~dp0rawrxd_q6_lmhead_audit.cpp"
if errorlevel 1 exit /b 1
"%~dp0rawrxd_q6_lmhead_audit.exe" --selftest
exit /b %errorlevel%
