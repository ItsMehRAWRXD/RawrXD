@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
  echo VCVARS_FAIL
  exit /b 1
)
echo === KILL IDE ===
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native.exe >nul 2>&1
echo === NATIVE_EXT ===
cd /d F:\rawrxd\build_tip_ext_host_001
echo NINJA_START=%DATE% %TIME%
ninja RawrXD-Win32IDE-Native-Ext
set NINJA_EC=%ERRORLEVEL%
echo NINJA_EXIT=%NINJA_EC%
echo NINJA_END=%DATE% %TIME%
if not "%NINJA_EC%"=="0" exit /b %NINJA_EC%
echo === STAGE tip_integ_candidate_001 ===
set TIPROOT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\package\tip_integ_candidate_001
copy /Y F:\rawrxd\build_tip_ext_host_001\bin\RawrXD-Win32IDE-Native-Ext.exe "%TIPROOT%\RawrXD-Win32IDE-Native-Ext.exe"
powershell -NoProfile -Command "$h=(Get-FileHash '%TIPROOT%\RawrXD-Win32IDE-Native-Ext.exe' -Algorithm SHA256).Hash; Set-Content -LiteralPath '%TIPROOT%\SHA256.txt' -Value $h; Write-Host ('NATIVE_SHA=' + $h)"
echo STAGE_DONE
exit /b 0
