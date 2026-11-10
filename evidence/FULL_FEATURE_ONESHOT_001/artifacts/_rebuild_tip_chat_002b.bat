@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d F:\rawrxd
echo RECONFIG_START
cmake -S F:\rawrxd -B F:\rawrxd\build_tip_chat_ctrl_enter_002 -G Ninja -DCMAKE_BUILD_TYPE=Release -DRAWRXD_NATIVE_IDE_EXT=ON -DRAWRXD_BUILD_WIN32IDE=ON
echo CMAKE_RC=%ERRORLEVEL%
if errorlevel 1 exit /b 92
findstr /C:"Win32NativeDebugBackend.cpp" F:\rawrxd\build_tip_chat_ctrl_enter_002\build.ninja >nul
if errorlevel 1 (
  echo NATIVE_DEBUG_NOT_IN_NINJA
  exit /b 93
) else (
  echo NATIVE_DEBUG_IN_NINJA=1
)
echo NINJA_BUILD_START
cmake --build F:\rawrxd\build_tip_chat_ctrl_enter_002 --target RawrXD-Win32IDE-Native-Ext -j 8
echo NINJA_RC=%ERRORLEVEL%
exit /b %ERRORLEVEL%
