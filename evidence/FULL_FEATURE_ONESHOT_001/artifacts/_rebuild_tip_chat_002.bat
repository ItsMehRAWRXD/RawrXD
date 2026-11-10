@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (
  echo VCVARS_FAIL
  exit /b 91
)
echo VCVARS_OK
cd /d F:\rawrxd
if not exist F:\rawrxd\build_tip_chat_ctrl_enter_002\build.ninja (
  echo CMAKE_CONFIG_START
  cmake -S F:\rawrxd -B F:\rawrxd\build_tip_chat_ctrl_enter_002 -G Ninja -DCMAKE_BUILD_TYPE=Release -DRAWRXD_NATIVE_IDE_EXT=ON
  echo CMAKE_CONFIG_RC=%ERRORLEVEL%
  if errorlevel 1 exit /b 92
) else (
  echo CMAKE_ALREADY_CONFIGURED
)
echo NINJA_BUILD_START
cmake --build F:\rawrxd\build_tip_chat_ctrl_enter_002 --target RawrXD-Win32IDE-Native-Ext -j 8
echo NINJA_RC=%ERRORLEVEL%
exit /b %ERRORLEVEL%
