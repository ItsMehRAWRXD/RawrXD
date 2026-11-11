@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64
if errorlevel 1 (
  echo VSDEVCMD_FAIL=%ERRORLEVEL%
  exit /b 1
)
echo VSDEVCMD_OK
where cmake
where ninja
where cl
cmake -S "F:\rawrxd\.worktrees\e59d_restore" -B "F:\rawrxd\build_post_e59d_candidate" -G Ninja -DCMAKE_BUILD_TYPE=Release -DRAWRXD_BUILD_WIN32IDE=ON -DRAWRXD_BUILD_WIN32IDE_QT=OFF -DRAWRXD_REQUIRE_QT=OFF -DRAWRXD_ENABLE_LTO=ON -DRAWRXD_ENABLE_HARDENING=ON -DENABLE_VULKAN=ON -DRAWRXD_BUILD_TESTS=OFF -DRAWRXD_BUILD_FUZZ=ON -DRAWRXD_BUILD_SECURITY_LIB=ON -DBUILD_SHARED_LIBS=OFF
echo CMAKE_EXIT=%ERRORLEVEL%
exit /b %ERRORLEVEL%
