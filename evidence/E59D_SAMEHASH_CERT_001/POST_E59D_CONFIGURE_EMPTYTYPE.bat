@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64
if errorlevel 1 exit /b 1
cmake -S "F:\rawrxd\.worktrees\e59d_restore" -B "F:\rawrxd\build_post_e59d_candidate" -G Ninja "-DCMAKE_BUILD_TYPE=" -DRAWRXD_BUILD_WIN32IDE=ON -DRAWRXD_BUILD_WIN32IDE_QT=OFF -DRAWRXD_REQUIRE_QT=OFF -DRAWRXD_ENABLE_LTO=ON -DRAWRXD_ENABLE_HARDENING=ON -DENABLE_VULKAN=ON -DRAWRXD_BUILD_TESTS=OFF -DRAWRXD_BUILD_FUZZ=ON -DRAWRXD_BUILD_SECURITY_LIB=ON -DBUILD_SHARED_LIBS=OFF
echo CMAKE_EXIT=%ERRORLEVEL%
if errorlevel 1 exit /b %ERRORLEVEL%
findstr /C:"CMAKE_BUILD_TYPE" "F:\rawrxd\build_post_e59d_candidate\CMakeCache.txt"
cmake --build "F:\rawrxd\build_post_e59d_candidate" --target RawrXD-Win32IDE-Native --parallel 8
echo BUILD_EXIT=%ERRORLEVEL%
exit /b %ERRORLEVEL%
