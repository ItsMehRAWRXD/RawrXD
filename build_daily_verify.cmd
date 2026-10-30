@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (
  echo vcvars64 failed
  exit /b 1
)

cd /d F:\rawrxd

set LOG=__build_daily_verify.log

echo ===== CONFIGURE ===== >> %LOG%
cmake -S . -B build_daily_verify -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_C_COMPILER=cl ^
  -DCMAKE_CXX_COMPILER=cl ^
  -DRAWRXD_BUILD_WIN32IDE=ON ^
  -DRAWRXD_REQUIRE_QT=OFF ^
  -DENABLE_VULKAN=ON ^
  -DUSE_ZLIB_FETCHCONTENT=OFF ^
  -DFETCHCONTENT_ZLIB=OFF ^
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON >> %LOG% 2>&1

if errorlevel 1 (
  echo CMAKE CONFIGURE FAILED >> %LOG%
  exit /b 1
)

echo ===== BUILD ===== >> %LOG%
cmake --build build_daily_verify --target RawrXD-Win32IDE-Native -j 8 >> %LOG% 2>&1
echo EXIT_CODE=%errorlevel% >> %LOG%
exit /b %errorlevel%
