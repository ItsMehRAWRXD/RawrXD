@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "F:\rawrxd\.worktrees\product_seal_clean_a5ae60ef_build"
echo GENERATOR=Ninja
where cmake
where ninja
cmake --version
ninja --version
cl 2>&1 | findstr /i "Version"
echo ---
cmake -S "F:\rawrxd\.worktrees\product_seal_clean_a5ae60ef" -B "F:\rawrxd\.worktrees\product_seal_clean_a5ae60ef_build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DRAWRXD_BUILD_WIN32IDE=ON -DRAWRXD_BUILD_WIN32IDE_QT=OFF -DRAWRXD_BUILD_TESTS=OFF -DRAWRXD_BUILD_BENCHMARKS=OFF
if errorlevel 1 exit /b 1
echo CONFIGURE_OK
cmake --build "F:\rawrxd\.worktrees\product_seal_clean_a5ae60ef_build" --target RawrXD-Win32IDE-Native --config Release -j %NUMBER_OF_PROCESSORS%
set RC=%ERRORLEVEL%
echo BUILD_EXIT=%RC%
exit /b %RC%
