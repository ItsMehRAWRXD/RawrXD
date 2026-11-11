@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d F:\rawrxd
rmdir /s /q build_qt_free 2>nul
mkdir build_qt_free
cd build_qt_free
cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release 2>&1
echo CMAKE_EXIT_CODE=%ERRORLEVEL%