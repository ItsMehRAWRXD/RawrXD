@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 91
cd /d F:\rawrxd
set BUILD_DIR=F:\rawrxd\build_deep2_openai_001
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
echo CONFIGURE_BEGIN
cmake -S F:\rawrxd -B "%BUILD_DIR%" -G Ninja -DCMAKE_BUILD_TYPE=Release -DRAWRXD_BUILD_DEEP2_ENGINE=ON -DRAWRXD_BUILD_WIN32IDE=OFF -DRAWRXD_BUILD_WIN32IDE_QT=OFF -DRAWRXD_NATIVE_IDE_EXT=OFF -DRAWRXD_BUILD_BENCHMARKS=OFF -DRAWRXD_BUILD_TESTS=OFF
set CFG_EC=%ERRORLEVEL%
echo CONFIGURE_EC=%CFG_EC%
if %CFG_EC% NEQ 0 exit /b %CFG_EC%
echo BUILD_TEST_API_BEGIN
cmake --build "%BUILD_DIR%" --target test_api_server --parallel 8
set T_EC=%ERRORLEVEL%
echo BUILD_TEST_API_EC=%T_EC%
echo BUILD_OPENAI_BEGIN
cmake --build "%BUILD_DIR%" --target deep2_openai_server --parallel 8
set O_EC=%ERRORLEVEL%
echo BUILD_OPENAI_EC=%O_EC%
if %T_EC% NEQ 0 exit /b %T_EC%
exit /b %O_EC%
