@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 ( echo VCVARS_FAIL & exit /b 1 )
if "%1"=="configure" (
  cmake -G Ninja -S "%~dp0b15_fixture" -B "%~dp0b15_build" -DCMAKE_BUILD_TYPE=Debug
  exit /b %errorlevel%
)
if "%1"=="build" (
  cmake --build "%~dp0b15_build"
  exit /b %errorlevel%
)
if "%1"=="test" (
  ctest --test-dir "%~dp0b15_build" --output-on-failure
  exit /b %errorlevel%
)
cmake -G Ninja -S "%~dp0b15_fixture" -B "%~dp0b15_build" -DCMAKE_BUILD_TYPE=Debug
if errorlevel 1 exit /b 1
cmake --build "%~dp0b15_build"
exit /b %errorlevel%
