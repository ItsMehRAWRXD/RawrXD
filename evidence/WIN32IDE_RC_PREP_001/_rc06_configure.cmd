@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 91
set SCRATCH=g:\~dev\rawrxd\evidence\WIN32IDE_RC_PREP_001\_rc06_cmake_scratch
if exist "%SCRATCH%" rmdir /s /q "%SCRATCH%"
mkdir "%SCRATCH%"
set LOG=g:\~dev\rawrxd\evidence\WIN32IDE_RC_PREP_001\_rc06_configure_log.txt
cmake -S "g:\~dev\rawrxd\src\agentic" -B "%SCRATCH%" -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF > "%LOG%" 2>&1
echo EXIT=%ERRORLEVEL%>> "%LOG%"
exit /b %ERRORLEVEL%
