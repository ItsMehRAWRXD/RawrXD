@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 91
set ROOT=g:\~dev\rawrxd
set BASE=%ROOT%\evidence\WIN32IDE_RC_PREP_001
set LOG=%BASE%\_rc05_configure_log.txt
echo === RC05 scratch configure > "%LOG%"

set S1=%BASE%\_rc05_cmake_scratch_modelloader
if exist "%S1%" rmdir /s /q "%S1%"
mkdir "%S1%"
echo --- ModelLoader --- >> "%LOG%"
cmake -S "%ROOT%\RawrXD-ModelLoader" -B "%S1%" -G Ninja -DCMAKE_BUILD_TYPE=Release -DENABLE_VULKAN=OFF >> "%LOG%" 2>&1
set E1=%ERRORLEVEL%
echo MODELLOADER_EXIT=%E1%>> "%LOG%"

set S2=%BASE%\_rc05_cmake_scratch_ship
if exist "%S2%" rmdir /s /q "%S2%"
mkdir "%S2%"
echo. >> "%LOG%"
echo --- Ship --- >> "%LOG%"
cmake -S "%ROOT%\Ship" -B "%S2%" -G Ninja -DCMAKE_BUILD_TYPE=Release >> "%LOG%" 2>&1
set E2=%ERRORLEVEL%
echo SHIP_EXIT=%E2%>> "%LOG%"

set S3=%BASE%\_rc05_cmake_scratch_digestion
if exist "%S3%" rmdir /s /q "%S3%"
mkdir "%S3%"
echo. >> "%LOG%"
echo --- digestion --- >> "%LOG%"
cmake -S "%ROOT%\src\digestion" -B "%S3%" -G Ninja -DCMAKE_BUILD_TYPE=Release >> "%LOG%" 2>&1
set E3=%ERRORLEVEL%
echo DIGESTION_EXIT=%E3%>> "%LOG%"

set S4=%BASE%\_rc05_cmake_scratch_thermal
if exist "%S4%" rmdir /s /q "%S4%"
mkdir "%S4%"
echo. >> "%LOG%"
echo --- thermal --- >> "%LOG%"
cmake -S "%ROOT%\src\thermal" -B "%S4%" -G Ninja -DCMAKE_BUILD_TYPE=Release >> "%LOG%" 2>&1
set E4=%ERRORLEVEL%
echo THERMAL_EXIT=%E4%>> "%LOG%"

echo. >> "%LOG%"
echo SUMMARY E1=%E1% E2=%E2% E3=%E3% E4=%E4%>> "%LOG%"
if not "%E1%"=="0" exit /b %E1%
if not "%E2%"=="0" exit /b %E2%
if not "%E3%"=="0" exit /b %E3%
if not "%E4%"=="0" exit /b %E4%
exit /b 0
