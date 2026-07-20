@echo off
REM Build script for Tree Attention Benchmark Suite
REM VAL-032: Reproducible Performance Validation

echo Building RawrXD Tree Attention Benchmark Suite...
echo.

REM Create build directory
if not exist build mkdir build
cd build

REM Configure with CMake
echo Configuring...
cmake .. -DCMAKE_BUILD_TYPE=Release -DRAWRXD_BUILD_BENCHMARKS=ON
if errorlevel 1 goto error

REM Build
echo Building...
cmake --build . --config Release --target benchmark_tree_attention -j%NUMBER_OF_PROCESSORS%
if errorlevel 1 goto error

echo.
echo Build successful!
echo.
echo To run the benchmark:
echo   .\Release\benchmark_tree_attention.exe --iterations 10000 --output results.json
echo.
goto end

:error
echo.
echo Build failed!
exit /b 1

:end
cd ..
