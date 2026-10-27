@echo off
REM ============================================================================
REM build_deep2_bench_tps.bat  --  RAWRXD_GATE7_TPS_001
REM ============================================================================
REM Builds the trace-free production benchmark (prefill/decode TPS).
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if "%INCLUDE%"=="" ( echo ERROR: vcvarsall failed & exit /b 1 )

set VK_INC=C:\VulkanSDK\1.4.357.0\Include
set GGML_SRC=F:\rawrxd\3rdparty\ggml
set GGML_BUILD=F:\rawrxd\build_ggml_profiler
set OUT=F:\rawrxd\tools\deep2_bench_tps.exe
set SRC=F:\rawrxd\src
set T=F:\rawrxd\tools
set PATH=%GGML_BUILD%\bin\Release;%PATH%

if not exist "%GGML_BUILD%\src\Release\ggml.lib" (
    cmake -S %GGML_SRC% -B %GGML_BUILD% -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release -DGGML_BUILD_TESTS=OFF -DGGML_BUILD_EXAMPLES=OFF -DGGML_BUILD_BENCHMARKS=OFF -DGGML_NATIVE=ON >nul
    if errorlevel 1 ( echo GGML_CONFIGURE_FAILED & exit /b 1 )
    cmake --build %GGML_BUILD% --config Release --target ggml ggml-cpu ggml-base >nul
    if errorlevel 1 ( echo GGML_BUILD_FAILED & exit /b 1 )
)

REM The benchmark uses two different source files named vulkan_compute.cpp.
REM Build through CMake so their object paths remain distinct and match the
REM canonical parity target instead of relying on a basename-colliding cl line.
cmake -S F:\rawrxd -B F:\rawrxd\build_reap -G Ninja >nul
if errorlevel 1 ( echo CMAKE_CONFIGURE_FAILED & exit /b 1 )
cmake --build F:\rawrxd\build_reap --config Release --target deep2_bench_tps --parallel 8
if errorlevel 1 ( echo BUILD_FAILED & exit /b 1 )
copy /Y F:\rawrxd\build_reap\bin\deep2_bench_tps.exe %OUT% >nul
if errorlevel 1 ( echo COPY_FAILED & exit /b 1 )
echo Built: %OUT% (CMake target deep2_bench_tps)
echo.
echo Usage: deep2_bench_tps.exe --model ^<gguf^> --tokens "1 185" [--decode N] [--runs N] [--cpu]
