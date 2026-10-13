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

cl /nologo /std:c++20 /EHsc /O2 /W3 /permissive- /bigobj /openmp /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS /I %VK_INC% /I %GGML_SRC%\include /I %SRC% /I %SRC%\deep2 /I %SRC%\deep2\modelgenie /I F:\rawrxd\include /I F:\rawrxd %T%\deep2_bench_tps.cpp %SRC%\deep2\runtime_graph_executor.cpp %SRC%\deep2\modelgenie\universal_gguf.cpp %SRC%\deep2\quant_dot_dispatch.cpp %SRC%\vulkan_compute.cpp /Fe%OUT% /link /LIBPATH:%VK_INC%\..\Lib vulkan-1.lib psapi.lib /LIBPATH:%GGML_BUILD%\src\Release ggml.lib ggml-cpu.lib ggml-base.lib /LIBPATH:%GGML_BUILD%\bin\Release 2>&1
if errorlevel 1 ( echo BUILD_FAILED & exit /b 1 )
echo Built: %OUT%
echo.
echo Usage: deep2_bench_tps.exe --model ^<gguf^> --tokens "1 185" [--decode N] [--runs N] [--cpu]
