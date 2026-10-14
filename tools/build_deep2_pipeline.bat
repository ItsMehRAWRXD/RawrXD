@echo off
REM ============================================================================
REM build_deep2_pipeline.bat  --  RAWRXD_DEEP2_ONE_PIPELINE
REM ----------------------------------------------------------------------------
REM Builds ONE self-contained executable that loads a real GGUF and runs the
REM whole Deep2 pipeline without a separate server:
REM   universal ingest -> evidence verifier -> ElasticResidencyManager leasing
REM   -> flash-frozen versioned pages over the REAL tensor bytes -> runtime
REM   graph executor + quant dot dispatch (GPU where the kernel exists)
REM   -> concurrent KV COW -> freeze/validate/replay/restore -> durable pages
REM
REM The compiler command is deliberately on ONE physical line: a caret
REM continuation silently drops /std:c++20 with this CL (warning D9002).
REM ============================================================================
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if "%INCLUDE%"=="" ( echo ERROR: vcvarsall failed & exit /b 1 )

set VK_INC=C:\VulkanSDK\1.4.357.0\Include
set GGML_SRC=F:\rawrxd\3rdparty\ggml
set GGML_BUILD=F:\rawrxd\build_ggml_profiler
set OUT=%~dp0deep2_pipeline.exe
set SRC=F:\rawrxd\src
set T=%~dp0
set PATH=%GGML_BUILD%\bin\Release;%PATH%

if not exist "%GGML_BUILD%\src\Release\ggml.lib" (
    echo [1/2] building ggml...
    cmake -S %GGML_SRC% -B %GGML_BUILD% -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release -DGGML_BUILD_TESTS=OFF -DGGML_BUILD_EXAMPLES=OFF -DGGML_BUILD_BENCHMARKS=OFF -DGGML_NATIVE=ON >nul
    if errorlevel 1 ( echo GGML_CONFIGURE_FAILED & exit /b 1 )
    cmake --build %GGML_BUILD% --config Release --target ggml ggml-cpu ggml-base >nul
    if errorlevel 1 ( echo GGML_BUILD_FAILED & exit /b 1 )
) else ( echo [1/2] ggml already built )

echo [2/2] building deep2_pipeline.exe...
cl /nologo /std:c++20 /EHsc /O2 /W3 /permissive- /bigobj /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS /I %VK_INC% /I %GGML_SRC%\include /I %SRC% /I %SRC%\deep2 /I %SRC%\deep2\modelgenie /I %SRC%\deep2\lavapath /I %SRC%\deep2\vwa /I F:\rawrxd\include /I F:\rawrxd %T%deep2_pipeline.cpp %SRC%\deep2\runtime_graph_executor.cpp %SRC%\deep2\modelgenie\universal_gguf.cpp %SRC%\deep2\quant_dot_dispatch.cpp %SRC%\vulkan_compute.cpp %SRC%\deep2\ElasticResidencyManager.cpp %SRC%\deep2\GhostCache.cpp %SRC%\deep2\QuantKernelRegistry.cpp %SRC%\deep2\lavapath\FreeTokenMicroZone.cpp %SRC%\deep2\lavapath\FreeTokenFutureCompletion.cpp %SRC%\deep2\lavapath\FutureConsumerSpace.cpp %SRC%\deep2\VwaResolveBlocks.cpp %SRC%\deep2\asm_stubs.cpp /Fe%OUT% /link /LIBPATH:%VK_INC%\..\Lib vulkan-1.lib /LIBPATH:%GGML_BUILD%\src\Release ggml.lib ggml-cpu.lib ggml-base.lib /LIBPATH:%GGML_BUILD%\bin\Release 2>&1
if errorlevel 1 ( echo BUILD_FAILED & exit /b 1 )
echo Built: %OUT%
echo.
echo Usage: deep2_pipeline.exe --model ^<gguf^> [--prompt "text"] [--decode N]
echo                           [--pages N] [--budget-frac 0.5] [--evidence dir]
echo                           [--force-cpu] [--concurrent-gpu]
