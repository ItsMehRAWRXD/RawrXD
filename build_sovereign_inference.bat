@echo off
REM Sovereign Inference Engine Build Script
REM Builds complete inference pipeline with native toolchain only

echo ==========================================
echo  Sovereign Inference Engine Build
echo  Native Toolchain Only (No ML64/LINK)
echo ==========================================
echo.

set SRC_DIR=d:\rawrxd\src\asm
set SOVEREIGN_DIR=d:\rawrxd\src\sovereign
set OUT_DIR=d:\rawrxd\build-sovereign-native
set TOOLCHAIN=d:\rawrxd\compilers\native_toolchain

if not exist %OUT_DIR% mkdir %OUT_DIR%

echo [1/5] Assembling Sovereign Core Components...
echo.

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SOVEREIGN_DIR%\sovereign_main.asm" "%OUT_DIR%\sovereign_main.obj"
if errorlevel 1 goto :asm_error
echo   sovereign_main.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\sovereign_kernels.asm" "%OUT_DIR%\sovereign_kernels.obj"
if errorlevel 1 goto :asm_error
echo   sovereign_kernels.asm - OK

echo.
echo [2/5] Assembling Model Loader Components...
echo.

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\model_bridge_x64.asm" "%OUT_DIR%\model_bridge_x64.obj"
if errorlevel 1 goto :asm_error
echo   model_bridge_x64.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\mmap_loader.asm" "%OUT_DIR%\mmap_loader.obj"
if errorlevel 1 goto :asm_error
echo   mmap_loader.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\model_streamer_x64.asm" "%OUT_DIR%\model_streamer_x64.obj"
if errorlevel 1 goto :asm_error
echo   model_streamer_x64.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\Sovereign_Loader_MMAP.asm" "%OUT_DIR%\Sovereign_Loader_MMAP.obj"
if errorlevel 1 goto :asm_error
echo   Sovereign_Loader_MMAP.asm - OK

echo.
echo [3/5] Assembling GGUF Parser Components...
echo.

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\gguf_parser.asm" "%OUT_DIR%\gguf_parser.obj"
if errorlevel 1 goto :asm_error
echo   gguf_parser.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\gguf_weight_mapping.asm" "%OUT_DIR%\gguf_weight_mapping.obj"
if errorlevel 1 goto :asm_error
echo   gguf_weight_mapping.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\RawrXD_GGUF_GraphInterpreter.asm" "%OUT_DIR%\RawrXD_GGUF_GraphInterpreter.obj"
if errorlevel 1 goto :asm_error
echo   RawrXD_GGUF_GraphInterpreter.asm - OK

echo.
echo [4/5] Assembling Inference Kernel Components...
echo.

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\dequant_simd.asm" "%OUT_DIR%\dequant_simd.obj"
if errorlevel 1 goto :asm_error
echo   dequant_simd.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\FlashAttention_AVX512.asm" "%OUT_DIR%\FlashAttention_AVX512.obj"
if errorlevel 1 goto :asm_error
echo   FlashAttention_AVX512.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\RawrXD_Inference_AVX512.asm" "%OUT_DIR%\RawrXD_Inference_AVX512.obj"
if errorlevel 1 goto :asm_error
echo   RawrXD_Inference_AVX512.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\avx512_matmul.asm" "%OUT_DIR%\avx512_matmul.obj"
if errorlevel 1 goto :asm_error
echo   avx512_matmul.asm - OK

echo.
echo [5/5] Linking Sovereign Inference Engine...
echo.

"%TOOLCHAIN%\rawrxd_native_linker.exe" ^
    "%OUT_DIR%\sovereign_main.obj" ^
    "%OUT_DIR%\sovereign_kernels.obj" ^
    "%OUT_DIR%\model_bridge_x64.obj" ^
    "%OUT_DIR%\mmap_loader.obj" ^
    "%OUT_DIR%\model_streamer_x64.obj" ^
    "%OUT_DIR%\Sovereign_Loader_MMAP.obj" ^
    "%OUT_DIR%\gguf_parser.obj" ^
    "%OUT_DIR%\gguf_weight_mapping.obj" ^
    "%OUT_DIR%\RawrXD_GGUF_GraphInterpreter.obj" ^
    "%OUT_DIR%\dequant_simd.obj" ^
    "%OUT_DIR%\FlashAttention_AVX512.obj" ^
    "%OUT_DIR%\RawrXD_Inference_AVX512.obj" ^
    "%OUT_DIR%\avx512_matmul.obj" ^
    /out:"%OUT_DIR%\Sovereign_Inference_Engine.exe" ^
    /entry:main

if errorlevel 1 goto :link_error

echo.
echo ==========================================
echo  BUILD SUCCESSFUL
echo ==========================================
echo.
echo Output: %OUT_DIR%\Sovereign_Inference_Engine.exe
echo.
for %%I in ("%OUT_DIR%\Sovereign_Inference_Engine.exe") do (
    echo Size: %%~zI bytes
)
echo.
goto :end

:asm_error
echo.
echo ==========================================
echo  ASSEMBLY ERROR
echo ==========================================
echo.
exit /b 1

:link_error
echo.
echo ==========================================
echo  LINK ERROR
echo ==========================================
echo.
exit /b 1

:end
echo Done.
