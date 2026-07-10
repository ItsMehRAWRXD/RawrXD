@echo off
REM Build SPIR-V shaders for RawrXD Medusa GPU
REM Requires Vulkan SDK glslangValidator

echo Building SPIR-V shaders for RDNA3...

set GLSLANG=C:\VulkanSDK\1.3.275.0\Bin\glslangValidator.exe

if not exist "%GLSLANG%" (
    echo ERROR: glslangValidator not found at %GLSLANG%
    echo Please install Vulkan SDK or update path
    exit /b 1
)

set OUTDIR=..
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

echo.
echo Compiling matmul_fp16.comp...
"%GLSLANG%" -V --target-env vulkan1.2 -o "%OUTDIR%\matmul_fp16.spv" matmul_fp16.comp
if errorlevel 1 (
    echo FAILED: matmul_fp16.comp
    exit /b 1
)
echo OK: matmul_fp16.spv

echo.
echo Compiling rms_norm_fp16.comp...
"%GLSLANG%" -V --target-env vulkan1.2 -o "%OUTDIR%\rms_norm_fp16.spv" rms_norm_fp16.comp
if errorlevel 1 (
    echo FAILED: rms_norm_fp16.comp
    exit /b 1
)
echo OK: rms_norm_fp16.spv

echo.
echo Compiling softmax_fp16.comp...
"%GLSLANG%" -V --target-env vulkan1.2 -o "%OUTDIR%\softmax_fp16.spv" softmax_fp16.comp
if errorlevel 1 (
    echo FAILED: softmax_fp16.comp
    exit /b 1
)
echo OK: softmax_fp16.spv

echo.
echo Compiling verify_candidates.comp...
"%GLSLANG%" -V --target-env vulkan1.2 -o "%OUTDIR%\verify_candidates.spv" verify_candidates.comp
if errorlevel 1 (
    echo FAILED: verify_candidates.comp
    exit /b 1
)
echo OK: verify_candidates.spv

echo.
echo ========================================
echo All shaders compiled successfully!
echo Output: %OUTDIR%\*.spv
echo ========================================

REM Generate C++ header with embedded bytecode
echo Generating embedded shader header...
echo #pragma once > "%OUTDIR%\embedded_shaders.hpp"
echo // Auto-generated from SPIR-V shaders >> "%OUTDIR%\embedded_shaders.hpp"
echo. >> "%OUTDIR%\embedded_shaders.hpp"

for %%f in ("%OUTDIR%\*.spv") do (
    echo Embedding %%~nxf...
    echo // %%~nxf >> "%OUTDIR%\embedded_shaders.hpp"
    certutil -encodehex "%%f" "%%f.hex" 4
    echo static const uint32_t k%%~nf_spv[] = { >> "%OUTDIR%\embedded_shaders.hpp"
    
    REM Parse hex file and generate C++ array
    setlocal EnableDelayedExpansion
    set "line="
    for /f "delims=" %%a in (%%f.hex) do (
        set "hexline=%%a"
        REM Extract hex values and format as 0xXXXXXXXX
        for %%h in (!hexline!) do (
            if not "%%h"==" " (
                set "hexval=%%h"
                if not "!hexval!"==" " (
                    echo     0x!hexval!, >> "%OUTDIR%\embedded_shaders.hpp"
                )
            )
        )
    )
    endlocal
    
    echo }; >> "%OUTDIR%\embedded_shaders.hpp"
    echo. >> "%OUTDIR%\embedded_shaders.hpp"
    del "%%f.hex"
)

echo.
echo Generated: %OUTDIR%\embedded_shaders.hpp
