@echo off
REM Build script for MASM x64 Vulkan implementation
REM Requires Visual Studio 2019 or later with MASM tools

echo ========================================
echo MASM x64 Vulkan Build Script
echo ========================================
echo.

REM Check for Visual Studio environment
where ml64.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: ml64.exe not found!
    echo Please run this script from a Visual Studio x64 Native Tools Command Prompt
    echo or run vcvarsall.bat x64 first
    exit /b 1
)

echo [1/4] Setting up directories...
if not exist obj mkdir obj
if not exist lib mkdir lib
if not exist bin mkdir bin
echo Done.
echo.

echo [2/4] Compiling Vulkan core...
ml64 /c /Cp /Cx /Zi /W3 /nologo /I"include" /Fo"obj\" vulkan\core\vk_instance.asm
if %ERRORLEVEL% NEQ 0 goto :error
ml64 /c /Cp /Cx /Zi /W3 /nologo /I"include" /Fo"obj\" vulkan\core\vk_command.asm
if %ERRORLEVEL% NEQ 0 goto :error
ml64 /c /Cp /Cx /Zi /W3 /nologo /I"include" /Fo"obj\" vulkan\memory\vk_memory.asm
if %ERRORLEVEL% NEQ 0 goto :error
ml64 /c /Cp /Cx /Zi /W3 /nologo /I"include" /Fo"obj\" vulkan\sync\vk_sync.asm
if %ERRORLEVEL% NEQ 0 goto :error
echo Done.
echo.

echo [3/4] Compiling compute operations...
ml64 /c /Cp /Cx /Zi /W3 /nologo /I"include" /Fo"obj\" vulkan\compute\tensor_ops.asm
if %ERRORLEVEL% NEQ 0 goto :error
ml64 /c /Cp /Cx /Zi /W3 /nologo /I"include" /Fo"obj\" vulkan\compute\matrix_ops.asm
if %ERRORLEVEL% NEQ 0 goto :error
ml64 /c /Cp /Cx /Zi /W3 /nologo /I"include" /Fo"obj\" vulkan\compute\activation_funcs.asm
if %ERRORLEVEL% NEQ 0 goto :error
echo Done.
echo.

echo [4/4] Compiling dependencies...
ml64 /c /Cp /Cx /Zi /W3 /nologo /I"include" /Fo"obj\" compression\zlib.asm
if %ERRORLEVEL% NEQ 0 goto :error
ml64 /c /Cp /Cx /Zi /W3 /nologo /I"include" /Fo"obj\" compression\zstd.asm
if %ERRORLEVEL% NEQ 0 goto :error
ml64 /c /Cp /Cx /Zi /W3 /nologo /I"include" /Fo"obj\" crypto\openssl.asm
if %ERRORLEVEL% NEQ 0 goto :error
ml64 /c /Cp /Cx /Zi /W3 /nologo /I"include" /Fo"obj\" cuda\cuda_runtime.asm
if %ERRORLEVEL% NEQ 0 goto :error
ml64 /c /Cp /Cx /Zi /W3 /nologo /I"include" /Fo"obj\" rocm\hip_runtime.asm
if %ERRORLEVEL% NEQ 0 goto :error
echo Done.
echo.

echo [5/5] Creating libraries...
lib /MACHINE:X64 /nologo /OUT:"lib\vulkan_masm.lib" obj\vk_instance.obj obj\vk_command.obj obj\vk_memory.obj obj\vk_sync.obj obj\tensor_ops.obj obj\matrix_ops.obj obj\activation_funcs.obj
if %ERRORLEVEL% NEQ 0 goto :error

lib /MACHINE:X64 /nologo /OUT:"lib\compression_masm.lib" obj\zlib.obj obj\zstd.obj
if %ERRORLEVEL% NEQ 0 goto :error

lib /MACHINE:X64 /nologo /OUT:"lib\crypto_masm.lib" obj\openssl.obj
if %ERRORLEVEL% NEQ 0 goto :error

lib /MACHINE:X64 /nologo /OUT:"lib\gpu_masm.lib" obj\cuda_runtime.obj obj\hip_runtime.obj
if %ERRORLEVEL% NEQ 0 goto :error
echo Done.
echo.

echo ========================================
echo Build completed successfully!
echo ========================================
echo.
echo Libraries created:
echo   - lib\vulkan_masm.lib
echo   - lib\compression_masm.lib
echo   - lib\crypto_masm.lib
echo   - lib\gpu_masm.lib
echo.
goto :end

:error
echo.
echo ========================================
echo Build FAILED!
echo ========================================
exit /b 1

:end
