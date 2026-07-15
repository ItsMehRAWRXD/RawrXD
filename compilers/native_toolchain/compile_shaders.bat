@echo off
REM compile_shaders.bat - Compile Vulkan compute shaders to SPIR-V

echo ============================================
echo Compiling Vulkan Compute Shaders
echo ============================================

set SHADER_DIR=src\gpu\vulkan\shaders
set GLSLC=glslc

if not exist %GLSLC%.exe (
    echo ERROR: glslc not found. Please install Vulkan SDK.
    exit /b 1
)

echo.
echo Compiling shaders...

%GLSLC% %SHADER_DIR%\rmsnorm.comp -o %SHADER_DIR%\rmsnorm.spv
if %ERRORLEVEL% neq 0 (
    echo FAILED: rmsnorm.comp
    exit /b 1
)
echo   rmsnorm.comp -> rmsnorm.spv

%GLSLC% %SHADER_DIR%\rope.comp -o %SHADER_DIR%\rope.spv
if %ERRORLEVEL% neq 0 (
    echo FAILED: rope.comp
    exit /b 1
)
echo   rope.comp -> rope.spv

%GLSLC% %SHADER_DIR%\attention.comp -o %SHADER_DIR%\attention.spv
if %ERRORLEVEL% neq 0 (
    echo FAILED: attention.comp
    exit /b 1
)
echo   attention.comp -> attention.spv

%GLSLC% %SHADER_DIR%\matmul.comp -o %SHADER_DIR%\matmul.spv
if %ERRORLEVEL% neq 0 (
    echo FAILED: matmul.comp
    exit /b 1
)
echo   matmul.comp -> matmul.spv

%GLSLC% %SHADER_DIR%\softmax.comp -o %SHADER_DIR%\softmax.spv
if %ERRORLEVEL% neq 0 (
    echo FAILED: softmax.comp
    exit /b 1
)
echo   softmax.comp -> softmax.spv

%GLSLC% %SHADER_DIR%\swiglu.comp -o %SHADER_DIR%\swiglu.spv
if %ERRORLEVEL% neq 0 (
    echo FAILED: swiglu.comp
    exit /b 1
)
echo   swiglu.comp -> swiglu.spv

echo.
echo ============================================
echo Shader compilation complete!
echo ============================================