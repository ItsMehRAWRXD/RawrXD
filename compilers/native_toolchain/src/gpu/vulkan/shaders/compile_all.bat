@echo off
set GLSLC=C:\VulkanSDK\1.4.328.1\Bin\glslc.exe
set SHADER_DIR=%~dp0

echo Compiling GLSL shaders to SPIR-V...
echo.

"%GLSLC%" "%SHADER_DIR%rmsnorm.comp" -o "%SHADER_DIR%rmsnorm.spv"
if errorlevel 1 goto error

echo [OK] rmsnorm.comp -> rmsnorm.spv

"%GLSLC%" "%SHADER_DIR%rope.comp" -o "%SHADER_DIR%rope.spv"
if errorlevel 1 goto error

echo [OK] rope.comp -> rope.spv

"%GLSLC%" "%SHADER_DIR%attention.comp" -o "%SHADER_DIR%attention.spv"
if errorlevel 1 goto error

echo [OK] attention.comp -> attention.spv

"%GLSLC%" "%SHADER_DIR%matmul.comp" -o "%SHADER_DIR%matmul.spv"
if errorlevel 1 goto error

echo [OK] matmul.comp -> matmul.spv

"%GLSLC%" "%SHADER_DIR%softmax.comp" -o "%SHADER_DIR%softmax.spv"
if errorlevel 1 goto error

echo [OK] softmax.comp -> softmax.spv

"%GLSLC%" "%SHADER_DIR%swiglu.comp" -o "%SHADER_DIR%swiglu.spv"
if errorlevel 1 goto error

echo [OK] swiglu.comp -> swiglu.spv

echo.
echo ============================================
echo All shaders compiled successfully!
echo ============================================
goto end

:error
echo.
echo ERROR: Shader compilation failed!
exit /b 1

:end