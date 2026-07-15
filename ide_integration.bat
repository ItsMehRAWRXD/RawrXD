@echo off
echo RawrXD IDE - GPU Backend Integration
echo   Initializing IDE...
echo   Loading Vulkan backend...
echo   Executing GPU backend...
echo.
vulkan_backend.exe
if %ERRORLEVEL% equ 0 (
    echo.
    echo IDE GPU Integration: SUCCESS
    exit /b 0
) else (
    echo.
    echo IDE GPU Integration: FAILED
    exit /b 1
)
