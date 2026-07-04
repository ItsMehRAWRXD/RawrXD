@echo off
REM RDNA3 Kernel Integration Script
REM Integrates RDNA3 kernels into the main RawrXD build

echo ========================================
echo  RDNA3 Kernel Integration
echo  Target: RX 7800 XT (gfx1101)
echo ========================================
echo.

set "SOURCE_OBJ=obj\RDNA3_AllInOne.obj"
set "DEST_DIR=..\..\..\build"
set "DEST_OBJ=RDNA3_Kernels.obj"

REM Check if source object exists
if not exist "%SOURCE_OBJ%" (
    echo [!] Source object not found: %SOURCE_OBJ%
    echo [!] Run build_simple.bat first
    exit /b 1
)

REM Check if destination directory exists
if not exist "%DEST_DIR%" (
    echo [!] Destination directory not found: %DEST_DIR%
    echo [!] Creating directory...
    mkdir "%DEST_DIR%"
)

echo [1/3] Copying RDNA3 kernel object to build directory...
copy /Y "%SOURCE_OBJ%" "%DEST_DIR%\%DEST_OBJ%"
if errorlevel 1 goto :error

echo [2/3] Verifying copy...
if not exist "%DEST_DIR%\%DEST_OBJ%" (
    echo [!] Copy verification failed
    exit /b 1
)

echo [3/3] Generating integration report...
echo RDNA3 Kernel Integration Report > "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo ======================================== >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo Date: %date% %time% >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo Source: %SOURCE_OBJ% >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo Destination: %DEST_DIR%\%DEST_OBJ% >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo Status: SUCCESS >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo ======================================== >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo. >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo Kernels Included: >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo   - Q4MatMul_RDNA3 >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo   - KVCacheAttention_RDNA3 >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo   - TileStreamer_RDNA3 >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo. >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo Hardware Target: RX 7800 XT (gfx1101) >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo Model Target: 120B Q4_K_M >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo. >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo Next Steps: >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo   1. Link RDNA3_Kernels.obj with main executable >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo   2. Implement GPU doorbell mapping >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"
echo   3. Test kernel dispatch on target hardware >> "%DEST_DIR%\RDNA3_INTEGRATION.txt"

echo.
echo ========================================
echo  INTEGRATION SUCCESSFUL
echo ========================================
echo.
echo Files copied:
echo   Source: %SOURCE_OBJ%
echo   Destination: %DEST_DIR%\%DEST_OBJ%
echo.
echo Integration report: %DEST_DIR%\RDNA3_INTEGRATION.txt
echo.
echo Next steps:
echo   1. Link RDNA3_Kernels.obj with main executable
echo   2. Implement GPU doorbell mapping
echo   3. Test kernel dispatch on target hardware
echo.
goto :end

:error
echo.
echo [!] INTEGRATION FAILED
echo.
exit /b 1

:end
