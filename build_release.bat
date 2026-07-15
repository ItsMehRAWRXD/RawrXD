@echo off
REM Build RawrXD Model Loading Release Package
REM Version 1.0.0

echo ==========================================
echo RawrXD Model Loading - Release Build
echo Version 1.0.0
echo ==========================================
echo.

set VERSION=1.0.0
set BUILD_DIR=d:\rawrxd\build
set RELEASE_DIR=d:\rawrxd\release\RawrXD-v%VERSION%-Windows
set SOURCE_DIR=d:\rawrxd

echo Cleaning previous build...
if exist %RELEASE_DIR% rmdir /s /q %RELEASE_DIR%
mkdir %RELEASE_DIR%
mkdir %RELEASE_DIR%\bin
mkdir %RELEASE_DIR%\lib
mkdir %RELEASE_DIR%\include
mkdir %RELEASE_DIR%\docs
mkdir %RELEASE_DIR%\examples
mkdir %RELEASE_DIR%\tests

echo.
echo Building test executables...
echo.

REM Build all test executables
cd %SOURCE_DIR%

echo [1/4] Building test_model_basic.exe...
g++.exe -std=c++17 -O2 -Wall -o %BUILD_DIR%\test_model_basic.exe tests\test_model_basic.cpp
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: test_model_basic.exe
    exit /b 1
)
echo SUCCESS: test_model_basic.exe

echo [2/4] Building test_gpu_detection.exe...
g++.exe -std=c++17 -O2 -Wall -o %BUILD_DIR%\test_gpu_detection.exe tests\test_gpu_detection.cpp -ldxgi -ld3d12
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: test_gpu_detection.exe
    exit /b 1
)
echo SUCCESS: test_gpu_detection.exe

echo [3/4] Building test_gpu_upload_d3d12.exe...
g++.exe -std=c++17 -O2 -Wall -o %BUILD_DIR%\test_gpu_upload_d3d12.exe tests\test_gpu_upload_d3d12.cpp -ldxgi -ld3d12
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: test_gpu_upload_d3d12.exe
    exit /b 1
)
echo SUCCESS: test_gpu_upload_d3d12.exe

echo [4/4] Building test_integration_pipeline.exe...
g++.exe -std=c++17 -O2 -Wall -o %BUILD_DIR%\test_integration_pipeline.exe tests\test_integration_pipeline.cpp -ldxgi -ld3d12
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: test_integration_pipeline.exe
    exit /b 1
)
echo SUCCESS: test_integration_pipeline.exe

echo.
echo Copying files to release directory...
echo.

REM Copy executables
copy %BUILD_DIR%\test_model_basic.exe %RELEASE_DIR%\bin\
copy %BUILD_DIR%\test_gpu_detection.exe %RELEASE_DIR%\bin\
copy %BUILD_DIR%\test_gpu_upload_d3d12.exe %RELEASE_DIR%\bin\
copy %BUILD_DIR%\test_integration_pipeline.exe %RELEASE_DIR%\bin\

REM Copy headers
xcopy %SOURCE_DIR%\include\*.hpp %RELEASE_DIR%\include\ /s /e /y

REM Copy documentation
copy %SOURCE_DIR%\docs\API_REFERENCE.md %RELEASE_DIR%\docs\
copy %SOURCE_DIR%\docs\USAGE_GUIDE.md %RELEASE_DIR%\docs\
copy %SOURCE_DIR%\FINAL_STATUS_REPORT.md %RELEASE_DIR%\docs\

REM Copy examples
copy %SOURCE_DIR%\examples\*.cpp %RELEASE_DIR%\examples\

REM Copy tests
copy %SOURCE_DIR%\tests\*.cpp %RELEASE_DIR%\tests\

REM Create README
echo # RawrXD Model Loading v%VERSION% > %RELEASE_DIR%\README.md
echo. >> %RELEASE_DIR%\README.md
echo ## Quick Start >> %RELEASE_DIR%\README.md
echo. >> %RELEASE_DIR%\README.md
echo ```powershell >> %RELEASE_DIR%\README.md
echo # Test with your model >> %RELEASE_DIR%\README.md
echo .\bin\test_integration_pipeline.exe "path\to\model.gguf" >> %RELEASE_DIR%\README.md
echo ``` >> %RELEASE_DIR%\README.md
echo. >> %RELEASE_DIR%\README.md
echo ## Documentation >> %RELEASE_DIR%\README.md
echo - docs\API_REFERENCE.md - API documentation >> %RELEASE_DIR%\README.md
echo - docs\USAGE_GUIDE.md - Usage guide >> %RELEASE_DIR%\README.md
echo. >> %RELEASE_DIR%\README.md
echo ## Tests >> %RELEASE_DIR%\README.md
echo - bin\test_model_basic.exe - Basic model validation >> %RELEASE_DIR%\README.md
echo - bin\test_gpu_detection.exe - GPU detection >> %RELEASE_DIR%\README.md
echo - bin\test_gpu_upload_d3d12.exe - GPU upload test >> %RELEASE_DIR%\README.md
echo - bin\test_integration_pipeline.exe - Full pipeline test >> %RELEASE_DIR%\README.md
echo. >> %RELEASE_DIR%\README.md
echo ## Version >> %RELEASE_DIR%\README.md
echo Version: %VERSION% >> %RELEASE_DIR%\README.md
echo Date: 2026-07-14 >> %RELEASE_DIR%\README.md
echo Status: Production Ready >> %RELEASE_DIR%\README.md

echo.
echo ==========================================
echo Build Complete!
echo ==========================================
echo.
echo Release package created at:
echo   %RELEASE_DIR%
echo.
echo Contents:
dir /s /b %RELEASE_DIR% | findstr /v ".git"
echo.
echo To create ZIP archive:
echo   powershell Compress-Archive -Path '%RELEASE_DIR%' -DestinationPath 'RawrXD-v%VERSION%-Windows.zip'
echo.
echo Done!
