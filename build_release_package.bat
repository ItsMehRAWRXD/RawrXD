@echo off
REM RawrXD Model Loading - Build Release Package
REM This script builds the release binaries and creates a distribution package

echo ==========================================
echo RawrXD Model Loading - Release Build
echo ==========================================
echo.

set BUILD_DIR=d:\rawrxd\build
set RELEASE_DIR=d:\rawrxd\release\RawrXD-ModelLoading-v1.0.0
set DOCS_DIR=%RELEASE_DIR%\docs
set TESTS_DIR=%RELEASE_DIR%\tests
set EXAMPLES_DIR=%RELEASE_DIR%\examples

REM Create directory structure
echo Creating release directory structure...
if exist %RELEASE_DIR% rmdir /s /q %RELEASE_DIR%
mkdir %RELEASE_DIR%
mkdir %RELEASE_DIR%\bin
mkdir %DOCS_DIR%
mkdir %TESTS_DIR%
mkdir %EXAMPLES_DIR%

REM Build test executables
echo.
echo Building test executables...

g++.exe -std=c++17 -O2 -Wall -o %RELEASE_DIR%\bin\test_model_basic.exe d:\rawrxd\tests\test_model_basic.cpp
g++.exe -std=c++17 -O2 -Wall -o %RELEASE_DIR%\bin\test_gpu_detection.exe d:\rawrxd\tests\test_gpu_detection.cpp -ldxgi -ld3d12
g++.exe -std=c++17 -O2 -Wall -o %RELEASE_DIR%\bin\test_gpu_upload_d3d12.exe d:\rawrxd\tests\test_gpu_upload_d3d12.cpp -ldxgi -ld3d12
g++.exe -std=c++17 -O2 -Wall -o %RELEASE_DIR%\bin\test_integration_pipeline.exe d:\rawrxd\tests\test_integration_pipeline.cpp -ldxgi -ld3d12

echo.
echo Copying documentation...
copy d:\rawrxd\FINAL_STATUS_REPORT.md %DOCS_DIR%\README.md
copy d:\rawrxd\GPU_INTEGRATION_COMPLETE.md %DOCS_DIR%\GPU_INTEGRATION.md
copy d:\rawrxd\PHASE4_INTEGRATION_COMPLETE.md %DOCS_DIR%\INTEGRATION_TESTING.md

REM Copy test source files
echo.
echo Copying test source files...
copy d:\rawrxd\tests\test_model_basic.cpp %TESTS_DIR%\test_model_basic.cpp
copy d:\rawrxd\tests\test_gpu_detection.cpp %TESTS_DIR%\test_gpu_detection.cpp
copy d:\rawrxd\tests\test_gpu_upload_d3d12.cpp %TESTS_DIR%\test_gpu_upload_d3d12.cpp
copy d:\rawrxd\tests\test_integration_pipeline.cpp %TESTS_DIR%\test_integration_pipeline.cpp

REM Create example usage file
echo.
echo Creating example usage file...
echo /* Example: Loading a GGUF model and uploading to GPU */ > %EXAMPLES_DIR%\example_basic.cpp
echo #include <stdio.h> >> %EXAMPLES_DIR%\example_basic.cpp
echo. >> %EXAMPLES_DIR%\example_basic.cpp
echo int main() { >> %EXAMPLES_DIR%\example_basic.cpp
echo     printf("RawrXD Model Loading Example\n"); >> %EXAMPLES_DIR%\example_basic.cpp
echo     printf("============================\n"); >> %EXAMPLES_DIR%\example_basic.cpp
echo     printf("1. Load GGUF file: test_model_basic.exe model.gguf\n"); >> %EXAMPLES_DIR%\example_basic.cpp
echo     printf("2. Check GPU: test_gpu_detection.exe\n"); >> %EXAMPLES_DIR%\example_basic.cpp
echo     printf("3. Test upload: test_gpu_upload_d3d12.exe\n"); >> %EXAMPLES_DIR%\example_basic.cpp
echo     printf("4. Full pipeline: test_integration_pipeline.exe model.gguf\n"); >> %EXAMPLES_DIR%\example_basic.cpp
echo     return 0; >> %EXAMPLES_DIR%\example_basic.cpp
echo } >> %EXAMPLES_DIR%\example_basic.cpp

REM Create build script
echo.
echo Creating build script...
echo @echo off > %RELEASE_DIR%\build_tests.bat
echo REM Build all test executables >> %RELEASE_DIR%\build_tests.bat
echo. >> %RELEASE_DIR%\build_tests.bat
echo g++.exe -std=c++17 -O2 -Wall -o bin\test_model_basic.exe tests\test_model_basic.cpp >> %RELEASE_DIR%\build_tests.bat
echo g++.exe -std=c++17 -O2 -Wall -o bin\test_gpu_detection.exe tests\test_gpu_detection.cpp -ldxgi -ld3d12 >> %RELEASE_DIR%\build_tests.bat
echo g++.exe -std=c++17 -O2 -Wall -o bin\test_gpu_upload_d3d12.exe tests\test_gpu_upload_d3d12.cpp -ldxgi -ld3d12 >> %RELEASE_DIR%\build_tests.bat
echo g++.exe -std=c++17 -O2 -Wall -o bin\test_integration_pipeline.exe tests\test_integration_pipeline.cpp -ldxgi -ld3d12 >> %RELEASE_DIR%\build_tests.bat
echo. >> %RELEASE_DIR%\build_tests.bat
echo echo Build complete! >> %RELEASE_DIR%\build_tests.bat

REM Create README
echo.
echo Creating package README...
echo # RawrXD Model Loading v1.0.0 > %RELEASE_DIR%\README.txt
echo. >> %RELEASE_DIR%\README.txt
echo ## Quick Start >> %RELEASE_DIR%\README.txt
echo. >> %RELEASE_DIR%\README.txt
echo 1. Test with a model: >> %RELEASE_DIR%\README.txt
echo    bin\test_model_basic.exe path\to\model.gguf >> %RELEASE_DIR%\README.txt
echo. >> %RELEASE_DIR%\README.txt
echo 2. Check GPU support: >> %RELEASE_DIR%\README.txt
echo    bin\test_gpu_detection.exe >> %RELEASE_DIR%\README.txt
echo. >> %RELEASE_DIR%\README.txt
echo 3. Test GPU upload: >> %RELEASE_DIR%\README.txt
echo    bin\test_gpu_upload_d3d12.exe >> %RELEASE_DIR%\README.txt
echo. >> %RELEASE_DIR%\README.txt
echo 4. Full pipeline test: >> %RELEASE_DIR%\README.txt
echo    bin\test_integration_pipeline.exe path\to\model.gguf >> %RELEASE_DIR%\README.txt
echo. >> %RELEASE_DIR%\README.txt
echo ## Documentation >> %RELEASE_DIR%\README.txt
echo - docs\README.md - Final status report >> %RELEASE_DIR%\README.txt
echo - docs\GPU_INTEGRATION.md - GPU integration details >> %RELEASE_DIR%\README.txt
echo - docs\INTEGRATION_TESTING.md - Integration testing results >> %RELEASE_DIR%\README.txt
echo. >> %RELEASE_DIR%\README.txt
echo ## Building from Source >> %RELEASE_DIR%\README.txt
echo Run build_tests.bat to rebuild all test executables. >> %RELEASE_DIR%\README.txt
echo Requires: GCC or MinGW with C++17 support >> %RELEASE_DIR%\README.txt
echo. >> %RELEASE_DIR%\README.txt
echo ## System Requirements >> %RELEASE_DIR%\README.txt
echo - Windows 10/11 (for DirectX 12 support) >> %RELEASE_DIR%\README.txt
echo - GPU with DirectX 12 or Vulkan support >> %RELEASE_DIR%\README.txt
echo - GGUF format model files >> %RELEASE_DIR%\README.txt
echo. >> %RELEASE_DIR%\README.txt
echo ## Performance >> %RELEASE_DIR%\README.txt
echo - GPU Upload: Up to 12.91 GB/s >> %RELEASE_DIR%\README.txt
echo - Model Load: ~100ms for 100MB >> %RELEASE_DIR%\README.txt
echo - Verified with: 60M and 1B parameter models >> %RELEASE_DIR%\README.txt

echo.
echo ==========================================
echo Release Package Created!
echo ==========================================
echo.
echo Location: %RELEASE_DIR%
echo.
echo Package contents:
dir /s /b %RELEASE_DIR%
echo.
echo To distribute:
echo 1. Zip the release directory: RawrXD-ModelLoading-v1.0.0
echo 2. Upload to distribution server
echo 3. Update download links
echo.
pause
