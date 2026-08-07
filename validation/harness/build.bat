@echo off
:: RawrXD Validation Harness Build Script
:: Builds the production validation harness for generating witness artifacts

echo Building RawrXD Validation Harness Suite...
echo.

set CXXFLAGS=/std:c++17 /O2 /W3 /EHsc /nologo
set INCLUDES=/I"..\..\3rdparty\json\include"
set COMMON_LIBS=ws2_32.lib

if not exist "..\..\3rdparty\json\include" (
    echo ERROR: nlohmann/json not found at ..\..\3rdparty\json\include
    echo Please ensure the JSON library is available
    exit /b 1
)

:: Build ValidationHarness.exe
echo [1/4] Building ValidationHarness.exe...
cl %CXXFLAGS% %INCLUDES% ValidationHarness.cpp /Fe:ValidationHarness.exe /link %COMMON_LIBS%
if errorlevel 1 (
    echo ValidationHarness build FAILED
    exit /b 1
)
echo   SUCCESS

:: Build HardwareValidator.exe
echo [2/4] Building HardwareValidator.exe...
cl %CXXFLAGS% %INCLUDES% HardwareValidator.cpp /Fe:HardwareValidator.exe /link %COMMON_LIBS%
if errorlevel 1 (
    echo HardwareValidator build FAILED
    exit /b 1
)
echo   SUCCESS

:: Build RealInferenceBenchmark.exe
echo [3/4] Building RealInferenceBenchmark.exe...
cl %CXXFLAGS% %INCLUDES% RealInferenceBenchmark.cpp /Fe:RealInferenceBenchmark.exe /link %COMMON_LIBS%
if errorlevel 1 (
    echo RealInferenceBenchmark build FAILED
    exit /b 1
)
echo   SUCCESS

:: Build TelemetryCollector.exe
echo [4/5] Building TelemetryCollector.exe...
cl %CXXFLAGS% %INCLUDES% TelemetryCollector.cpp /Fe:TelemetryCollector.exe /link %COMMON_LIBS% pdh.lib
if errorlevel 1 (
    echo TelemetryCollector build FAILED
    exit /b 1
)
echo   SUCCESS

:: Build complete
echo.
echo ========================================
echo Build SUCCESSFUL
echo ========================================
echo.
echo Generated executables:
echo   - ValidationHarness.exe      (Full validation suite)
echo   - HardwareValidator.exe      (GPU detection)
echo   - RealInferenceBenchmark.exe (Live inference testing)
echo   - TelemetryCollector.exe     (Real-time GPU telemetry)
echo.
echo Usage Examples:
echo.
echo   ValidationHarness.exe --output-dir validation_output --target http://127.0.0.1:8080 --iterations 100
echo   HardwareValidator.exe validation_output\hardware_report.json
echo   RealInferenceBenchmark.exe --host 127.0.0.1 --port 8080 --runs 50 --output benchmark.json
echo   TelemetryCollector.exe --duration 60 --interval 1000 --output telemetry.json
echo.
