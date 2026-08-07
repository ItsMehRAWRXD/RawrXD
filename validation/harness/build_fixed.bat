@echo off
:: RawrXD Validation Harness Build Script
:: Builds the production validation harness for generating witness artifacts

echo Building RawrXD Validation Harness Suite...
echo.

set CXXFLAGS=/std:c++17 /O2 /W3 /EHsc /nologo
set INCLUDES=/I"..\..\3rdparty"
set COMMON_LIBS=ws2_32.lib

if not exist "..\..\3rdparty\nlohmann\json.hpp" (
    echo ERROR: nlohmann/json not found at ..\..\3rdparty\nlohmann\json.hpp
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
echo [4/4] Building TelemetryCollector.exe...
cl %CXXFLAGS% %INCLUDES% TelemetryCollector.cpp /Fe:TelemetryCollector.exe /link %COMMON_LIBS% pdh.lib
if errorlevel 1 (
    echo TelemetryCollector build FAILED
    exit /b 1
)
echo   SUCCESS

echo.
echo All builds completed successfully!
echo.
echo Executables created:
echo   - ValidationHarness.exe
echo   - HardwareValidator.exe
echo   - RealInferenceBenchmark.exe
echo   - TelemetryCollector.exe
