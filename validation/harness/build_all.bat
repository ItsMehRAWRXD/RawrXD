@echo off
setlocal enabledelayedexpansion

echo === RawrXD Validation Framework Build ===
echo.

:: Set up MinGW path
set PATH=C:\ProgramData\mingw64\mingw64\bin;%PATH%

:: Verify g++ exists
where g++ >nul 2>nul
if errorlevel 1 (
    echo ERROR: g++ not found in PATH
    echo PATH=%PATH%
    exit /b 1
) else (
    echo g++ found
    g++ --version
)

echo.
echo === Building ValidationHarness.exe ===
g++ -std=c++17 -O2 -I"d:\RawrXD\3rdparty" ValidationHarness.cpp -o ValidationHarness.exe -lws2_32
if errorlevel 1 (
    echo FAILED: ValidationHarness.exe
    exit /b 1
) else (
    echo OK: ValidationHarness.exe
)

echo.
echo === Building HardwareValidator.exe ===
g++ -std=c++17 -O2 -I"d:\RawrXD\3rdparty" HardwareValidator.cpp -o HardwareValidator.exe -lws2_32
if errorlevel 1 (
    echo FAILED: HardwareValidator.exe
    exit /b 1
) else (
    echo OK: HardwareValidator.exe
)

echo.
echo === Building RealInferenceBenchmark.exe ===
g++ -std=c++17 -O2 -I"d:\RawrXD\3rdparty" RealInferenceBenchmark.cpp -o RealInferenceBenchmark.exe -lws2_32
if errorlevel 1 (
    echo FAILED: RealInferenceBenchmark.exe
    exit /b 1
) else (
    echo OK: RealInferenceBenchmark.exe
)

echo.
echo === Building TelemetryCollector.exe ===
g++ -std=c++17 -O2 -I"d:\RawrXD\3rdparty" TelemetryCollector.cpp -o TelemetryCollector.exe -lws2_32 -lpdh
if errorlevel 1 (
    echo FAILED: TelemetryCollector.exe
    exit /b 1
) else (
    echo OK: TelemetryCollector.exe
)

echo.
echo === All builds completed successfully! ===
echo.
dir *.exe
