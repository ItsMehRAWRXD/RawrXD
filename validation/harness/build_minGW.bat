@echo off
setlocal
set PATH=C:\ProgramData\mingw64\mingw64\bin;C:\mingw64\bin;%PATH%
set CXXFLAGS=-std=c++17 -O2 -I"d:\RawrXD\3rdparty"
set COMMON_LIBS=-lws2_32 -lwbemuuid -lole32 -loleaut32 -luuid

echo Building RawrXD Validation Harness Suite (MinGW)...
echo.

echo [1/4] Building ValidationHarness.exe...
C:\ProgramData\mingw64\mingw64\bin\g++.exe %CXXFLAGS% ValidationHarness.cpp -o ValidationHarness.exe %COMMON_LIBS% 2>build_err1.txt
if errorlevel 1 (
    echo FAILED
    type build_err1.txt
    exit /b 1
)
echo   SUCCESS

echo [2/4] Building HardwareValidator.exe...
C:\ProgramData\mingw64\mingw64\bin\g++.exe %CXXFLAGS% HardwareValidator.cpp -o HardwareValidator.exe %COMMON_LIBS% 2>build_err2.txt
if errorlevel 1 (
    echo FAILED
    type build_err2.txt
    exit /b 1
)
echo   SUCCESS

echo [3/4] Building RealInferenceBenchmark.exe...
g++ %CXXFLAGS% RealInferenceBenchmark.cpp -o RealInferenceBenchmark.exe %COMMON_LIBS% 2>build_err3.txt
if errorlevel 1 (
    echo FAILED
    type build_err3.txt
    exit /b 1
)
echo   SUCCESS

echo [4/4] Building TelemetryCollector.exe...
g++ %CXXFLAGS% TelemetryCollector.cpp -o TelemetryCollector.exe %COMMON_LIBS% -lpdh 2>build_err4.txt
if errorlevel 1 (
    echo FAILED
    type build_err4.txt
    exit /b 1
)
echo   SUCCESS

echo.
echo All builds completed successfully!
echo.
echo Executables created:
dir *.exe
