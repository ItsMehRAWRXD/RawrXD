@echo off
REM Build script for Phase 6 Real Model Validator

echo Building Real Model Validator...
echo.

set CXX=g++.exe
set CXXFLAGS=-std=c++17 -O2 -Wall -Wextra -DUNICODE -D_UNICODE
set INCLUDES=-I"%~dp0..\..\include" -I"%~dp0..\..\include\gpu"
set LIBS=-ldxgi -ld3d12 -lshlwapi

REM Create output directory
if not exist "%~dp0..\..\build" mkdir "%~dp0..\..\build"

REM Compile
%CXX% %CXXFLAGS% %INCLUDES% "%~dp0real_model_validator.cpp" -o "%~dp0..\..\build\real_model_validator.exe" %LIBS%

if %ERRORLEVEL% neq 0 (
    echo Build FAILED
    exit /b 1
)

echo Build SUCCESSFUL
echo.
echo Usage:
echo   build\real_model_validator.exe [models_directory]
echo.
echo Example:
echo   build\real_model_validator.exe F:\models
echo.
