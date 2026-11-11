@echo off
::============================================================================
:: test_build.bat
:: RawrXD N-EVM - Test Suite Build Script
::============================================================================

setlocal enabledelayedexpansion

:: Configuration
set "TEST_NAME=%1"
set "BUILD_TYPE=%2"
if "%~1"=="" set "TEST_NAME=all"
if "%~2"=="" set "BUILD_TYPE=release"

:: Directories
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%..\..\.."
set "BUILD_DIR=%PROJECT_ROOT%\build\tests"
set "SRC_DIR=%SCRIPT_DIR%"

:: Compiler settings
set "CXX=cl"
set "CXXFLAGS=/std:c++17 /W4 /EHsc /MP"
set "INCLUDES=/I%PROJECT_ROOT%\src\nevm /I%PROJECT_ROOT%\third_party\jsoncpp\include"
set "LIBS=kernel32.lib user32.lib"

:: Set build-specific flags
if /I "%BUILD_TYPE%"=="debug" (
    set "CXXFLAGS=%CXXFLAGS% /Od /Zi /MDd /D_DEBUG"
    set "LINKFLAGS=/DEBUG"
) else (
    set "CXXFLAGS=%CXXFLAGS% /O2 /MD /DNDEBUG"
    set "LINKFLAGS=/OPT:REF /OPT:ICF"
)

echo ================================================================================
echo RawrXD N-EVM Test Suite Build
echo ================================================================================
echo Build Type: %BUILD_TYPE%
echo Test Target: %TEST_NAME%
echo ================================================================================

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

:: Test files
set "TEST_FILES=test_main.cpp"
set "TEST_FILES=%TEST_FILES% test_math_mode.cpp"
set "TEST_FILES=%TEST_FILES% test_determinism.cpp"
set "TEST_FILES=%TEST_FILES% test_kv_integrity.cpp"
set "TEST_FILES=%TEST_FILES% test_execution_plan.cpp"
set "TEST_FILES=%TEST_FILES% test_performance_thresholds.cpp"
set "TEST_FILES=%TEST_FILES% test_golden_output.cpp"
set "TEST_FILES=%TEST_FILES% test_validation_schema.cpp"
set "TEST_FILES=%TEST_FILES% test_integration.cpp"

:: Build specific test or all
if /I "%TEST_NAME%"=="all" (
    echo Building all tests...
    set "SOURCES=%TEST_FILES%"
    set "OUTPUT=%BUILD_DIR%\nevm_tests.exe"
) else (
    echo Building %TEST_NAME%...
    set "SOURCES=test_main.cpp %TEST_NAME%.cpp"
    set "OUTPUT=%BUILD_DIR%\%TEST_NAME%.exe"
)

:: Compile
echo.
echo Compiling...
echo Sources: %SOURCES%
echo Output: %OUTPUT%
echo.

set "OBJ_FILES="
for %%f in (%SOURCES%) do (
    set "OBJ_FILE=%BUILD_DIR%\%%~nf.obj"
    set "OBJ_FILES=!OBJ_FILES! !OBJ_FILE!"
    
    echo Compiling %%f...
    %CXX% /c %CXXFLAGS% %INCLUDES% /Fo"!OBJ_FILE!" "%SRC_DIR%\%%f"
    
    if errorlevel 1 (
        echo ERROR: Compilation failed for %%f
        exit /b 1
    )
)

:: Link
echo.
echo Linking...
link %LINKFLAGS% /OUT:"%OUTPUT%" %OBJ_FILES% %LIBS%

if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

echo.
echo ================================================================================
echo Build successful: %OUTPUT%
echo ================================================================================

:: Run tests if requested
if /I "%3"=="run" (
    echo.
    echo Running tests...
    echo ================================================================================
    "%OUTPUT%"
    set "EXIT_CODE=%ERRORLEVEL%"
    echo ================================================================================
    echo Test exit code: %EXIT_CODE%
    exit /b %EXIT_CODE%
)

exit /b 0
