@echo off
REM Simple Build Validation for RawrXD Unified Architecture
REM Provides concrete evidence of compilation success

echo ==========================================
echo RawrXD Build Validation
echo ==========================================
echo.

set CXX=g++
set CXXFLAGS=-std=c++17 -Wall -Wextra -I. -Isrc -Iinclude
set BUILD_DIR=build_validation
set ERRORS=0

REM Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo Phase 1: Component Compilation
echo ------------------------------------------

echo [1/6] Compiling Core.cpp...
%CXX% %CXXFLAGS% -c src\agentic\Core.cpp -o %BUILD_DIR%\Core.o 2>nul
if %ERRORLEVEL% neq 0 (
    echo FAILED: Core.cpp
    set /a ERRORS+=1
) else (
    echo PASS: Core.cpp
)

echo [2/6] Compiling LegacyCoreAdapter.cpp...
%CXX% %CXXFLAGS% -c src\agentic\LegacyCoreAdapter.cpp -o %BUILD_DIR%\LegacyCoreAdapter.o 2>nul
if %ERRORLEVEL% neq 0 (
    echo FAILED: LegacyCoreAdapter.cpp
    set /a ERRORS+=1
) else (
    echo PASS: LegacyCoreAdapter.cpp
)

echo [3/6] Compiling LegacyInferenceAdapter.cpp...
%CXX% %CXXFLAGS% -c src\inference\LegacyInferenceAdapter.cpp -o %BUILD_DIR%\LegacyInferenceAdapter.o 2>nul
if %ERRORLEVEL% neq 0 (
    echo FAILED: LegacyInferenceAdapter.cpp
    set /a ERRORS+=1
) else (
    echo PASS: LegacyInferenceAdapter.cpp
)

echo.
echo Phase 2: Header Validation
echo ------------------------------------------

echo [4/6] Validating Core.h...
%CXX% %CXXFLAGS% -fsyntax-only src\agentic\Core.h 2>nul
if %ERRORLEVEL% neq 0 (
    echo FAILED: Core.h
    set /a ERRORS+=1
) else (
    echo PASS: Core.h
)

echo [5/6] Validating InferenceEngine.h...
%CXX% %CXXFLAGS% -fsyntax-only src\inference\InferenceEngine.h 2>nul
if %ERRORLEVEL% neq 0 (
    echo FAILED: InferenceEngine.h
    set /a ERRORS+=1
) else (
    echo PASS: InferenceEngine.h
)

echo [6/6] Validating ErrorHandling.h...
%CXX% %CXXFLAGS% -fsyntax-only src\core\ErrorHandling.h 2>nul
if %ERRORLEVEL% neq 0 (
    echo FAILED: ErrorHandling.h
    set /a ERRORS+=1
) else (
    echo PASS: ErrorHandling.h
)

echo.
echo ==========================================
if %ERRORS% equ 0 (
    echo VALIDATION PASSED
    echo All components compile successfully
) else (
    echo VALIDATION FAILED
    echo %ERRORS% component(s) failed
)
echo ==========================================

exit /b %ERRORS%
