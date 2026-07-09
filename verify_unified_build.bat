@echo off
REM Build Verification Script for Unified Architecture
REM Verifies all unified components compile successfully

echo ==========================================
echo Unified Architecture Build Verification
echo ==========================================
echo.

set CXX=g++
set CXXFLAGS=-std=c++17 -Wall -Wextra -I. -Isrc -Iinclude
set ERRORS=0

echo [1/8] Compiling Core.cpp...
%CXX% %CXXFLAGS% -c src\agentic\Core.cpp -o build\Core.o 2>nul
if %ERRORLEVEL% neq 0 (
    echo FAILED: Core.cpp
    set /a ERRORS+=1
) else (
    echo OK: Core.cpp
)

echo [2/8] Compiling LegacyCoreAdapter.cpp...
%CXX% %CXXFLAGS% -c src\agentic\LegacyCoreAdapter.cpp -o build\LegacyCoreAdapter.o 2>nul
if %ERRORLEVEL% neq 0 (
    echo FAILED: LegacyCoreAdapter.cpp
    set /a ERRORS+=1
) else (
    echo OK: LegacyCoreAdapter.cpp
)

echo [3/8] Compiling LegacyInferenceAdapter.cpp...
%CXX% %CXXFLAGS% -c src\inference\LegacyInferenceAdapter.cpp -o build\LegacyInferenceAdapter.o 2>nul
if %ERRORLEVEL% neq 0 (
    echo FAILED: LegacyInferenceAdapter.cpp
    set /a ERRORS+=1
) else (
    echo OK: LegacyInferenceAdapter.cpp
)

echo [4/8] Verifying ErrorHandling.h...
%CXX% %CXXFLAGS% -fsyntax-only src\core\ErrorHandling.h 2>nul
if %ERRORLEVEL% neq 0 (
    echo FAILED: ErrorHandling.h
    set /a ERRORS+=1
) else (
    echo OK: ErrorHandling.h
)

echo [5/8] Verifying Config.h...
%CXX% %CXXFLAGS% -fsyntax-only src\core\Config.h 2>nul
if %ERRORLEVEL% neq 0 (
    echo FAILED: Config.h
    set /a ERRORS+=1
) else (
    echo OK: Config.h
)

echo [6/8] Verifying Logger.h...
%CXX% %CXXFLAGS% -fsyntax-only src\core\Logger.h 2>nul
if %ERRORLEVEL% neq 0 (
    echo FAILED: Logger.h
    set /a ERRORS+=1
) else (
    echo OK: Logger.h
)

echo [7/8] Verifying Core.h...
%CXX% %CXXFLAGS% -fsyntax-only src\agentic\Core.h 2>nul
if %ERRORLEVEL% neq 0 (
    echo FAILED: Core.h
    set /a ERRORS+=1
) else (
    echo OK: Core.h
)

echo [8/8] Verifying InferenceEngine.h...
%CXX% %CXXFLAGS% -fsyntax-only src\inference\InferenceEngine.h 2>nul
if %ERRORLEVEL% neq 0 (
    echo FAILED: InferenceEngine.h
    set /a ERRORS+=1
) else (
    echo OK: InferenceEngine.h
)

echo.
echo ==========================================
if %ERRORS% equ 0 (
    echo BUILD VERIFICATION: PASSED
    echo All unified architecture components compile successfully!
) else (
    echo BUILD VERIFICATION: FAILED
    echo %ERRORS% component(s) failed to compile
)
echo ==========================================

exit /b %ERRORS%
