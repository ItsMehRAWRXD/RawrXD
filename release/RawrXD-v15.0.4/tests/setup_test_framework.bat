@echo off
REM =============================================================================
REM   RawrXD Production Test Framework - Batch 1 of 5
REM   Comprehensive testing infrastructure for the entire D drive codebase
REM =============================================================================

setlocal EnableDelayedExpansion

set "RAWRXD_HOME=d:\rawrxd"
set "TEST_HOME=%RAWRXD_HOME%\tests"
set "BUILD_HOME=%RAWRXD_HOME%\build"

if not exist "%TEST_HOME%" mkdir "%TEST_HOME%"
if not exist "%TEST_HOME%\unit" mkdir "%TEST_HOME%\unit"
if not exist "%TEST_HOME%\integration" mkdir "%TEST_HOME%\integration"
if not exist "%TEST_HOME%\fuzz" mkdir "%TEST_HOME%\fuzz"
if not exist "%TEST_HOME%\sanitizer" mkdir "%TEST_HOME%\sanitizer"
if not exist "%BUILD_HOME%" mkdir "%BUILD_HOME%"

echo =============================================================================
echo   RawrXD Production Test Framework - Setup
echo =============================================================================
echo.
echo Test directories created:
echo   - %TEST_HOME%\unit
echo   - %TEST_HOME%\integration
echo   - %TEST_HOME%\fuzz
echo   - %TEST_HOME%\sanitizer
echo.
