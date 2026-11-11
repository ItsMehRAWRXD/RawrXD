@echo off
REM =============================================================================
REM link_sovereign_engine.bat
REM Final Link Step: Combine all Phase 11/22/23 components into executables
REM =============================================================================

setlocal EnableDelayedExpansion

set "BUILD_DIR=D:\RawrXD\build"
set "BIN_DIR=%BUILD_DIR%\bin"
set "OBJ_DIR=%BUILD_DIR%\obj"

REM Toolchain
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

REM Linker flags
set "LDFLAGS=/MACHINE:X64 /OPT:REF /OPT:ICF /LARGEADDRESSAWARE /SUBSYSTEM:CONSOLE"
set "DEBUG_LDFLAGS=/MACHINE:X64 /DEBUG /LARGEADDRESSAWARE /SUBSYSTEM:CONSOLE"

REM Libraries
set "LIBS=kernel32.lib user32.lib advapi32.lib ws2_32.lib"

REM Create bin directory
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

echo.
echo =============================================================================
echo Linking Sovereign Engine Components
echo =============================================================================

REM Collect all object files
set "OBJ_FILES="
for %%f in ("%OBJ_DIR%\*.obj") do (
    set "OBJ_FILES=!OBJ_FILES! "%%f""
)

echo Object files: %OBJ_FILES%

REM =============================================================================
REM Link: Integration Test Executable
REM =============================================================================

echo.
echo [1/3] Linking test_ring_integration.exe...
"%LINK%" %LDFLAGS% /OUT:"%BIN_DIR%\test_ring_integration.exe" %OBJ_FILES% %LIBS%
if errorlevel 1 (
    echo ERROR: Failed to link test_ring_integration.exe
    exit /b 1
)
echo OK: %BIN_DIR%\test_ring_integration.exe

REM =============================================================================
REM Link: Engine Controller Test
REM =============================================================================

echo.
echo [2/3] Linking test_engine_controller_integration.exe...
"%LINK%" %LDFLAGS% /OUT:"%BIN_DIR%\test_engine_controller_integration.exe" %OBJ_FILES% %LIBS%
if errorlevel 1 (
    echo ERROR: Failed to link test_engine_controller_integration.exe
    exit /b 1
)
echo OK: %BIN_DIR%\test_engine_controller_integration.exe

REM =============================================================================
REM Link: Sovereign Engine DLL
REM =============================================================================

echo.
echo [3/3] Linking sovereign_engine.dll...
"%LINK%" /DLL %LDFLAGS% /OUT:"%BIN_DIR%\sovereign_engine.dll" /IMPLIB:"%BUILD_DIR%\sovereign_engine_dll.lib" %OBJ_FILES% %LIBS%
if errorlevel 1 (
    echo ERROR: Failed to link sovereign_engine.dll
    exit /b 1
)
echo OK: %BIN_DIR%\sovereign_engine.dll

REM =============================================================================
REM Summary
REM =============================================================================

echo.
echo =============================================================================
echo LINK COMPLETE
echo =============================================================================
echo.
echo Executables:
dir /b "%BIN_DIR%\*.exe" 2^>nul
echo.
echo Libraries:
dir /b "%BIN_DIR%\*.dll" "%BUILD_DIR%\*.lib" 2^>nul
echo.
echo Next: Run tests with: %BIN_DIR%\test_ring_integration.exe
echo.

endlocal
