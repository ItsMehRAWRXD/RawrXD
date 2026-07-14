@echo off
REM ============================================================================
REM RAWRXD FINAL UNIFIED SYSTEM - BUILD SCRIPT
REM Zero-Dependency Model Loading & Streaming + Complete Infrastructure
REM ============================================================================

setlocal enabledelayedexpansion

REM Configuration
set SRC_DIR=%~dp0
set OUT_DIR=%SRC_DIR%\..\bin
set OBJ_DIR=%SRC_DIR%\..\obj

REM Compiler settings
set CXX=cl.exe
set CXXFLAGS=/std:c++20 /O2 /W3 /EHsc /nologo /MP /D_CRT_SECURE_NO_WARNINGS
set CXXFLAGS=%CXXFLAGS% /DWIN32_LEAN_AND_MEAN /DNOMINMAX
set CXXFLAGS=%CXXFLAGS% /I"%SRC_DIR%"

set LDFLAGS=/SUBSYSTEM:CONSOLE /MACHINE:X64

REM Create output directories
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"

echo.
echo ============================================================================
echo  RAWRXD FINAL UNIFIED SYSTEM - BUILD
echo ============================================================================
echo.
echo  Source: %SRC_DIR%
echo  Output: %OUT_DIR%
echo  Objects: %OBJ_DIR%
echo.

REM Source files
set SOURCES=
set SOURCES=%SOURCES% "%SRC_DIR%\RawrXD_Final_Unified.cpp"
set SOURCES=%SOURCES% "%SRC_DIR%\RawrXD_Final_Unified_Part2.cpp"
set SOURCES=%SOURCES% "%SRC_DIR%\RawrXD_Final_Unified_Part3.cpp"

REM Object files
set OBJECTS=
set OBJECTS=%OBJECTS% "%OBJ_DIR%\RawrXD_Final_Unified.obj"
set OBJECTS=%OBJECTS% "%OBJ_DIR%\RawrXD_Final_Unified_Part2.obj"
set OBJECTS=%OBJECTS% "%OBJ_DIR%\RawrXD_Final_Unified_Part3.obj"

REM Compile each source file
echo [1/4] Compiling RawrXD_Final_Unified.cpp...
%CXX% %CXXFLAGS% /c /Fo"%OBJ_DIR%\RawrXD_Final_Unified.obj" "%SRC_DIR%\RawrXD_Final_Unified.cpp"
if errorlevel 1 goto :compile_error

echo [2/4] Compiling RawrXD_Final_Unified_Part2.cpp...
%CXX% %CXXFLAGS% /c /Fo"%OBJ_DIR%\RawrXD_Final_Unified_Part2.obj" "%SRC_DIR%\RawrXD_Final_Unified_Part2.cpp"
if errorlevel 1 goto :compile_error

echo [3/4] Compiling RawrXD_Final_Unified_Part3.cpp...
%CXX% %CXXFLAGS% /c /Fo"%OBJ_DIR%\RawrXD_Final_Unified_Part3.obj" "%SRC_DIR%\RawrXD_Final_Unified_Part3.cpp"
if errorlevel 1 goto :compile_error

REM Link
echo [4/4] Linking RawrXD_Unified.exe...
link.exe %LDFLAGS% /OUT:"%OUT_DIR%\RawrXD_Unified.exe" %OBJECTS%
if errorlevel 1 goto :link_error

echo.
echo ============================================================================
echo  BUILD SUCCESSFUL
echo ============================================================================
echo.
echo  Output: %OUT_DIR%\RawrXD_Unified.exe
echo.

REM Show file info
if exist "%OUT_DIR%\RawrXD_Unified.exe" (
    dir /b "%OUT_DIR%\RawrXD_Unified.exe"
    for %%F in ("%OUT_DIR%\RawrXD_Unified.exe") do (
        echo  Size: %%~zF bytes
    )
)

echo.
goto :end

:compile_error
echo.
echo ERROR: Compilation failed!
echo.
goto :end

:link_error
echo.
echo ERROR: Linking failed!
echo.
goto :end

:end
endlocal
