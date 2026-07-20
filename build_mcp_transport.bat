@echo off
REM ============================================================================
REM Build MCP Transport Module for RawrXD IDE
REM MASM x64 + C++ Wrapper Compilation
REM ============================================================================

setlocal EnableDelayedExpansion

REM Tool paths from user memory
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set CL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe

REM Directories
set SRC_DIR=d:\RawrXD\src\mcp
set OBJ_DIR=d:\RawrXD\obj\mcp
set LIB_DIR=d:\RawrXD\lib
set INC_DIR=d:\RawrXD\include

REM Create directories
if not exist %OBJ_DIR% mkdir %OBJ_DIR%
if not exist %LIB_DIR% mkdir %LIB_DIR%
if not exist %INC_DIR% mkdir %INC_DIR%

echo ============================================================================
echo RawrXD MCP Transport Build Pipeline
echo ============================================================================
echo.

REM ============================================================================
REM Step 1: Assemble MASM transport layer
REM ============================================================================
echo [1/4] Assembling MCP_Transport_x64.asm...

"%ML64%" /c /W3 /nologo /Zi /Fo "%OBJ_DIR%\MCP_Transport_x64.obj" "%SRC_DIR%\MCP_Transport_x64.asm" 2>&1

if errorlevel 1 (
    echo ERROR: MASM assembly failed
    exit /b 1
)

echo         MCP_Transport_x64.obj - OK

REM ============================================================================
REM Step 2: Compile C++ wrapper
REM ============================================================================
echo [2/4] Compiling C++ wrapper...

"%CL%" /c /nologo /W4 /EHsc /O2 /Zi /MD /Fo"%OBJ_DIR%\MCP_Transport_Wrapper.obj" ^
    /I"%SRC_DIR%" ^
    /I"d:\RawrXD\third_party\nlohmann" ^
    "%SRC_DIR%\MCP_Transport_Wrapper.cpp" 2>&1

if errorlevel 1 (
    echo ERROR: C++ compilation failed
    exit /b 1
)

echo         MCP_Transport_Wrapper.obj - OK

REM ============================================================================
REM Step 3: Create static library
REM ============================================================================
echo [3/4] Creating static library...

REM Use lib.exe to create static library
set LIB_TOOL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\lib.exe

"%LIB_TOOL%" /nologo /out:"%LIB_DIR%\MCP_Transport.lib" ^
    "%OBJ_DIR%\MCP_Transport_x64.obj" ^
    "%OBJ_DIR%\MCP_Transport_Wrapper.obj" 2>&1

if errorlevel 1 (
    echo ERROR: Library creation failed
    exit /b 1
)

echo         MCP_Transport.lib - OK

REM ============================================================================
REM Step 4: Copy headers
REM ============================================================================
echo [4/4] Copying headers...

copy /Y "%SRC_DIR%\MCP_Transport_Native.h" "%INC_DIR%\" >nul
echo         MCP_Transport_Native.h - OK

REM ============================================================================
REM Summary
REM ============================================================================
echo.
echo ============================================================================
echo Build Complete
echo ============================================================================
echo.
echo Output files:
echo   Library: %LIB_DIR%\MCP_Transport.lib
echo   Header:  %INC_DIR%\MCP_Transport_Native.h
echo.
echo Object files:
dir /b "%OBJ_DIR%\*.obj" 2>nul
echo.

REM ============================================================================
REM Optional: Create test executable
REM ============================================================================
if "%1"=="--test" (
    echo Building test executable...
    
    "%CL%" /nologo /W4 /EHsc /O2 /Zi /MD /Fe"%OBJ_DIR%\MCP_Test.exe" ^
        "%SRC_DIR%\MCP_Test.cpp" ^
        /I"%SRC_DIR%" ^
        /I"%INC_DIR%" ^
        "%LIB_DIR%\MCP_Transport.lib" ^
        winhttp.lib crypt32.lib ws2_32.lib 2>&1
    
    if not errorlevel 1 (
        echo Test executable: %OBJ_DIR%\MCP_Test.exe
    )
)

endlocal
