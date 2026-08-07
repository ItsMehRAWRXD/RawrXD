@echo off
REM ============================================================================
REM build_deep2_server_mingw.bat - Build Deep2 Local Server with MinGW
REM ============================================================================

setlocal enabledelayedexpansion

set "RAWXD_ROOT=d:\rawrxd"
set "BUILD_DIR=%RAWXD_ROOT%\build_deep2"
set "SRC_DIR=%RAWXD_ROOT%\src\deep2"
set "THIRDPARTY=%RAWXD_ROOT%\third_party"

REM MinGW paths
set "MINGW_BIN=C:\msys64\mingw64\bin"
set "CC=%MINGW_BIN%\gcc.exe"
set "CXX=%MINGW_BIN%\g++.exe"

REM Check for MinGW
if not exist "%CXX%" (
    echo ERROR: MinGW g++ not found at %CXX%
    echo Please install MSYS2/MinGW-w64
    exit /b 1
)

REM Include paths
set "INCLUDES=-I%RAWXD_ROOT%\src -I%THIRDPARTY%\llama.cpp -I%THIRDPARTY%\llama.cpp\ggml\include -I%THIRDPARTY%\llama.cpp\ggml\src"

REM Compiler flags
set "CFLAGS=-O3 -march=native -DNDEBUG -D_CRT_SECURE_NO_WARNINGS -Wall -Wextra -std=c11"
set "CXXFLAGS=-O3 -march=native -DNDEBUG -D_CRT_SECURE_NO_WARNINGS -Wall -Wextra -std=c++17"

REM Libraries
set "LIBS=-lws2_32 -lkernel32 -luser32"

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
cd /d "%BUILD_DIR%"

echo ============================================================================
echo Building Deep2 Local Server with MinGW
echo ============================================================================
echo.
echo Compiler: %CXX%
echo.

REM Source files for server
set "SERVER_SOURCES=%SRC_DIR%\deep2_server_main.cpp %SRC_DIR%\Deep2LocalServer.cpp %SRC_DIR%\Deep2InferenceGateway.cpp"

REM Additional Deep2 engine sources
set "DEEP2_SOURCES=%SRC_DIR%\Deep2Engine.cpp"

echo [1/2] Compiling Deep2 Local Server...
echo Sources: %SERVER_SOURCES%
echo.

%CXX% %CXXFLAGS% %INCLUDES% %SERVER_SOURCES% %DEEP2_SOURCES% -o deep2_server.exe %LIBS% 2>&1
if errorlevel 1 (
    echo.
    echo [FAIL] Server compilation failed
    exit /b 1
)
echo [PASS] deep2_server.exe built successfully
echo.

echo [2/2] Build Summary
echo ============================================================================
dir /b *.exe 2>nul
echo.
echo Usage:
echo   deep2_server.exe --model ^<path^> [--port ^<port^>] [--host ^<host^>]
echo.
echo Example:
echo   deep2_server.exe --model models\\llama-3.1-8b-q4.gguf
echo.
echo ============================================================================
echo Build complete!
echo ============================================================================

endlocal
