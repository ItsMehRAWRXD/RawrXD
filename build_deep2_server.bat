@echo off
REM ============================================================================
REM build_deep2_server.bat - Build Deep2 Local Server
REM ============================================================================

setlocal enabledelayedexpansion

set "RAWXD_ROOT=d:\rawrxd"
set "BUILD_DIR=%RAWXD_ROOT%\build_deep2"
set "SRC_DIR=%RAWXD_ROOT%\src\deep2"
set "THIRDPARTY=%RAWXD_ROOT%\third_party"

REM Compiler settings
set "CC=cl.exe"
set "CXX=cl.exe"

REM Include paths
set "INCLUDES=/I%RAWXD_ROOT%\src /I%THIRDPARTY%\llama.cpp /I%THIRDPARTY%\llama.cpp\ggml\include /I%THIRDPARTY%\llama.cpp\ggml\src"

REM Compiler flags
set "CFLAGS=/nologo /O2 /arch:AVX2 /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /W3 /EHsc /MP"
set "CXXFLAGS=%CFLAGS% /std:c++17"

REM Linker flags
set "LDFLAGS=/link /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF"

REM Libraries
set "LIBS=kernel32.lib user32.lib ws2_32.lib"

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
cd /d "%BUILD_DIR%"

echo ============================================================================
echo Building Deep2 Local Server
echo ============================================================================
echo.

REM Source files for server
set "SERVER_SOURCES=%SRC_DIR%\deep2_server_main.cpp %SRC_DIR%\Deep2LocalServer.cpp %SRC_DIR%\Deep2InferenceGateway.cpp"

REM Source files for certification
set "CERT_SOURCES=%SRC_DIR%\VAL063_Deep2Certification.cpp %SRC_DIR%\Deep2InferenceGateway.cpp"

REM Additional Deep2 engine sources (adjust as needed)
set "DEEP2_SOURCES=%SRC_DIR%\Deep2Engine.cpp"

echo [1/3] Compiling Deep2 Local Server...
%CXX% %CXXFLAGS% %INCLUDES% %SERVER_SOURCES% %DEEP2_SOURCES% /Fe:deep2_server.exe %LDFLAGS% %LIBS%
if errorlevel 1 (
    echo [FAIL] Server compilation failed
    exit /b 1
)
echo [PASS] deep2_server.exe built successfully
echo.

echo [2/3] Compiling VAL-063 Certification...
%CXX% %CXXFLAGS% %INCLUDES% %CERT_SOURCES% %DEEP2_SOURCES% /Fe:VAL063_Certification.exe %LDFLAGS% %LIBS%
if errorlevel 1 (
    echo [FAIL] Certification compilation failed
    exit /b 1
)
echo [PASS] VAL063_Certification.exe built successfully
echo.

echo [3/3] Build Summary
echo ============================================================================
dir /b *.exe 2>nul
echo.
echo Usage:
echo   deep2_server.exe --model ^<path^> [--port ^<port^>] [--host ^<host^>]
echo   VAL063_Certification.exe ^<model.gguf^> [prompt]
echo.
echo ============================================================================
echo Build complete!
echo ============================================================================

endlocal
