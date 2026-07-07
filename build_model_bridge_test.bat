@echo off
REM ============================================================================
REM build_model_bridge_test.bat - Build ModelOperationsBridge Validation Test
REM ============================================================================
REM Minimal build script for testing the ModelOperationsBridge infrastructure
REM before wiring it into the full Win32IDE build.
REM ============================================================================

setlocal enabledelayedexpansion

echo [BUILD] ModelOperationsBridge Validation Test
echo ============================================

REM Detect MSVC toolchain
set "MSVC_ROOT="
for %%C in (
    "D:\VS2022Enterprise\VC\Tools\MSVC"
    "C:\VS2022Enterprise\VC\Tools\MSVC"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC"
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC"
) do (
    if exist %%C (
        for /f "delims=" %%V in ('dir /b /ad "%%C" 2^>nul ^| findstr /r "^[0-9]"') do (
            if exist "%%C\%%V\bin\Hostx64\x64\cl.exe" (
                set "MSVC_ROOT=%%C\%%V"
                goto :found_msvc
            )
        )
    )
)

echo [ERROR] MSVC toolchain not found. Please run from a Developer Command Prompt.
exit /b 1

:found_msvc
echo [BUILD] Found MSVC at: %MSVC_ROOT%

REM Detect Windows SDK
set "WIN_SDK_ROOT="
for %%S in (
    "D:\Program Files (x86)\Windows Kits\10"
    "C:\Program Files (x86)\Windows Kits\10"
) do (
    if exist %%S (
        set "WIN_SDK_ROOT=%%S"
        goto :found_sdk
    )
)

echo [ERROR] Windows SDK not found.
exit /b 1

:found_sdk
echo [BUILD] Found Windows SDK at: %WIN_SDK_ROOT%

REM Set up environment
set "INCLUDE=%MSVC_ROOT%\include;%WIN_SDK_ROOT%\Include\10.0.22621.0\ucrt;%WIN_SDK_ROOT%\Include\10.0.22621.0\shared;%WIN_SDK_ROOT%\Include\10.0.22621.0\um"
set "LIB=%MSVC_ROOT%\lib\x64;%MSVC_ROOT%\lib\onecore\x64;%WIN_SDK_ROOT%\Lib\10.0.22621.0\ucrt\x64;%WIN_SDK_ROOT%\Lib\10.0.22621.0\um\x64"
set "PATH=%MSVC_ROOT%\bin\Hostx64\x64;%WIN_SDK_ROOT%\bin\10.0.22621.0\x64;%PATH%"

echo [BUILD] INCLUDE set
echo [BUILD] LIB set
echo [BUILD] PATH updated

REM Create build output directory
if not exist "build\test" mkdir build\test

REM Source files
set "SOURCES=src\core\model_operations_bridge.cpp src\core\thread_pool.cpp src\test\model_operations_bridge_test.cpp"

REM Compiler flags
set "CXXFLAGS=/std:c++20 /EHsc /W3 /nologo /DWIN32 /D_WINDOWS /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN"

REM Include paths
set "INCLUDES=/I"src" /I"src\core" /I"src\win32app" /I"3rdparty\nlohmann\single_include""

REM Linker flags
set "LDFLAGS=/link user32.lib gdi32.lib kernel32.lib"

echo.
echo [BUILD] Compiling...
echo.

REM Compile each source file
for %%F in (src\core\model_operations_bridge.cpp src\core\thread_pool.cpp src\test\model_operations_bridge_test.cpp) do (
    echo [COMPILE] %%F
    "%MSVC_ROOT%\bin\Hostx64\x64\cl.exe" %CXXFLAGS% %INCLUDES% /c "%%F" /Fo"build\test\%%~nF.obj" 2>&1
    if errorlevel 1 (
        echo [ERROR] Failed to compile %%F
        exit /b 1
    )
)

echo.
echo [BUILD] Linking...
echo.

REM Link
"%MSVC_ROOT%\bin\Hostx64\x64\link.exe" build\test\model_operations_bridge.obj build\test\thread_pool.obj build\test\model_operations_bridge_test.obj %LDFLAGS% /OUT:"build\test\model_operations_bridge_test.exe" 2>&1
if errorlevel 1 (
    echo [ERROR] Link failed
    exit /b 1
)

echo.
echo [BUILD] ============================================
echo [BUILD] Build successful!
echo [BUILD] Output: build\test\model_operations_bridge_test.exe
echo [BUILD] ============================================
echo.
echo [RUN] To execute the test:
echo [RUN]   build\test\model_operations_bridge_test.exe
echo.

exit /b 0