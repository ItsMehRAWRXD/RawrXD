@echo off
REM ============================================================================
REM build_minimal_test.bat - Build Minimal ModelOperationsBridge Test
REM ============================================================================
REM Standalone test that avoids heavy dependencies (swarm_scheduler, etc.)
REM Tests: Job ID allocation, callback registry, stats tracking
REM ============================================================================

echo [BUILD] Minimal ModelOperationsBridge Test
echo ===========================================

set "MSVC_ROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"
set "WIN_SDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "SDK_VER=10.0.22621.0"

echo [BUILD] MSVC: %MSVC_ROOT%
echo [BUILD] SDK: %WIN_SDK_ROOT%\%SDK_VER%

REM Set up environment
set "INCLUDE=%MSVC_ROOT%\include;%WIN_SDK_ROOT%\Include\%SDK_VER%\ucrt;%WIN_SDK_ROOT%\Include\%SDK_VER%\shared;%WIN_SDK_ROOT%\Include\%SDK_VER%\um"
set "LIB=%MSVC_ROOT%\lib\x64;%MSVC_ROOT%\lib\onecore\x64;%WIN_SDK_ROOT%\Lib\%SDK_VER%\ucrt\x64;%WIN_SDK_ROOT%\Lib\%SDK_VER%\um\x64"
set "PATH=%MSVC_ROOT%\bin\Hostx64\x64;%WIN_SDK_ROOT%\bin\%SDK_VER%\x64;%PATH%"

echo [BUILD] INCLUDE set
echo [BUILD] LIB set

REM Create build directory
if not exist "build\test" mkdir build\test

echo.
echo [BUILD] Compiling minimal test...
echo.

REM Compile minimal test (no external dependencies)
"%MSVC_ROOT%\bin\Hostx64\x64\cl.exe" /std:c++latest /EHsc /W3 /nologo /DWIN32 /D_WINDOWS /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX ^
    /c src\test\model_operations_bridge_minimal_test.cpp /Fo"build\test\model_operations_bridge_minimal_test.obj"
if errorlevel 1 (
    echo [ERROR] Failed to compile minimal test
    exit /b 1
)

echo.
echo [BUILD] Linking...
echo.

REM Link
"%MSVC_ROOT%\bin\Hostx64\x64\link.exe" build\test\model_operations_bridge_minimal_test.obj ^
    user32.lib gdi32.lib kernel32.lib /OUT:"build\test\model_operations_bridge_minimal_test.exe"
if errorlevel 1 (
    echo [ERROR] Link failed
    exit /b 1
)

echo.
echo [BUILD] ============================================
echo [BUILD] Build successful!
echo [BUILD] Output: build\test\model_operations_bridge_minimal_test.exe
echo [BUILD] ============================================
echo.
echo [RUN] To execute the test:
echo [RUN]   build\test\model_operations_bridge_minimal_test.exe
echo.

exit /b 0