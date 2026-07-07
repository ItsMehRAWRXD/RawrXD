@echo off
REM ============================================================================
REM build_bridge_test.bat - Build ModelOperationsBridge Validation Test
REM ============================================================================
REM Uses VS2022 Dev environment to compile the test.
REM ============================================================================

echo [BUILD] ModelOperationsBridge Validation Test
echo ==============================================

REM Set up VS2022 environment
if exist "C:\VS2022Enterprise\Common7\Tools\VsDevCmd.bat" (
    call "C:\VS2022Enterprise\Common7\Tools\VsDevCmd.bat" -arch=x64
) else if exist "D:\VS2022Enterprise\Common7\Tools\VsDevCmd.bat" (
    call "D:\VS2022Enterprise\Common7\Tools\VsDevCmd.bat" -arch=x64
) else (
    echo [ERROR] VS2022 Dev environment not found
    exit /b 1
)

echo [BUILD] Environment set up
echo.

REM Create build directory
if not exist "build\test" mkdir build\test

REM Compile
echo [BUILD] Compiling...
cl.exe /std:c++20 /EHsc /W3 /nologo /DWIN32 /D_WINDOWS /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN ^
    /I"src" /I"src\core" /I"src\win32app" /I"3rdparty\nlohmann\single_include" ^
    /c src\core\model_operations_bridge.cpp /Fo"build\test\model_operations_bridge.obj" 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to compile model_operations_bridge.cpp
    exit /b 1
)

cl.exe /std:c++20 /EHsc /W3 /nologo /DWIN32 /D_WINDOWS /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN ^
    /I"src" /I"src\core" /I"src\win32app" /I"3rdparty\nlohmann\single_include" ^
    /c src\core\thread_pool.cpp /Fo"build\test\thread_pool.obj" 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to compile thread_pool.cpp
    exit /b 1
)

cl.exe /std:c++20 /EHsc /W3 /nologo /DWIN32 /D_WINDOWS /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN ^
    /I"src" /I"src\core" /I"src\win32app" /I"3rdparty\nlohmann\single_include" ^
    /c src\test\model_operations_bridge_test.cpp /Fo"build\test\model_operations_bridge_test.obj" 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to compile model_operations_bridge_test.cpp
    exit /b 1
)

echo.
echo [BUILD] Linking...
link.exe build\test\model_operations_bridge.obj build\test\thread_pool.obj build\test\model_operations_bridge_test.obj ^
    user32.lib gdi32.lib kernel32.lib /OUT:"build\test\model_operations_bridge_test.exe" 2>&1
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