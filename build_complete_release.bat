@echo off
setlocal EnableDelayedExpansion

echo ============================================
echo RawrXD Complete Release Builder
echo Version: 14.7.3
echo ============================================
echo.

:: Find VS2022
set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise"
if not exist "%VS_PATH%" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
)
if not exist "%VS_PATH%" (
    set "VS_PATH=C:\VS2022Enterprise"
)

if not exist "%VS_PATH%" (
    echo ERROR: Visual Studio not found
    exit /b 1
)

echo [1/6] Found VS at: %VS_PATH%

:: Find MSVC version
for /f "delims=" %%i in ('dir /b /ad "%VS_PATH%\VC\Tools\MSVC\" 2^>nul ^| sort /r') do (
    set "MSVC_VER=%%i"
    goto :found_msvc
)
:found_msvc
echo [2/6] Found MSVC version: %MSVC_VER%

set "MSVC_ROOT=%VS_PATH%\VC\Tools\MSVC\%MSVC_VER%"

:: Find Windows SDK
set "SDK_PATH=C:\Program Files (x86)\Windows Kits\10"
if not exist "%SDK_PATH%" (
    set "SDK_PATH=D:\Program Files (x86)\Windows Kits\10"
)
set "SDK_VER=10.0.22621.0"

:: Set up paths
set "INCLUDE=%MSVC_ROOT%\include;%SDK_PATH%\Include\%SDK_VER%\ucrt;%SDK_PATH%\Include\%SDK_VER%\shared;%SDK_PATH%\Include\%SDK_VER%\um"
set "LIB=%MSVC_ROOT%\lib\x64;%SDK_PATH%\Lib\%SDK_VER%\ucrt\x64;%SDK_PATH%\Lib\%SDK_VER%\um\x64"
set "PATH=%MSVC_ROOT%\bin\Hostx64\x64;%PATH%"

set "CL_EXE=%MSVC_ROOT%\bin\Hostx64\x64\cl.exe"

echo [3/6] Building GUI Applications...
echo.

:: Build Minimal GUI
cd /d "%~dp0\src\win32app"
echo Building RawrXD_GUI_Minimal.exe...
"%CL_EXE%" /EHsc /O2 /std:c++17 /DUNICODE /D_UNICODE /D_HAS_CXX17=1 /FeRawrXD_GUI_Minimal.exe RawrXD_GUI_Minimal.cpp /link user32.lib gdi32.lib comctl32.lib shell32.lib ole32.lib comdlg32.lib
if errorlevel 1 (
    echo ERROR: Minimal GUI build failed
    exit /b 1
)
echo   [OK] RawrXD_GUI_Minimal.exe

:: Build Enhanced GUI
echo Building RawrXD_GUI_Enhanced.exe...
"%CL_EXE%" /EHsc /O2 /std:c++17 /DUNICODE /D_UNICODE /D_HAS_CXX17=1 /FeRawrXD_GUI_Enhanced.exe RawrXD_GUI_Enhanced.cpp /link user32.lib gdi32.lib comctl32.lib shell32.lib ole32.lib comdlg32.lib
if errorlevel 1 (
    echo   [WARN] Enhanced GUI build failed (optional)
) else (
    echo   [OK] RawrXD_GUI_Enhanced.exe
)

echo.
echo [4/6] Building Test Suite...
echo.

:: Build Tests
cd /d "%~dp0\src\tests"
echo Building RawrXD-InferenceRoutingTest.exe...
"%CL_EXE%" /EHsc /O2 /std:c++17 /D_HAS_CXX17=1 /FeRawrXD-InferenceRoutingTest.exe inference_routing_test.cpp /link
if errorlevel 1 (
    echo   [WARN] Test build failed
) else (
    echo   [OK] RawrXD-InferenceRoutingTest.exe
)

echo.
echo [5/6] Copying to distribution...
echo.

:: Create dist structure
if not exist "%~dp0\dist" mkdir "%~dp0\dist"
if not exist "%~dp0\dist\bin" mkdir "%~dp0\dist\bin"

:: Copy executables
copy /Y "%~dp0\src\win32app\RawrXD_GUI_Minimal.exe" "%~dp0\dist\bin\RawrXD.exe" >nul
echo   [OK] Copied RawrXD.exe

if exist "%~dp0\src\win32app\RawrXD_GUI_Enhanced.exe" (
    copy /Y "%~dp0\src\win32app\RawrXD_GUI_Enhanced.exe" "%~dp0\dist\bin\RawrXD_Enhanced.exe" >nul
    echo   [OK] Copied RawrXD_Enhanced.exe
)

if exist "%~dp0\src\tests\RawrXD-InferenceRoutingTest.exe" (
    copy /Y "%~dp0\src\tests\RawrXD-InferenceRoutingTest.exe" "%~dp0\dist\bin\" >nul
    echo   [OK] Copied RawrXD-InferenceRoutingTest.exe
)

echo.
echo [6/6] Running tests...
echo.

:: Run tests
if exist "%~dp0\dist\bin\RawrXD-InferenceRoutingTest.exe" (
    cd /d "%~dp0\dist\bin"
    RawrXD-InferenceRoutingTest.exe
    if errorlevel 1 (
        echo   [WARN] Some tests failed
    ) else (
        echo   [OK] All tests passed
    )
)

echo.
echo ============================================
echo BUILD COMPLETE
echo ============================================
echo.
echo Output: %~dp0dist\bin\
echo   - RawrXD.exe (Main GUI)
echo   - RawrXD_Enhanced.exe (Optional)
echo   - RawrXD-InferenceRoutingTest.exe (Tests)
echo.
echo Next: Run package\create_distribution.ps1 to create ZIP
echo.

pause
