@echo off

echo ============================================
echo RawrXD Minimal GUI Builder
echo ============================================

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

echo Found VS at: %VS_PATH%

:: Find MSVC version
for /f "delims=" %%i in ('dir /b /ad "%VS_PATH%\VC\Tools\MSVC\" 2^>nul ^| sort /r') do (
    set "MSVC_VER=%%i"
    goto :found_msvc
)
:found_msvc
echo Found MSVC version: %MSVC_VER%

set "MSVC_ROOT=%VS_PATH%\VC\Tools\MSVC\%MSVC_VER%"

:: Find Windows SDK
set "SDK_PATH=C:\Program Files (x86)\Windows Kits\10"
if not exist "%SDK_PATH%" (
    set "SDK_PATH=D:\Program Files (x86)\Windows Kits\10"
)

set "SDK_VER=10.0.22621.0"

echo Found SDK at: %SDK_PATH%

:: Setup environment and build in one cmd session
cd /d "%~dp0\src\win32app"

:: Set up paths directly
set "INCLUDE=%MSVC_ROOT%\include;%SDK_PATH%\Include\%SDK_VER%\ucrt;%SDK_PATH%\Include\%SDK_VER%\shared;%SDK_PATH%\Include\%SDK_VER%\um"
set "LIB=%MSVC_ROOT%\lib\x64;%SDK_PATH%\Lib\%SDK_VER%\ucrt\x64;%SDK_PATH%\Lib\%SDK_VER%\um\x64"
set "PATH=%MSVC_ROOT%\bin\Hostx64\x64;%PATH%"

echo.
echo Building RawrXD_GUI_Minimal.cpp...
echo.

"%MSVC_ROOT%\bin\Hostx64\x64\cl.exe" /EHsc /O2 /std:c++17 /DUNICODE /D_UNICODE /D_HAS_CXX17=1 /FeRawrXD_GUI_Minimal.exe RawrXD_GUI_Minimal.cpp /link user32.lib gdi32.lib comctl32.lib shell32.lib ole32.lib comdlg32.lib

echo.
echo Building RawrXD_GUI_Integrated.cpp...
echo.

"%MSVC_ROOT%\bin\Hostx64\x64\cl.exe" /EHsc /O2 /std:c++17 /DUNICODE /D_UNICODE /D_HAS_CXX17=1 /I"%~dp0\include" /I"%~dp0\src" /FeRawrXD_GUI_Integrated.exe RawrXD_GUI_Integrated.cpp /link user32.lib gdi32.lib comctl32.lib shell32.lib ole32.lib comdlg32.lib winhttp.lib

if errorlevel 1 (
    echo.
    echo WARNING: Integrated build failed - using minimal version only
    echo This is expected if RawrXD headers are not available
)

if errorlevel 1 (
    echo.
    echo ERROR: Build failed
    exit /b 1
)

echo.
echo ============================================
echo Build SUCCESSFUL
echo Output: %CD%\RawrXD_GUI_Minimal.exe
echo ============================================

:: Copy to bin directory
if not exist "%~dp0..\bin" mkdir "%~dp0..\bin"
copy /Y RawrXD_GUI_Minimal.exe "%~dp0..\bin\"

echo.
echo To run: .\bin\RawrXD_GUI_Minimal.exe
