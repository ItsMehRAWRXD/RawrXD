@echo off
:: RawrXD Browser Build Script
:: Zero-dependency browser using only Win32 APIs

echo ===========================================
echo RawrXD Browser - Zero Dependency Build
echo ===========================================
echo.

set "SRC_DIR=%~dp0"
set "OBJ_DIR=%SRC_DIR%obj"
set "BIN_DIR=%SRC_DIR%bin"

:: Create directories
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

:: Find Visual Studio
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VS_PATH=%%i"
    )
)

if not defined VS_PATH (
    echo ERROR: Visual Studio not found!
    exit /b 1
)

echo Found Visual Studio at: %VS_PATH%

:: Setup environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64 > nul 2>&1

:: Compiler flags
set "CFLAGS=/nologo /W3 /O2 /MD /EHsc /std:c++17"
set "DEFINES=/DUNICODE /D_UNICODE /DWIN32 /D_WINDOWS"
set "INCLUDES=/I"%SRC_DIR%""
set "LDFLAGS=/SUBSYSTEM:WINDOWS /MACHINE:X64"
set "LIBS=winhttp.lib gdi32.lib user32.lib shell32.lib ole32.lib"

echo.
echo Compiling...
echo.

:: Compile source files
cl.exe %CFLAGS% %DEFINES% /I"%SRC_DIR%" /c /Fo"%OBJ_DIR%\RawrXD_Browser.obj" "%SRC_DIR%RawrXD_Browser.cpp"
if errorlevel 1 goto :error

cl.exe %CFLAGS% %DEFINES% /I"%SRC_DIR%" /c /Fo"%OBJ_DIR%\RawrXD_BrowserWindow.obj" "%SRC_DIR%RawrXD_BrowserWindow.cpp"
if errorlevel 1 goto :error

cl.exe %CFLAGS% %DEFINES% /I"%SRC_DIR%" /c /Fo"%OBJ_DIR%\RawrXD_Browser_Main.obj" "%SRC_DIR%RawrXD_Browser_Main.cpp"
if errorlevel 1 goto :error

echo.
echo Linking...
echo.

:: Link executable
link.exe %LDFLAGS% /OUT:"%BIN_DIR%\RawrXD_Browser.exe" ^
    "%OBJ_DIR%\RawrXD_Browser.obj" ^
    "%OBJ_DIR%\RawrXD_BrowserWindow.obj" ^
    "%OBJ_DIR%\RawrXD_Browser_Main.obj" ^
    %LIBS%

if errorlevel 1 goto :error

echo.
echo ===========================================
echo Build SUCCESSFUL!
echo ===========================================
echo.
echo Executable: %BIN_DIR%\RawrXD_Browser.exe
echo.
echo Usage:
echo   RawrXD_Browser.exe [URL]
echo.
echo Examples:
echo   RawrXD_Browser.exe
echo   RawrXD_Browser.exe example.com
echo   RawrXD_Browser.exe https://raw.githubusercontent.com
echo.

exit /b 0

:error
echo.
echo ===========================================
echo Build FAILED!
echo ===========================================
exit /b 1
