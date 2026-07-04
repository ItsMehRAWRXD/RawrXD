@echo off
setlocal

REM Find VS2022 Enterprise
set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
if not exist "%VS_PATH%" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise"
)

if not exist "%VS_PATH%" (
    echo ERROR: Visual Studio not found
    exit /b 1
)

REM Setup environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

if errorlevel 1 (
    echo ERROR: Failed to setup VC environment
    exit /b 1
)

cd /d d:\rawrxd

echo Compiling test_gguf_loader.exe...
cl.exe /EHsc /W3 /O2 /I. /Isrc /Iinclude ^
    test_gguf_loader_console.cpp ^
    src\streaming_gguf_loader.cpp ^
    src\gguf_loader.cpp ^
    /Fe:test_gguf_loader.exe ^
    /link

if errorlevel 1 (
    echo FAILED to compile
    exit /b 1
)

echo SUCCESS: test_gguf_loader.exe built
