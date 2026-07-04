@echo off
setlocal EnableDelayedExpansion

echo ========================================
echo Setting up VS Environment and Compiling
echo ========================================

REM Find VS installation
set "VS_PATH="
for %%p in (
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional"
    "C:\Program Files\Microsoft Visual Studio\2022\Community"
    "C:\Program Files\Microsoft Visual Studio\18\Enterprise"
    "D:\VS2022Enterprise"
) do (
    if exist "%%~p\VC\Auxiliary\Build\vcvars64.bat" (
        set "VS_PATH=%%~p"
        goto :found_vs
    )
)

:found_vs
if "%VS_PATH%"=="" (
    echo ERROR: Could not find Visual Studio
    exit /b 1
)

echo Found VS at: %VS_PATH%

REM Setup environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat"

if errorlevel 1 (
    echo ERROR: Failed to setup environment
    exit /b 1
)

cd /d d:\rawrxd

echo.
echo Compiling standalone_gguf_test.cpp...
cl.exe /EHsc /W3 /O2 /c standalone_gguf_test.cpp /Fogguf_test.obj

if errorlevel 1 (
    echo Compilation FAILED
    exit /b 1
)

echo Linking...
link.exe /OUT:gguf_test.exe /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup gguf_test.obj kernel32.lib

if errorlevel 1 (
    echo Linking FAILED
    exit /b 1
)

echo.
echo SUCCESS: gguf_test.exe built!
echo.
echo To test with your 40B model:
echo   gguf_test.exe "F:\OllamaModels\Qwen3.5-40B-Claude-4.6-Opus-Deckard-Heretic-Uncensored-Thinking.Q4_K_M.gguf"
