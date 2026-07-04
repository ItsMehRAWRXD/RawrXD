@echo off
setlocal EnableDelayedExpansion

echo ========================================
echo Compiling Standalone GGUF Test
echo ========================================

REM Try to find cl.exe
set "CL_PATH="

REM Check common VS2022 locations
for %%p in (
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC"
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC"
    "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC"
    "D:\VS2022Enterprise\VC\Tools\MSVC"
) do (
    if exist "%%~p" (
        for /f "delims=" %%v in ('dir /b /ad "%%~p" 2^>nul ^| sort /r') do (
            set "CL_PATH=%%~p\%%v\bin\Hostx64\x64\cl.exe"
            if exist "!CL_PATH!" goto :found_cl
        )
    )
)

:found_cl
if not exist "%CL_PATH%" (
    echo ERROR: Could not find cl.exe
    echo Please run this from a Visual Studio Developer Command Prompt
    exit /b 1
)

echo Found compiler: %CL_PATH%

cd /d d:\rawrxd

echo.
echo Compiling standalone_gguf_test.cpp...
"%CL_PATH%" /EHsc /W3 /O2 /Fe:gguf_test.exe standalone_gguf_test.cpp

if errorlevel 1 (
    echo FAILED to compile
    exit /b 1
)

echo.
echo SUCCESS: gguf_test.exe built
echo.
echo To test with your 40B model:
echo   gguf_test.exe "F:\OllamaModels\Qwen3.5-40B-Claude-4.6-Opus-Deckard-Heretic-Uncensored-Thinking.Q4_K_M.gguf"
