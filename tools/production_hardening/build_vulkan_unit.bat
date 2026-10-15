@echo off
REM ============================================================================
REM Compile-verify a Vulkan-capable translation unit (e.g. src/gguf_loader.cpp,
REM which pulls in vulkan_compute.h).
REM Discovers the Vulkan SDK from VULKAN_SDK so no path is hardcoded.
REM Usage: build_vulkan_unit.bat <source.cpp> [objdir]
REM ============================================================================
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo ERROR: vcvars64.bat failed
    exit /b 1
)

set SRC=%1
if "%SRC%"=="" (
    echo USAGE: build_vulkan_unit.bat ^<source.cpp^> [objdir]
    exit /b 1
)
set OBJDIR=%2
if "%OBJDIR%"=="" set OBJDIR=%TEMP%\kilo\vk_objs

REM Locate the real Vulkan SDK include directory.
set VKINC=%VULKAN_SDK%\Include
if not exist "%VKINC%\vulkan\vulkan.h" (
    echo ERROR: Vulkan SDK not found. Set VULKAN_SDK. ^(looked in "%VKINC%"^)
    exit /b 1
)
echo Using Vulkan SDK: %VKINC%

if not exist "%OBJDIR%" mkdir "%OBJDIR%"

cl.exe /nologo /std:c++20 /EHsc /W4 /permissive- /c /Fo:"%OBJDIR%\\" /I"%CD%\include" /I"%CD%\src\utils" /I"%VKINC%" "%SRC%" 2>&1
set RC=%errorlevel%
echo === exit code: %RC% ===
exit /b %RC%