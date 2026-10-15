@echo off
REM ============================================================================
REM Build + run the GGUFLoader hardening integration tests.
REM ============================================================================
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo ERROR: vcvars64.bat failed
    exit /b 1
)
setlocal enabledelayedexpansion
set ROOT=%CD%
set VKINC=%VULKAN_SDK%\Include
if not exist "%VKINC%\vulkan\vulkan.h" (
    echo ERROR: Vulkan SDK not found ^(VULKAN_SDK^)
    exit /b 1
)
set OBJS=%ROOT%\build_loader_tests\obj
set OUT=%ROOT%\build_loader_tests
if not exist "%OBJS%" mkdir "%OBJS%"

REM Link the REAL vocab resolver rather than stubbing it: the loader's
REM ParseMetadata() genuinely calls it, so stubbing would test fiction.
set SOURCES=src\utils\input_sanitizer.cpp src\utils\secure_buffer.cpp src\utils\crash_handler.cpp src\gguf_loader.cpp src\gguf_vocab_resolver.cpp tests\test_input_sanitizer.cpp tests\test_gguf_loader_hardening.cpp tests\test_crash_resilience.cpp tests\main_hardening_tests.cpp

for %%S in (%SOURCES%) do (
    echo --- CL %%S
    cl.exe /nologo /std:c++20 /EHsc /W4 /permissive- /O2 /Fo:"%OBJS%\%%~nS.obj" /I"%ROOT%\include" /I"%ROOT%\tests" /I"%ROOT%\src\utils" /I"%VKINC%" /c "%%S" 2>&1
    if errorlevel 1 (
        echo COMPILE FAILED: %%S
        exit /b 1
    )
)

echo --- LINK
link.exe /nologo /SUBSYSTEM:CONSOLE /OUT:"%OUT%\loader_hardening_tests.exe" %OBJS%\*.obj dbghelp.lib bcrypt.lib /LIBPATH:"%VULKAN_SDK%\Lib" vulkan-1.lib 2>&1
if errorlevel 1 (
    echo LINK FAILED
    exit /b 1
)

echo === RUN ===
"%OUT%\loader_hardening_tests.exe" 2>&1
set RC=%errorlevel%
echo === exit code: %RC% ===
exit /b %RC%