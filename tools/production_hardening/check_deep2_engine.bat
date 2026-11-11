@echo off
REM ============================================================================
REM Compile-verify src/deep2/Deep2Engine.cpp (the Logf_ blocker).
REM Discovers its include roots the same way the in-tree build does.
REM Usage: check_deep2_engine.bat
REM ============================================================================
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 exit /b 1

set ROOT=%CD%
set VKINC=%VULKAN_SDK%\Include
set OBJDIR=%ROOT%\build_deep2_check\obj
if not exist "%OBJDIR%" mkdir "%OBJDIR%"

echo === CL src\deep2\Deep2Engine.cpp (target: Logf_ resolves) ===
cl.exe /nologo /std:c++20 /EHsc /W4 /permissive- /c /Fo:"%OBJDIR%\\" /I"%ROOT%\include" /I"%ROOT%\src" /I"%ROOT%\tools\deep2_debugger" /I"%ROOT%\src\deep2" /I"%ROOT%\src\utils" /I"%ROOT%\src\ui" /I"%ROOT%\src\qtapp" /I"%VKINC%" src\deep2\Deep2Engine.cpp 2>&1
set RC=%errorlevel%
echo === exit code: %RC% ===
exit /b %RC%