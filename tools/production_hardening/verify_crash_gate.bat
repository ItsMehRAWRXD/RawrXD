@echo off
REM ============================================================================
REM Gate 3: prove CrashHandler captures a REAL hard crash.
REM A unit test calling reportFatal() cannot prove this - a real fault
REM bypasses C++ unwinding, so it must be observed in a child process.
REM ============================================================================
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 exit /b 1
setlocal enabledelayedexpansion
set ROOT=%CD%
set OBJS=%ROOT%\build_crash_gate\obj
set OUT=%ROOT%\build_crash_gate
if not exist "%OBJS%" mkdir "%OBJS%"

for %%S in (src\utils\crash_handler.cpp tests\crash_probe.cpp) do (
    echo --- CL %%S
    cl.exe /nologo /std:c++20 /EHsc /W4 /permissive- /O2 /Fo:"%OBJS%\%%~nS.obj" /I"%ROOT%\include" /I"%ROOT%\src\utils" /c "%%S" 2>&1
    if errorlevel 1 (
        echo COMPILE FAILED: %%S
        exit /b 1
    )
)

echo --- LINK
link.exe /nologo /SUBSYSTEM:CONSOLE /OUT:"%OUT%\crash_probe.exe" %OBJS%\*.obj dbghelp.lib bcrypt.lib 2>&1
if errorlevel 1 (
    echo LINK FAILED
    exit /b 1
)

echo === Launching child crash probes ===
"%OUT%\crash_probe.exe" parent 2>&1
set RC=%errorlevel%
echo === probe exit code: %RC% ===
exit /b %RC%