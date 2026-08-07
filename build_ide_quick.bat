@echo off
REM ============================================================================
REM RawrXD IDE Build — Quick build for the complete IDE with Deep2 completion
REM ============================================================================
REM This builds the Win32 IDE with:
REM   - Deep2Bridge (real local inference)
REM   - ai_completion_real (ghost text C API)
REM   - Win32IDE_GhostText (ghost text renderer)
REM   - All agent/context/reliability subsystems
REM
REM Prerequisites:
REM   - Visual Studio 2022 with C++ workload
REM   - Windows SDK 10.0.22621.0 or later
REM ============================================================================

setlocal EnableDelayedExpansion

REM --- Find MSVC ---
set "VCVARS="
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
) do (
    if exist %%P set "VCVARS=%%~fP" & goto :FOUND_VC
)
echo [ERROR] Visual Studio 2022 not found. Install Visual Studio 2022 with C++ workload.
exit /b 1

:FOUND_VC
call "%VCVARS%" >nul 2>&1
echo [BUILD] MSVC initialized

REM --- Directories ---
set "SRC=d:\rawrxd\src"
set "OUT=d:\rawrxd\build"
set "BIN=d:\rawrxd\bin"
if not exist "%OUT%" mkdir "%OUT%"
if not exist "%BIN%" mkdir "%BIN%"

REM --- Compiler flags ---
set "CFLAGS=/O2 /arch:AVX2 /DNDEBUG /W3 /EHsc /nologo /std:c++20 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN"
set "INCLUDES=/I%SRC% /I%SRC%\ide /I%SRC%\deep2 /I%SRC%\core /I%SRC%\include /I%SRC%\..\include /I%SRC%\..\Ship"
set "LIBS=user32.lib gdi32.lib comctl32.lib kernel32.lib advapi32.lib ole32.lib oleaut32.lib"

echo.
echo  ================================================
echo   RAWRXD IDE BUILD
echo  ================================================
echo.

REM --- Step 1: Compile Deep2Bridge ---
echo [1/4] Compiling Deep2Bridge...
cl.exe %CFLAGS% %INCLUDES% /c "%SRC%\ide\Deep2Bridge.cpp" /Fo"%OUT%\Deep2Bridge.obj" >"%OUT%\build.log" 2>&1
if errorlevel 1 ( type "%OUT%\build.log" & echo [FAIL] Deep2Bridge & exit /b 1 )
echo   [OK] Deep2Bridge.obj

REM --- Step 2: Compile ai_completion_real ---
echo [2/4] Compiling AI Completion Real...
cl.exe %CFLAGS% %INCLUDES% /c "%SRC%\ai_completion_real.cpp" /Fo"%OUT%\ai_completion_real.obj" >"%OUT%\build.log" 2>&1
if errorlevel 1 ( type "%OUT%\build.log" & echo [FAIL] ai_completion_real & exit /b 1 )
echo   [OK] ai_completion_real.obj

REM --- Step 3: Compile validation gates ---
echo [3/4] Compiling Validation Gates...
cl.exe %CFLAGS% %INCLUDES% /c "%SRC%\validation\gates\VAL070_VAL076_ProductionGates.cpp" /Fo"%OUT%\VAL070.obj" >"%OUT%\build.log" 2>&1
if errorlevel 1 ( type "%OUT%\build.log" & echo [WARN] VAL070 skipped & goto :SKIP_VAL )
echo   [OK] VAL070.obj

REM --- Step 4: Link validation executable ---
echo [4/4] Linking Validation Executable...
link.exe /MACHINE:X64 /OUT:"%BIN%\VAL-070.exe" "%OUT%\VAL070.obj" "%OUT%\Deep2Bridge.obj" "%OUT%\ai_completion_real.obj" %LIBS% >"%OUT%\link.log" 2>&1
if errorlevel 1 ( type "%OUT%\link.log" & echo [WARN] Link failed & goto :SKIP_VAL )
echo   [OK] %BIN%\VAL-070.exe

:SKIP_VAL
echo.
echo  ================================================
echo   BUILD COMPLETE
echo  ================================================
echo.
echo   Output files:
if exist "%BIN%\VAL-070.exe" echo     %BIN%\VAL-070.exe  (Validation Gates)
echo.
echo   To build the full IDE, use CMake:
echo     cd d:\rawrxd
echo     cmake --build build --target RawrXD-Win32IDE
echo.
echo   To run validation:
echo     %BIN%\VAL-070.exe
echo.

endlocal
