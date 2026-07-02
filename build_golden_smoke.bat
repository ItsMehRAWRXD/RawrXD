@echo off
REM ============================================================================
REM Golden Build Smoke Test — Build & Run
REM Validates all major subsystems coexist without crashes
REM ============================================================================

echo [SMOKE] RawrXD Golden Build Smoke Test
echo [SMOKE] Date: 2026-06-10
echo.

REM Initialize Visual Studio 2022 Enterprise environment
set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"
set "VCVARSALL=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
if exist "%VCVARSALL%" (
    call "%VCVARSALL%" x64
) else (
    echo [SMOKE] WARNING: VS2022 Enterprise not found, trying default paths
    set "CL_EXE=cl"
    set "LINK_EXE=link"
)

if not exist "%VCVARSALL%" (
    set "CL_EXE=%VS_PATH%\bin\Hostx64\x64\cl.exe"
    set "LINK_EXE=%VS_PATH%\bin\Hostx64\x64\link.exe"
)

set SRC_DIR=%~dp0src
set BUILD_DIR=%~dp0..\build_smoke
set OUT_DIR=%BUILD_DIR%\bin

REM Create output directory
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

REM Windows SDK paths
set "WIN10_SDK=C:\Program Files (x86)\Windows Kits\10"
set "SDK_VER=10.0.22621.0"
set "SDK_INC=%WIN10_SDK%\Include\%SDK_VER%"
set "SDK_LIB=%WIN10_SDK%\Lib\%SDK_VER%"

REM Compiler flags
set CL_FLAGS=/nologo /W3 /EHsc /O2 /MD /std:c++latest /DNDEBUG /DWIN32_LEAN_AND_MEAN /DNOMINMAX
set INCLUDES=/I "%SRC_DIR%" /I "%SRC_DIR%\include" /I "%SRC_DIR%\core" /I "%SRC_DIR%\collab" /I "%SRC_DIR%\modules" /I "%SRC_DIR%\ai" /I "%SRC_DIR%\gpu" /I "%SDK_INC%\ucrt" /I "%SDK_INC%\shared" /I "%SDK_INC%\um"
set LIBPATHS=/LIBPATH:"%SDK_LIB%\ucrt\x64" /LIBPATH:"%SDK_LIB%\um\x64"
set LIBS=kernel32.lib user32.lib gdi32.lib ws2_32.lib winhttp.lib psapi.lib advapi32.lib

REM Source files for smoke test
set SMOKE_SRC=%SRC_DIR%\test_harness\golden_build_smoke_test.cpp
set ARBITER_SRC=%SRC_DIR%\core\resource_arbiter.cpp

REM Object files
set SMOKE_OBJ=%BUILD_DIR%\golden_build_smoke_test.obj
set ARBITER_OBJ=%BUILD_DIR%\resource_arbiter.obj

echo [SMOKE] Building Resource Arbiter...
cl %CL_FLAGS% %INCLUDES% /c "%ARBITER_SRC%" /Fo"%ARBITER_OBJ%"
if errorlevel 1 (
    echo [SMOKE] FAILED: Resource Arbiter compilation failed
    exit /b 1
)

echo [SMOKE] Building Smoke Test...
cl %CL_FLAGS% %INCLUDES% /c "%SMOKE_SRC%" /Fo"%SMOKE_OBJ%"
if errorlevel 1 (
    echo [SMOKE] FAILED: Smoke test compilation failed
    exit /b 1
)

echo [SMOKE] Linking...
link /nologo /SUBSYSTEM:CONSOLE /OUT:"%OUT_DIR%\golden_build_smoke_test.exe" "%SMOKE_OBJ%" "%ARBITER_OBJ%" %LIBS% %LIBPATHS%
if errorlevel 1 (
    echo [SMOKE] FAILED: Linking failed
    exit /b 1
)

echo [SMOKE] Build successful!
echo.
echo [SMOKE] Running tests...
echo.

"%OUT_DIR%\golden_build_smoke_test.exe"
set TEST_RESULT=%errorlevel%

echo.
if %TEST_RESULT% == 0 (
    echo [SMOKE] ALL TESTS PASSED — Golden Build validated!
    exit /b 0
) else (
    echo [SMOKE] TESTS FAILED — See output above for details
    exit /b 1
)
