@echo off
REM Titan Engine MASM64 Build Script
REM Compiles the assembly and C++ test harness, then links them together

setlocal enabledelayedexpansion

echo ========================================
echo Titan Engine MASM64 Build Script
echo ========================================
echo.

REM Set up Visual Studio environment
set "VS_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717"
set "ML64=%VS_PATH%\bin\Hostx64\x64\ml64.exe"
set "CL=%VS_PATH%\bin\Hostx64\x64\cl.exe"
set "LINK=%VS_PATH%\bin\Hostx64\x64\link.exe"

REM Source and output paths
set "ASM_SRC=d:\rawrxd\src\agentic\RawrXD_Absolutely_Complete.asm"
set "CPP_SRC=d:\rawrxd\src\agentic\titan_test_harness.cpp"
set "OBJ_DIR=d:\rawrxd\src\agentic"
set "ASM_OBJ=%OBJ_DIR%\titan_engine.obj"
set "CPP_OBJ=%OBJ_DIR%\titan_test_harness.obj"
set "EXE_OUT=%OBJ_DIR%\TitanTest.exe"

echo [STEP 1] Assembling MASM64 source...
echo   Source: %ASM_SRC%
echo   Output: %ASM_OBJ%

"%ML64%" /c /nologo /W3 /Fo %ASM_OBJ% %ASM_SRC%
if errorlevel 1 (
    echo.
    echo ERROR: Assembly failed!
    exit /b 1
)
echo   Assembly successful.
echo.

echo [STEP 2] Compiling C++ test harness...
echo   Source: %CPP_SRC%
echo   Output: %CPP_OBJ%

"%CL%" /c /EHsc /nologo /W3 /Fo %CPP_OBJ% %CPP_SRC%
if errorlevel 1 (
    echo.
    echo ERROR: C++ compilation failed!
    exit /b 1
)
echo   Compilation successful.
echo.

echo [STEP 3] Linking executable...
echo   Objects: %ASM_OBJ%, %CPP_OBJ%
echo   Output: %EXE_OUT%

"%LINK%" /NOLOGO /SUBSYSTEM:CONSOLE /MACHINE:X64 /OUT %EXE_OUT% %ASM_OBJ% %CPP_OBJ% kernel32.lib ntdll.lib
if errorlevel 1 (
    echo.
    echo ERROR: Linking failed!
    exit /b 1
)
echo   Linking successful.
echo.

echo ========================================
echo BUILD COMPLETE
echo ========================================
echo.
echo Executable: %EXE_OUT%
echo.
echo To run the tests:
echo   %EXE_OUT%
echo.

endlocal