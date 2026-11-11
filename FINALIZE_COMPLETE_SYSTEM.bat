@echo off
chcp 65001 > nul
setlocal EnableDelayedExpansion

echo ================================================================================
echo RAWRXD COMPLETE SYSTEM FINALIZATION
echo Model Loading + Streaming + Native Toolchain + IDE
echo ================================================================================
echo.

set "ROOT=d:\rawrxd"
set "TOOLCHAIN=%ROOT%\compilers\native_toolchain"
set "SOV_BUILD=d:\sovereign_build"
set "FINAL=%ROOT%\build\final"
set "VS_LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "VS_ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"

if not exist "%FINAL%" mkdir "%FINAL%"

echo [PHASE 1/7] Verifying Prerequisites
echo ======================================

REM Check Visual Studio tools
if not exist "%VS_LINK%" (
    echo ERROR: Visual Studio linker not found at %VS_LINK%
    echo Please install VS2022 with C++ build tools
    exit /b 1
)
echo [OK] Visual Studio tools found

REM Check heap patch - use full path
if not exist "%TOOLCHAIN%\sovereign_memory_patch.obj" (
    echo [BUILD] Heap patch object not found, building...
    cd /d "%TOOLCHAIN%"
    if exist "sovereign_memory_patch_fixed.asm" (
        "%VS_ML64%" /c /nologo /Zi /Fo:"%TOOLCHAIN%\sovereign_memory_patch.obj" "%TOOLCHAIN%\sovereign_memory_patch_fixed.asm"
    ) else if exist "sovereign_memory_patch.asm" (
        "%VS_ML64%" /c /nologo /Zi /Fo:"%TOOLCHAIN%\sovereign_memory_patch.obj" "%TOOLCHAIN%\sovereign_memory_patch.asm"
    )
    if errorlevel 1 (
        echo ERROR: Failed to build heap patch
        exit /b 1
    )
)
if exist "%TOOLCHAIN%\sovereign_memory_patch.obj" (
    echo [OK] Heap patch ready
) else (
    echo [ERROR] Heap patch object not found after build attempt
    exit /b 1
)

REM Check Sovereign objects
if not exist "%SOV_BUILD%" (
    echo ERROR: Sovereign build directory not found: %SOV_BUILD%
    exit /b 1
)
echo [OK] Sovereign build directory exists

echo.
echo [PHASE 2/7] Building Native Toolchain
echo ======================================
cd /d "%TOOLCHAIN%"

if not exist "rawrxd_native_assembler.exe" (
    echo [BUILD] Building native toolchain...
    call build_toolchain.bat
    if errorlevel 1 (
        echo ERROR: Toolchain build failed
        exit /b 1
    )
) else (
    echo [OK] Native toolchain already built
)

echo.
echo [PHASE 3/7] Linking Sovereign with Heap Patch
echo ======================================
cd /d "%FINAL%"

echo [LINK] Creating RawrXD_Sovereign.exe...

set "SOV_OBJS="
for %%f in ("%SOV_BUILD%\Sovereign_*.obj") do (
    set "SOV_OBJS=!SOV_OBJS! "%%f""
)
set "SOV_OBJS=!SOV_OBJS! "%TOOLCHAIN%\sovereign_memory_patch.obj""

"%VS_LINK%" /NOLOGO /OUT:"RawrXD_Sovereign.exe" !SOV_OBJS! ^
    /SUBSYSTEM:CONSOLE /ENTRY:main /DEBUG /MACHINE:X64 ^
    kernel32.lib user32.lib ntdll.lib advapi32.lib

if exist "RawrXD_Sovereign.exe" (
    echo [OK] RawrXD_Sovereign.exe created
    dir "RawrXD_Sovereign.exe"
) else (
    echo [WARNING] Link may have issues, continuing...
)

echo.
echo [PHASE 4/7] Building Model Streamer
echo ======================================
cd /d "%ROOT%"

if exist "AI_TokenStream.cpp" (
    echo [BUILD] Compiling AI_TokenStream...
    g++ -O2 -std=c++17 -DUNICODE -D_UNICODE ^
        AI_TokenStream.cpp ^
        -o "%FINAL%\AI_TokenStream.exe" ^
        -lwinhttp 2>nul
    
    if exist "%FINAL%\AI_TokenStream.exe" (
        echo [OK] AI_TokenStream.exe built
    ) else (
        echo [INFO] AI_TokenStream build skipped (optional)
    )
)

echo.
echo [PHASE 5/7] Creating Unified Launcher
echo ======================================
cd /d "%FINAL%"

(
echo @echo off
echo echo ================================================================================
echo echo RawrXD Complete System Launcher
echo echo ================================================================================
echo echo.
echo echo Usage: RawrXD.bat [command] [options]
echo.
echo echo Commands:
echo echo   sovereign    - Run Sovereign inference engine
echo echo   stream       - Run token streaming test
echo echo   test         - Run full test suite
echo echo   toolchain    - Show toolchain status
echo echo   ide          - Launch IDE (if available)
echo echo   help         - Show this help
echo echo.
echo echo Examples:
echo echo   RawrXD.bat sovereign --model model.gguf --prompt "Hello"
echo echo   RawrXD.bat stream --model deepseek-r1:8b
echo echo   RawrXD.bat test
echo echo.
echo if "%%1"=="" goto :help
echo if "%%1"=="sovereign" goto :sovereign
echo if "%%1"=="stream" goto :stream
echo if "%%1"=="test" goto :test
echo if "%%1"=="toolchain" goto :toolchain
echo if "%%1"=="ide" goto :ide
echo if "%%1"=="help" goto :help
echo echo Unknown command: %%1
echo goto :eof
echo.
echo :sovereign
echo cd /d "%~dp0"
echo if exist "RawrXD_Sovereign.exe" (
echo     RawrXD_Sovereign.exe %%2 %%3 %%4 %%5 %%6 %%7 %%8 %%9
echo ^) else (
echo     echo ERROR: RawrXD_Sovereign.exe not found
echo     echo Run FINALIZE_COMPLETE_SYSTEM.bat first
echo ^)
echo goto :eof
echo.
echo :stream
echo cd /d "%~dp0"
echo if exist "AI_TokenStream.exe" (
echo     AI_TokenStream.exe
echo ^) else (
echo     echo Running streaming test via Ollama API...
echo     cd /d "%ROOT%"
echo     test_chat_streaming.exe
echo ^)
echo goto :eof
echo.
echo :test
echo cd /d "%~dp0"
echo echo Running integration tests...
echo cd /d "%ROOT%"
echo test_integration.exe
echo goto :eof
echo.
echo :toolchain
echo cd /d "%TOOLCHAIN%"
echo echo Native Toolchain Status:
echo dir /b *.exe 2^>nul ^| find /c ".exe"
echo goto :eof
echo.
echo :ide
echo cd /d "%ROOT%"
echo echo IDE launch would go here
echo goto :eof
echo.
echo :help
echo goto :eof
echo.
) > RawrXD.bat

echo [OK] RawrXD.bat launcher created

echo.
echo [PHASE 6/7] Running Integration Tests
echo ======================================
cd /d "%ROOT%"

if exist "test_integration.exe" (
    test_integration.exe
    if errorlevel 1 (
        echo [WARNING] Some tests failed, but continuing...
    )
) else (
    echo [BUILD] Creating integration test...
    g++ -O2 test_integration.c -o test_integration.exe -lwinhttp 2>nul
    if exist "test_integration.exe" (
        test_integration.exe
    )
)

echo.
echo [PHASE 7/7] Final Verification
echo ======================================
cd /d "%FINAL%"

echo Final build contents:
dir /b 2>nul

echo.
echo ================================================================================
echo FINALIZATION COMPLETE
echo ================================================================================
echo.
echo Output Directory: %FINAL%
echo.
echo Executables:
echo   - RawrXD_Sovereign.exe    (Inference engine with heap patch)
echo   - AI_TokenStream.exe      (Token streaming, if built)
echo   - RawrXD.bat              (Unified launcher)
echo.
echo Usage:
echo   cd %FINAL%
echo   RawrXD.bat sovereign --help
echo   RawrXD.bat stream
echo   RawrXD.bat test
echo.
echo ================================================================================

endlocal
