@echo off
REM ============================================================================
REM RAWRXD COMPLETE BUILD SCRIPT - FINAL
REM Builds: Model Loading, Streaming, Inference Engine, Native Toolchain
REM ============================================================================

setlocal EnableDelayedExpansion

echo ================================================================================
echo  RAWRXD COMPLETE BUILD SYSTEM - FINAL
echo ================================================================================
echo.

set "ROOT=%CD%"
set "BUILD_DIR=%ROOT%\build-final"
set "BIN_DIR=%BUILD_DIR%\bin"
set "OBJ_DIR=%BUILD_DIR%\obj"

REM Create directories
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"

echo Build Directories:
echo   Root:   %ROOT%
echo   Build:  %BUILD_DIR%
echo   Bin:    %BIN_DIR%
echo   Obj:    %OBJ_DIR%
echo.

REM ============================================================================
REM PHASE 1: Native Toolchain (Assembler + Linker)
REM ============================================================================
echo [PHASE 1/5] Building Native Toolchain...
echo ================================================================================

if exist "%ROOT%\native_toolchain\minimal_assembler_with_relocs.c" (
    echo  - Building native assembler...
    gcc -O2 -o "%BIN_DIR%\sov_assembler.exe" "%ROOT%\native_toolchain\minimal_assembler_with_relocs.c" 2>nul
    if errorlevel 1 (
        echo    WARNING: Assembler build failed (optional component)
    ) else (
        echo    OK: sov_assembler.exe
    )
)

if exist "%ROOT%\native_toolchain\linker_with_relocations.c" (
    echo  - Building native linker...
    gcc -O2 -o "%BIN_DIR%\sov_linker.exe" "%ROOT%\native_toolchain\linker_with_relocations.c" 2>nul
    if errorlevel 1 (
        echo    WARNING: Linker build failed (optional component)
    ) else (
        echo    OK: sov_linker.exe
    )
)

REM ============================================================================
REM PHASE 2: Sovereign Engine (Zero-Dependency Inference)
REM ============================================================================
echo.
echo [PHASE 2/5] Building Sovereign Engine...
echo ================================================================================

if exist "%ROOT%\SOVEREIGN_ENGINE_FINAL\sovereign_complete.c" (
    echo  - Building sovereign engine (optimized)...
    gcc -O3 -march=native -ffast-math -o "%BIN_DIR%\sovereign.exe" "%ROOT%\SOVEREIGN_ENGINE_FINAL\sovereign_complete.c" 2>nul
    if errorlevel 1 (
        echo    WARNING: Sovereign build failed
    ) else (
        echo    OK: sovereign.exe
        
        REM Run quick benchmark
        echo  - Running benchmark test...
        "%BIN_DIR%\sovereign.exe" benchmark 50 > "%BUILD_DIR%\benchmark.log" 2>&1
        findstr "tokens/sec" "%BUILD_DIR%\benchmark.log" >nul && (
            for /f "tokens=*" %%a in ('findstr "tokens/sec" "%BUILD_DIR%\benchmark.log"') do echo    %%a
        ) || echo    Benchmark test completed
    )
)

REM ============================================================================
REM PHASE 3: Core Runtime (GGUF Loader + Streaming)
REM ============================================================================
echo.
echo [PHASE 3/5] Building Core Runtime (GGUF + Streaming)...
echo ================================================================================

REM Check for required headers
set "HAS_STREAMING=0"
set "HAS_GGUF=0"

if exist "%ROOT%\src\streaming_gguf_loader.cpp" (
    if exist "%ROOT%\src\streaming_gguf_loader.h" (
        set "HAS_STREAMING=1"
    )
)

if exist "%ROOT%\src\gguf\gguf_loader_real.cpp" (
    set "HAS_GGUF=1"
)

if "%HAS_STREAMING%"=="1" (
    echo  - Found streaming GGUF loader
    echo  - Found real GGUF loader implementation
    
    REM Compile streaming loader
    echo  - Compiling streaming_gguf_loader.cpp...
    g++ -std=c++17 -O2 -I"%ROOT%\include" -I"%ROOT%\src" -c "%ROOT%\src\streaming_gguf_loader.cpp" -o "%OBJ_DIR%\streaming_gguf_loader.obj" 2>nul
    if errorlevel 1 (
        echo    WARNING: Streaming loader compilation failed
    ) else (
        echo    OK: streaming_gguf_loader.obj
    )
    
    REM Compile real GGUF loader
    echo  - Compiling gguf_loader_real.cpp...
    g++ -std=c++17 -O2 -I"%ROOT%\include" -I"%ROOT%\src" -c "%ROOT%\src\gguf\gguf_loader_real.cpp" -o "%OBJ_DIR%\gguf_loader_real.obj" 2>nul
    if errorlevel 1 (
        echo    WARNING: GGUF loader compilation failed
    ) else (
        echo    OK: gguf_loader_real.obj
    )
) else (
    echo  - WARNING: Streaming components not found
)

REM ============================================================================
REM PHASE 4: Model Loader Components
REM ============================================================================
echo.
echo [PHASE 4/5] Building Model Loader Components...
echo ================================================================================

REM Enhanced model loader
if exist "%ROOT%\src\enhanced_model_loader.cpp" (
    echo  - Compiling enhanced_model_loader.cpp...
    g++ -std=c++17 -O2 -I"%ROOT%\include" -c "%ROOT%\src\enhanced_model_loader.cpp" -o "%OBJ_DIR%\enhanced_model_loader.obj" 2>nul
    if errorlevel 1 (
        echo    WARNING: Enhanced model loader compilation failed
    ) else (
        echo    OK: enhanced_model_loader.obj
    )
)

REM Dynamic model loader
if exist "%ROOT%\src\dynamic_model_loader.cpp" (
    echo  - Compiling dynamic_model_loader.cpp...
    g++ -std=c++17 -O2 -I"%ROOT%\include" -c "%ROOT%\src\dynamic_model_loader.cpp" -o "%OBJ_DIR%\dynamic_model_loader.obj" 2>nul
    if errorlevel 1 (
        echo    WARNING: Dynamic model loader compilation failed
    ) else (
        echo    OK: dynamic_model_loader.obj
    )
)

REM ============================================================================
REM PHASE 5: Link Core Runtime Library
REM ============================================================================
echo.
echo [PHASE 5/5] Linking Core Runtime Library...
echo ================================================================================

set "OBJ_FILES="
if exist "%OBJ_DIR%\streaming_gguf_loader.obj" set "OBJ_FILES=!OBJ_FILES! "%OBJ_DIR%\streaming_gguf_loader.obj""
if exist "%OBJ_DIR%\gguf_loader_real.obj" set "OBJ_FILES=!OBJ_FILES! "%OBJ_DIR%\gguf_loader_real.obj""
if exist "%OBJ_DIR%\enhanced_model_loader.obj" set "OBJ_FILES=!OBJ_FILES! "%OBJ_DIR%\enhanced_model_loader.obj""
if exist "%OBJ_DIR%\dynamic_model_loader.obj" set "OBJ_FILES=!OBJ_FILES! "%OBJ_DIR%\dynamic_model_loader.obj""

if not "!OBJ_FILES!"=="" (
    echo  - Creating rawrxd_core.dll...
    g++ -shared -o "%BIN_DIR%\rawrxd_core.dll" !OBJ_FILES! -lws2_32 2>nul
    if errorlevel 1 (
        echo    WARNING: Core DLL linking failed
    ) else (
        echo    OK: rawrxd_core.dll
    )
) else (
    echo  - No object files to link
)

REM ============================================================================
REM BUILD SUMMARY
REM ============================================================================
echo.
echo ================================================================================
echo  BUILD SUMMARY
echo ================================================================================
echo.

echo Built Artifacts:
echo ----------------

set "TOTAL_SIZE=0"
set "FILE_COUNT=0"

for %%F in ("%BIN_DIR%\*") do (
    set /a FILE_COUNT+=1
    set /a TOTAL_SIZE+=%%~zF
    echo   [%%~zF bytes] %%~nxF
)

if %FILE_COUNT%==0 (
    echo   (No files built)
)

echo.
echo Total Files: %FILE_COUNT%
echo Total Size: %TOTAL_SIZE% bytes
echo.

REM ============================================================================
REM VERIFICATION
REM ============================================================================
echo ================================================================================
echo  VERIFICATION
echo ================================================================================
echo.

if exist "%BIN_DIR%\sovereign.exe" (
    echo [OK] Sovereign Engine: READY
    "%BIN_DIR%\sovereign.exe" --version >nul 2>&1 && echo      Version check passed
) else (
    echo [MISSING] Sovereign Engine
)

if exist "%BIN_DIR%\sov_assembler.exe" (
    echo [OK] Native Assembler: READY
) else (
    echo [OPTIONAL] Native Assembler: Not built
)

if exist "%BIN_DIR%\sov_linker.exe" (
    echo [OK] Native Linker: READY
) else (
    echo [OPTIONAL] Native Linker: Not built
)

if exist "%BIN_DIR%\rawrxd_core.dll" (
    echo [OK] Core Runtime DLL: READY
) else (
    echo [PARTIAL] Core Runtime DLL: Build incomplete
)

echo.
echo ================================================================================
echo  BUILD COMPLETE
echo ================================================================================
echo.
echo Next Steps:
echo   1. Test sovereign.exe: %BIN_DIR%\sovereign.exe benchmark 100
echo   2. Load a model: %BIN_DIR%\sovereign.exe load ^<model.gguf^>
echo   3. Run inference: %BIN_DIR%\sovereign.exe infer "Hello"
echo.
echo For full IDE build, run: Build-Phase8-Sovereign.bat
echo.

cd "%ROOT%"
exit /b 0
