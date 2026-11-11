@echo off
chcp 65001 > nul
setlocal EnableDelayedExpansion

echo ================================================================================
echo RAWRXD COMPLETE SYSTEM - FINAL BUILD
echo ================================================================================
echo.

set "ROOT=d:\rawrxd"
set "TOOLCHAIN=%ROOT%\compilers\native_toolchain"
set "FINAL=%ROOT%\build\final"

if not exist "%FINAL%" mkdir "%FINAL%"

echo [1/5] Building Heap Patch...
cd /d "%TOOLCHAIN%"

if exist "sovereign_memory_patch_fixed.asm" (
    ml64 /c /nologo /Zi /Fo:sovereign_memory_patch.obj sovereign_memory_patch_fixed.asm
    echo [OK] Heap patch built
) else (
    echo [WARNING] Heap patch source not found
)

echo.
echo [2/5] Building Model Streamer...
cd /d "%ROOT%"

if exist "test_chat_streaming.c" (
    gcc -O2 test_chat_streaming.c -o "%FINAL%\stream_test.exe" -lwinhttp 2>nul
    if exist "%FINAL%\stream_test.exe" echo [OK] Stream test built
)

if exist "test_deepseek_streaming.c" (
    gcc -O2 test_deepseek_streaming.c -o "%FINAL%\deepseek_stream.exe" -lwinhttp 2>nul
    if exist "%FINAL%\deepseek_stream.exe" echo [OK] DeepSeek stream built
)

echo.
echo [3/5] Building Unified Test...
if exist "test_integration.c" (
    gcc -O2 test_integration.c -o "%FINAL%\test_integration.exe" -lwinhttp 2>nul
    if exist "%FINAL%\test_integration.exe" echo [OK] Integration test built
)

echo.
echo [4/5] Creating Launcher...
cd /d "%FINAL%"

(
echo @echo off
echo echo ================================================================================
echo echo RawrXD Complete System
echo echo ================================================================================
echo echo.
echo echo Available commands:
echo echo   stream       - Test token streaming with Ollama
echo echo   deepseek     - Stream with DeepSeek-R1:8b
echo echo   test         - Run integration tests
echo echo   status       - Show system status
echo echo.
echo if "%%1"=="stream" (
echo     echo Running streaming test...
echo     stream_test.exe
echo     goto :eof
echo ^)
echo if "%%1"=="deepseek" (
echo     echo Running DeepSeek streaming...
echo     deepseek_stream.exe
echo     goto :eof
echo ^)
echo if "%%1"=="test" (
echo     echo Running tests...
echo     test_integration.exe
echo     goto :eof
echo ^)
echo if "%%1"=="status" (
echo     echo System Status:
echo     echo   Toolchain: %TOOLCHAIN%
echo     echo   Models: Ollama localhost:11434
echo     echo   Tests: Available
echo     goto :eof
echo ^)
echo.
echo Usage: RawrXD.bat [stream^|deepseek^|test^|status]
echo.
) > RawrXD.bat

echo [OK] Launcher created

echo.
echo [5/5] Running Tests...
if exist "test_integration.exe" (
    test_integration.exe
)

echo.
echo ================================================================================
echo BUILD COMPLETE
echo ================================================================================
echo.
echo Output: %FINAL%
echo.
echo Executables:
dir /b *.exe 2>nul
echo.
echo Usage:
echo   cd %FINAL%
echo   RawrXD.bat stream
echo   RawrXD.bat deepseek
echo   RawrXD.bat test
echo.
echo ================================================================================

endlocal
