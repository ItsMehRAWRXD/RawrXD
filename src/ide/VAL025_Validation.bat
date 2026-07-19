@echo off
REM VAL-025 IDE Integration Validation
REM ==================================
REM Proves operational convergence of RawrXD IDE platform

setlocal enabledelayedexpansion

echo ========================================
echo VAL-025 IDE INTEGRATION VALIDATION
echo ========================================
echo.

set VAL025_START_TIME=%date% %time%
set VAL025_RESULT=UNKNOWN
set VAL025_PHASE=INIT

REM Create validation log
set VAL025_LOG=val025_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.log
set VAL025_LOG=%VAL025_LOG: =0%
echo VAL-025 Validation Log > %VAL025_LOG%
echo Started: %VAL025_START_TIME% >> %VAL025_LOG%
echo. >> %VAL025_LOG%

REM ============================================================
REM PHASE 1 - Build Integrity
echo [PHASE 1] Build Integrity
echo [PHASE 1] Build Integrity >> %VAL025_LOG%
echo ========================================= >> %VAL025_LOG%

set PHASE1_RESULT=FAIL

REM Check for compiler
where cl >nul 2>nul
if errorlevel 1 (
    echo   ERROR: Visual Studio compiler not found
    echo   ERROR: Visual Studio compiler not found >> %VAL025_LOG%
    goto :validation_failed
)
echo   [OK] Compiler found

REM Build IDE
echo   Building IDE...
cl /W4 /O2 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /nologo ^
    RawrXD_IDE_Win32.cpp /FeRawrXD_IDE_VAL025.exe ^
    /link /subsystem:windows /entry:wWinMainCRTStartup ^
    user32.lib gdi32.lib comctl32.lib comdlg32.lib shell32.lib shlwapi.lib advapi32.lib ole32.lib

if errorlevel 1 (
    echo   ERROR: Build failed
    echo   ERROR: Build failed >> %VAL025_LOG%
    goto :validation_failed
)

echo   [OK] Build successful
echo   [OK] Build successful >> %VAL025_LOG%

REM Verify executable exists and has content
if not exist RawrXD_IDE_VAL025.exe (
    echo   ERROR: Executable not found
    echo   ERROR: Executable not found >> %VAL025_LOG%
    goto :validation_failed
)

for %%F in (RawrXD_IDE_VAL025.exe) do (
    set EXE_SIZE=%%~zF
    echo   [OK] Executable size: !EXE_SIZE! bytes
    echo   [OK] Executable size: !EXE_SIZE! bytes >> %VAL025_LOG%
)

REM Generate hash
for /f "tokens=*" %%H in ('certutil -hashfile RawrXD_IDE_VAL025.exe SHA256 ^| findstr /v "hash" ^| findstr /v "CertUtil"') do (
    set EXE_HASH=%%H
    set EXE_HASH=!EXE_HASH: =!
)
echo   [OK] SHA256: !EXE_HASH:~0,64!
echo   [OK] SHA256: !EXE_HASH:~0,64! >> %VAL025_LOG%

set PHASE1_RESULT=PASS

REM ============================================================
REM PHASE 2 - Editor Runtime (Manual Verification Required)
echo.
echo [PHASE 2] Editor Runtime
echo [PHASE 2] Editor Runtime >> %VAL025_LOG%
echo ========================================= >> %VAL025_LOG%
echo   STATUS: MANUAL VERIFICATION REQUIRED
echo   STATUS: MANUAL VERIFICATION REQUIRED >> %VAL025_LOG%
echo.
echo   Instructions:
echo   1. Launch: RawrXD_IDE_VAL025.exe
echo   2. Create new file: test.asm
echo   3. Type the following code:
echo.
echo   .data
echo   msg db "RawrXD",0
echo.
echo   .code
echo   main proc
echo       ret
echo   main endp
echo   end
echo.
echo   4. Verify: characters render, cursor moves, file saves
echo.
echo   Press any key when ready to continue...
pause >nul

set PHASE2_RESULT=MANUAL

REM ============================================================
REM PHASE 3 - Native IntelliSense Proof
echo.
echo [PHASE 3] Native IntelliSense
echo [PHASE 3] Native IntelliSense >> %VAL025_LOG%
echo ========================================= >> %VAL025_LOG%
echo   STATUS: MANUAL VERIFICATION REQUIRED
echo   STATUS: MANUAL VERIFICATION REQUIRED >> %VAL025_LOG%
echo.
echo   Prerequisites:
echo   - Ollama is OFF
echo   - Network is disconnected
echo   - External LSP is OFF
echo.
echo   Instructions:
echo   1. Load a GGUF model via MoE -^> Load Model
echo   2. Open any .asm or .cpp file
echo   3. Press Ctrl+Space
echo   4. Verify completion appears WITHOUT Ollama
echo.
echo   Expected: Native completion via CPUInferenceEngine
echo.
echo   Press any key when ready to continue...
pause >nul

set PHASE3_RESULT=MANUAL

REM ============================================================
REM PHASE 4 - Language Intelligence
echo.
echo [PHASE 4] Language Intelligence
echo [PHASE 4] Language Intelligence >> %VAL025_LOG%
echo ========================================= >> %VAL025_LOG%
echo   STATUS: MANUAL VERIFICATION REQUIRED
echo   STATUS: MANUAL VERIFICATION REQUIRED >> %VAL025_LOG%
echo.
echo   Instructions:
echo   1. Create test.cpp with:
echo.
echo   class Engine {
echo   public:
echo       void Start();
echo   };
echo.
echo   Engine e;
echo   e.
echo.
echo   2. Trigger completion after "e."
echo   3. Verify "Start()" appears in suggestions
echo.
echo   Press any key when ready to continue...
pause >nul

set PHASE4_RESULT=MANUAL

REM ============================================================
REM PHASE 5 - Build Pipeline
echo.
echo [PHASE 5] Build Pipeline
echo [PHASE 5] Build Pipeline >> %VAL025_LOG%
echo ========================================= >> %VAL025_LOG%
echo   STATUS: MANUAL VERIFICATION REQUIRED
echo   STATUS: MANUAL VERIFICATION REQUIRED >> %VAL025_LOG%
echo.
echo   Instructions:
echo   1. Open test.asm
echo   2. Press F7 or Build -^> Build PE
echo   3. Verify build output shows:
echo      - ml64.exe invocation
echo      - link.exe invocation
echo      - test.exe created
echo   4. Run test.exe
echo.
echo   Press any key when ready to continue...
pause >nul

set PHASE5_RESULT=MANUAL

REM ============================================================
REM FINAL REPORT
echo.
echo ========================================
echo VAL-025 FINAL REPORT
echo ========================================
echo.
echo Phase 1 - Build Integrity    : %PHASE1_RESULT%
echo Phase 2 - Editor Runtime     : %PHASE2_RESULT%
echo Phase 3 - Native IntelliSense: %PHASE3_RESULT%
echo Phase 4 - Language Intelligence: %PHASE4_RESULT%
echo Phase 5 - Build Pipeline     : %PHASE5_RESULT%
echo.

REM Write final report to log
echo. >> %VAL025_LOG%
echo ======================================== >> %VAL025_LOG%
echo VAL-025 FINAL REPORT >> %VAL025_LOG%
echo ======================================== >> %VAL025_LOG%
echo. >> %VAL025_LOG%
echo Phase 1 - Build Integrity    : %PHASE1_RESULT% >> %VAL025_LOG%
echo Phase 2 - Editor Runtime     : %PHASE2_RESULT% >> %VAL025_LOG%
echo Phase 3 - Native IntelliSense: %PHASE3_RESULT% >> %VAL025_LOG%
echo Phase 4 - Language Intelligence: %PHASE4_RESULT% >> %VAL025_LOG%
echo Phase 5 - Build Pipeline     : %PHASE5_RESULT% >> %VAL025_LOG%
echo. >> %VAL025_LOG%

if "%PHASE1_RESULT%"=="PASS" (
    echo RESULT: READY FOR MANUAL VERIFICATION
    echo RESULT: READY FOR MANUAL VERIFICATION >> %VAL025_LOG%
    echo.
    echo Next steps:
    echo 1. Launch RawrXD_IDE_VAL025.exe
    echo 2. Complete manual verification phases
    echo 3. Review %VAL025_LOG%
) else (
    echo RESULT: FAILED
    echo RESULT: FAILED >> %VAL025_LOG%
)

echo. >> %VAL025_LOG%
echo Ended: %date% %time% >> %VAL025_LOG%

echo.
echo Log saved to: %VAL025_LOG%
pause

exit /b 0

:validation_failed
echo.
echo ========================================
echo VAL-025 VALIDATION FAILED
echo ========================================
echo.
echo Phase: %VAL025_PHASE%
echo.
echo Log saved to: %VAL025_LOG%
pause
exit /b 1
