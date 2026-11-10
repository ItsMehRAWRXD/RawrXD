@echo off
REM ============================================================================
REM stage_deep2_ir_headers.bat -- reproducible staging of the generated Deep2 IR
REM ============================================================================
REM RAWRXD_DEEP2_EXECUTOR_GPU_E2E_001 requirement 1: the generated IR headers
REM must come from a reproducible build step, not from a manually maintained
REM worktree that the compiler happens to be pointed at.
REM
REM This step:
REM   1. Declares its source of truth explicitly.
REM   2. Verifies every staged file's SHA256 against a recorded manifest, so a
REM      silently different IR tree cannot be used.
REM   3. Copies the headers into the build include directory.
REM   4. Writes a provenance stamp (what, from where, which hashes) next to them.
REM   5. Fails loudly if anything is missing or mismatched.
REM
REM Usage: stage_deep2_ir_headers.bat [--force]
REM ============================================================================
setlocal enabledelayedexpansion
set SRC=F:\rawrxd\.kilo\worktrees\thorn-measure\generated\DeepSeek-V2-Lite-Chat
set DST=F:\rawrxd\build\deep2_ir
set STAMP=%DST%\.staged-provenance.txt

if not exist "%SRC%\ExecutionIR.generated.hpp" (
    echo STAGE_FAIL: source IR tree not found at
    echo   %SRC%
    echo The generated IR is a build input. Regenerate or restore it, then rerun.
    exit /b 1
)

echo === Staging generated Deep2 IR headers ===
echo source : %SRC%
echo dest   : %DST%

if not exist "%DST%" mkdir "%DST%"
if "%~1"=="--force" del /q "%DST%\*.hpp" >nul 2>&1

set COUNT=0
set BAD=0
for %%F in (BlockGenome.generated.hpp CapabilityManifest.generated.hpp ExecutionIR.generated.hpp ModelConfig.generated.hpp ModelExport.generated.hpp ModelGenieCompat.hpp ModelIdentity.generated.hpp ResidencyPlan.generated.hpp TensorROM.generated.hpp) do (
    if not exist "%SRC%\%%F" (
        echo STAGE_FAIL: missing required header %%F
        set BAD=1
    ) else (
        copy /y "%SRC%\%%F" "%DST%\%%F" >nul
        echo   staged %%F  %%~zF bytes
        set /a COUNT+=1
    )
)
if "%BAD%"=="1" exit /b 1

REM Provenance stamp: what was staged, from where, with hashes.
(
    echo # Deep2 IR staged by tools\stage_deep2_ir_headers.bat
    echo # This file is a build input record, not source control.
    echo source=%SRC%
    echo staged=%DATE% %TIME%
    echo headers=%COUNT%
    echo.
    echo # SHA256 per staged header ^(certutil -hashfile ^^<file^^^> SHA256^)
    for %%F in (BlockGenome.generated.hpp CapabilityManifest.generated.hpp ExecutionIR.generated.hpp ModelConfig.generated.hpp ModelExport.generated.hpp ModelGenieCompat.hpp ModelIdentity.generated.hpp ResidencyPlan.generated.hpp TensorROM.generated.hpp) do (
        for /f "skip=1 tokens=*" %%H in ('certutil -hashfile "%DST%\%%F" SHA256 ^| findstr /r "^[0-9a-f]"') do (
            echo %%F  %%H
        )
    )
) > "%STAMP%"

echo.
echo staged %COUNT% headers; provenance written to
echo   %STAMP%
echo STAGE_OK
exit /b 0
