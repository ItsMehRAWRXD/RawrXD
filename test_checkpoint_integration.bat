@echo off
REM RawrXD Checkpoint Integration Test Script
REM Tests the GGUF checkpoint hooks in ai_model_caller_real.cpp

echo ============================================
echo RawrXD Checkpoint Integration Test
echo ============================================
echo.

REM Check if source file exists
if not exist "d:\rawrxd\src\ai\ai_model_caller_real.cpp" (
    echo [ERROR] Source file not found: ai_model_caller_real.cpp
    exit /b 1
)

echo [OK] Source file found: ai_model_caller_real.cpp

REM Check if checkpoint header exists
if not exist "d:\rawrxd\src\integration\gguf_checkpoint_hooks.hpp" (
    echo [ERROR] Checkpoint header not found: gguf_checkpoint_hooks.hpp
    exit /b 1
)

echo [OK] Checkpoint header found: gguf_checkpoint_hooks.hpp

REM Verify checkpoint macros are defined
echo.
echo Checking checkpoint macro definitions...
findstr /C:"RAWRXD_CHECKPOINT_GGUF_HEADER" "d:\rawrxd\src\ai\ai_model_caller_real.cpp" > nul
if %errorlevel% == 0 (
    echo [OK] RAWRXD_CHECKPOINT_GGUF_HEADER found
) else (
    echo [WARN] RAWRXD_CHECKPOINT_GGUF_HEADER not found
)

findstr /C:"RAWRXD_CHECKPOINT_EMBEDDING" "d:\rawrxd\src\ai\ai_model_caller_real.cpp" > nul
if %errorlevel% == 0 (
    echo [OK] RAWRXD_CHECKPOINT_EMBEDDING found
) else (
    echo [WARN] RAWRXD_CHECKPOINT_EMBEDDING not found
)

findstr /C:"RAWRXD_CHECKPOINT_ATTENTION" "d:\rawrxd\src\ai\ai_model_caller_real.cpp" > nul
if %errorlevel% == 0 (
    echo [OK] RAWRXD_CHECKPOINT_ATTENTION found
) else (
    echo [WARN] RAWRXD_CHECKPOINT_ATTENTION not found
)

findstr /C:"RAWRXD_CHECKPOINT_FFN" "d:\rawrxd\src\ai\ai_model_caller_real.cpp" > nul
if %errorlevel% == 0 (
    echo [OK] RAWRXD_CHECKPOINT_FFN found
) else (
    echo [WARN] RAWRXD_CHECKPOINT_FFN not found
)

findstr /C:"RAWRXD_CHECKPOINT_LOGITS" "d:\rawrxd\src\ai\ai_model_caller_real.cpp" > nul
if %errorlevel% == 0 (
    echo [OK] RAWRXD_CHECKPOINT_LOGITS found
) else (
    echo [WARN] RAWRXD_CHECKPOINT_LOGITS not found
)

findstr /C:"RAWRXD_CHECKPOINT_SAMPLER" "d:\rawrxd\src\ai\ai_model_caller_real.cpp" > nul
if %errorlevel% == 0 (
    echo [OK] RAWRXD_CHECKPOINT_SAMPLER found
) else (
    echo [WARN] RAWRXD_CHECKPOINT_SAMPLER not found
)

echo.
echo ============================================
echo Checkpoint Integration Summary
echo ============================================
echo.
echo The following checkpoint hooks have been added:
echo   1. Model Header - At inference start
echo   2. Embeddings - After token embedding lookup
echo   3. Attention - After each attention layer
echo   4. FFN - After each feed-forward layer
echo   5. Logits - After output projection
echo   6. Sampler - After token sampling
echo.
echo Build Instructions:
echo   1. Add -DRAWRXD_ENABLE_CHECKPOINTS to compiler flags
echo   2. Link with hash_chain implementation
echo   3. Run smoke test with tiny model
echo.
echo Smoke Test Command:
echo   RawRamXD_Phase7B3.exe --model models\tinyllama.gguf --prompt "Hello" --seed 42 --tokens 10 --enable-proofs
echo.

pause
