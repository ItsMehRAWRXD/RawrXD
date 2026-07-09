@echo off
chcp 65001 >nul
echo.
echo ==========================================
echo Step C1 Milestone Gates - GGUF Ingestion
echo ==========================================
echo.

set "EXE=.\rawrxd_v3.exe"
set "MODEL=d:\rawrxd\src\codestral22b.gguf"
set "DUMMY=d:\rawrxd\src\dummy.gguf"
set /a PASSED=0
set /a FAILED=0

:: Gate 1: GGUF File Detection
echo Gate 1: GGUF File Detection
echo ------------------------------------------
%EXE% inspect %DUMMY% --json > test_c1_g1.json 2>nul
if %ERRORLEVEL% EQU 0 (
    echo   PASS: GGUF file detected and parsed
    set /a PASSED+=1
) else (
    echo   FAIL: Could not detect GGUF file
    set /a FAILED+=1
)
echo.

:: Gate 2: Architecture Extraction
echo Gate 2: Architecture Extraction
echo ------------------------------------------
%EXE% inspect %MODEL% --json > test_c1_g2.json 2>nul
findstr "llama" test_c1_g2.json >nul
if %ERRORLEVEL% EQU 0 (
    echo   PASS: Architecture extracted (llama)
    set /a PASSED+=1
) else (
    echo   FAIL: Architecture not extracted
    set /a FAILED+=1
)
echo.

:: Gate 3: Tensor Count
echo Gate 3: Tensor Count
echo ------------------------------------------
findstr "tensor_count" test_c1_g2.json >nul
if %ERRORLEVEL% EQU 0 (
    echo   PASS: Tensor count extracted
    set /a PASSED+=1
) else (
    echo   FAIL: Tensor count not extracted
    set /a FAILED+=1
)
echo.

:: Gate 4: Vocabulary Size
echo Gate 4: Vocabulary Size
echo ------------------------------------------
findstr "vocab_size" test_c1_g2.json >nul
if %ERRORLEVEL% EQU 0 (
    echo   PASS: Vocab size extracted
    set /a PASSED+=1
) else (
    echo   FAIL: Vocab size not extracted
    set /a FAILED+=1
)
echo.

:: Gate 5: Layer Count
echo Gate 5: Layer Count
echo ------------------------------------------
findstr "layer_count" test_c1_g2.json >nul
if %ERRORLEVEL% EQU 0 (
    echo   PASS: Layer count extracted
    set /a PASSED+=1
) else (
    echo   FAIL: Layer count not extracted
    set /a FAILED+=1
)
echo.

:: Gate 6: Quantization Type
echo Gate 6: Quantization Type
echo ------------------------------------------
findstr "Q4_K" test_c1_g2.json >nul
if %ERRORLEVEL% EQU 0 (
    echo   PASS: Quantization type detected (Q4_K)
    set /a PASSED+=1
) else (
    echo   FAIL: Quantization type not detected
    set /a FAILED+=1
)
echo.

:: Gate 7: Tensor Names
echo Gate 7: Tensor Names
echo ------------------------------------------
findstr "token_embd.weight" test_c1_g2.json >nul
if %ERRORLEVEL% EQU 0 (
    echo   PASS: Tensor names extracted
    set /a PASSED+=1
) else (
    echo   FAIL: Tensor names not extracted
    set /a FAILED+=1
)
echo.

:: Gate 8: JSON Output Contract
echo Gate 8: JSON Output Contract
echo ------------------------------------------
findstr "\"status\":0" test_c1_g2.json >nul
if %ERRORLEVEL% EQU 0 (
    echo   PASS: JSON output valid
    set /a PASSED+=1
) else (
    echo   FAIL: JSON output invalid
    set /a FAILED+=1
)
echo.

:: Gate 9: Human-Readable Output
echo Gate 9: Human-Readable Output
echo ------------------------------------------
%EXE% inspect %DUMMY% > test_c1_g9.txt 2>nul
findstr "Model:" test_c1_g9.txt >nul
if %ERRORLEVEL% EQU 0 (
    echo   PASS: Human-readable output works
    set /a PASSED+=1
) else (
    echo   FAIL: Human-readable output broken
    set /a FAILED+=1
)
echo.

:: Summary
echo ==========================================
echo Step C1 Gate Summary
echo ==========================================
echo Passed: %PASSED%
echo Failed: %FAILED%
echo Total:  %PASSED% + %FAILED%
echo.

if %FAILED% EQU 0 (
    echo ALL GATES PASSED - Step C1 Complete
) else (
    echo SOME GATES FAILED
)

:: Cleanup
del /q test_c1_*.json test_c1_*.txt 2>nul

exit /b %FAILED%
