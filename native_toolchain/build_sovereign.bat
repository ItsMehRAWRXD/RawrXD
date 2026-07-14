@echo off
REM Build Sovereign Inference Engine - Zero Dependencies

echo === Building Sovereign Native Toolchain ===

set CC=cl
set CFLAGS=/O2 /W3 /nologo /D_CRT_SECURE_NO_WARNINGS

if not exist bin mkdir bin

REM Build GGUF loader
echo Building gguf_loader_native.exe...
%CC% %CFLAGS% /DTEST_GGUF_LOADER gguf_loader_native.c /Fe:bin\gguf_loader_native.exe
if errorlevel 1 (
    echo FAILED: gguf_loader_native
    exit /b 1
)

REM Build Sovereign inference engine
echo Building sovereign_inference_engine.exe...
%CC% %CFLAGS% /DTEST_INFERENCE sovereign_inference_engine.c /Fe:bin\sovereign_inference_engine.exe
if errorlevel 1 (
    echo FAILED: sovereign_inference_engine
    exit /b 1
)

REM Build unified model manager
echo Building model_manager.exe...
%CC% %CFLAGS% model_manager_native.c /Fe:bin\model_manager.exe
if errorlevel 1 (
    echo FAILED: model_manager
    exit /b 1
)

echo.
echo === Build Complete ===
echo Binaries in: bin\
dir bin\*.exe
echo.
echo Test with: bin\gguf_loader_native.exe ^<model.gguf^>
