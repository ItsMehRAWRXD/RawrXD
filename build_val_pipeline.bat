@echo off
cd /d d:\src
set GCC=C:\ProgramData\mingw64\mingw64\bin\g++.exe
set CFLAGS=-std=c++20 -O2 -Wall -Isrc -Isrc\include -Isrc\deep2 -Isrc\core -Isrc\unified -Isrc\context -Isrc\agent -Isrc\inference -Isrc\tokenizer -DUNICODE -D_UNICODE -DPHASE15_UNIFIED -DNDEBUG
set OBJS=build-unified-final\Deep2Provider.obj build-unified-final\Deep2Engine.obj build-unified-final\Deep2InferenceGateway.obj build-unified-final\ContextEngine.obj build-unified-final\CompilerAgent.obj build-unified-final\AIServiceAdapter.obj build-unified-final\RawrXDHost.obj build-unified-final\InferenceEngine.obj build-unified-final\LegacyAdapterStub.obj build-unified-final\sampling.obj build-unified-final\Tokenizer.obj build-unified-final\advanced_sampler.obj

echo Building val_deep2_pipeline.exe...
%GCC% %CFLAGS% -o build-unified-final\val_deep2_pipeline.exe val_deep2_inference_pipeline.cpp %OBJS% -lws2_32 -lwinmm
if errorlevel 1 (
    echo FAILED
    exit /b 1
)
echo SUCCESS
