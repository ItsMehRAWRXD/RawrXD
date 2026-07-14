@echo off
cd /d d:\rawrxd\build_cli
C:/ProgramData/mingw64/mingw64/bin/g++.exe -std=c++17 -O3 -mavx2 -mfma -mavx512f -mavx512dq -I../src -I../src/core -I../src/inference -I../../src/runtime -I../src/kernels ../src/core/minimal_json.cpp ../src/core/streaming_loader.cpp ../src/core/model_downloader.cpp ../src/inference/unified_inference.cpp ../../src/runtime/kv_cache_optimized.cpp ../../src/runtime/transformer_layer_optimized.cpp ../src/kernels/avx2_kernels.cpp ../src/kernels/avx512_kernels.cpp ../src/cli/rawrxd_infer.cpp -o rawrxd-infer.exe -lkernel32 -luser32 -lwinhttp 2>&1
echo Exit code: %ERRORLEVEL%
