# Vulkan Failure Threshold Sweep

Run: 2026-05-30 17:18:46
Bench: D:\llama-vulkan\build\bin\llama-bench.exe

| Model | Profile | ngl | p | n | Status | Exit | Assert | pp t/s | tg t/s | Notes |
|---|---|---:|---:|---:|---|---:|---|---:|---:|---|
| TinyLlama-1.1B-Q4_0 | full | 99 | 512 | 128 | FAIL | -1073740791 | True |  |  | GGML_ASSERT(prev != ggml_uncaught_exception) |
| TinyLlama-1.1B-Q4_0 | mid | 48 | 256 | 64 | FAIL | -1073740791 | True |  |  | GGML_ASSERT(prev != ggml_uncaught_exception) |
| TinyLlama-1.1B-Q4_0 | low | 24 | 128 | 32 | FAIL | -1073740791 | True |  |  | GGML_ASSERT(prev != ggml_uncaught_exception) |
| TinyLlama-1.1B-Q4_0 | cpu | 0 | 128 | 32 | FAIL | -1073740791 | True |  |  | GGML_ASSERT(prev != ggml_uncaught_exception) |
| ministral3 | full | 99 | 512 | 128 | FAIL | -1073740791 | True |  |  | GGML_ASSERT(prev != ggml_uncaught_exception) |
| ministral3 | mid | 48 | 256 | 64 | FAIL | -1073740791 | True |  |  | GGML_ASSERT(prev != ggml_uncaught_exception) |
| ministral3 | low | 24 | 128 | 32 | FAIL | -1073740791 | True |  |  | GGML_ASSERT(prev != ggml_uncaught_exception) |
| ministral3 | cpu | 0 | 128 | 32 | FAIL | -1073740791 | True |  |  | GGML_ASSERT(prev != ggml_uncaught_exception) |
| gptoss20b | full | 99 | 512 | 128 | FAIL | -1073740791 | True |  |  | GGML_ASSERT(prev != ggml_uncaught_exception) |
| gptoss20b | mid | 48 | 256 | 64 | FAIL | -1073740791 | True |  |  | GGML_ASSERT(prev != ggml_uncaught_exception) |
| gptoss20b | low | 24 | 128 | 32 | FAIL | -1073740791 | True |  |  | GGML_ASSERT(prev != ggml_uncaught_exception) |
| gptoss20b | cpu | 0 | 128 | 32 | FAIL | -1073740791 | True |  |  | GGML_ASSERT(prev != ggml_uncaught_exception) |
