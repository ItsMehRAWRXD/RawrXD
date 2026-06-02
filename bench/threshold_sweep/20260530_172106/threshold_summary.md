# Vulkan Failure Threshold Sweep

Run: 2026-05-30 17:21:11
Bench: D:\llama-vulkan\build\bin\llama-bench.exe

| Model | Profile | ngl | p | n | Status | Exit | Assert | pp t/s | tg t/s | Notes |
|---|---|---:|---:|---:|---|---:|---|---:|---:|---|
| TinyLlama-1.1B-Q4_0 | full | 99 | 512 | 128 | FAIL | 1 | False |  |  | main: error: failed to load model 'D:\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf' |
| TinyLlama-1.1B-Q4_0 | mid | 48 | 256 | 64 | FAIL | 1 | False |  |  | main: error: failed to load model 'D:\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf' |
| TinyLlama-1.1B-Q4_0 | low | 24 | 128 | 32 | FAIL | 1 | False |  |  | main: error: failed to load model 'D:\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf' |
| TinyLlama-1.1B-Q4_0 | cpu | 0 | 128 | 32 | FAIL | 1 | False |  |  | main: error: failed to load model 'D:\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf' |
| ministral3 | full | 99 | 512 | 128 | FAIL | 1 | False |  |  | main: error: failed to load model 'D:\ministral3.gguf' |
| ministral3 | mid | 48 | 256 | 64 | FAIL | 1 | False |  |  | main: error: failed to load model 'D:\ministral3.gguf' |
| ministral3 | low | 24 | 128 | 32 | FAIL | 1 | False |  |  | main: error: failed to load model 'D:\ministral3.gguf' |
| ministral3 | cpu | 0 | 128 | 32 | FAIL | 1 | False |  |  | main: error: failed to load model 'D:\ministral3.gguf' |
| gptoss20b | full | 99 | 512 | 128 | FAIL | 1 | False |  |  | main: error: failed to load model 'D:\gptoss20b.gguf' |
| gptoss20b | mid | 48 | 256 | 64 | FAIL | 1 | False |  |  | main: error: failed to load model 'D:\gptoss20b.gguf' |
| gptoss20b | low | 24 | 128 | 32 | FAIL | 1 | False |  |  | main: error: failed to load model 'D:\gptoss20b.gguf' |
| gptoss20b | cpu | 0 | 128 | 32 | FAIL | 1 | False |  |  | main: error: failed to load model 'D:\gptoss20b.gguf' |
