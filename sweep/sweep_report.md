# Deep2 Ollama Model Sweep

- date (UTC): 2026-10-12 22:32
- tokens per model: 3
- prompt: `def add(a, b):`
- tool: `F:\rawrxd\build_rt\deep2_runtime_dispatch.exe`

| Model | GB | wall s | exit | VERDICT | GPU_ONLY | PARITY | CERT | gates | TPS |
|---|---|---|---|---|---|---|---|---|---|
| n4-tiny-oracle:latest | 0.6 | 12.9 |  | PASS | PASS | PASS | PASS | 23 passed, 0 failed | 2.05 |
| qwen2.5-coder:1.5b-base | 0.9 | 22.5 |  | PASS | PASS | PASS | PASS | 22 passed, 0 failed | 0.90 |
| llama3.2:3b | 1.9 | 34.9 |  | PASS | PASS | PASS | PASS | 22 passed, 0 failed | 0.49 |
| qwen35-40b-heretic-q8:latest | 2 | 16.1 |  | FAIL | NOT_RUN | NOT_RUN | FAIL | 17 passed, 1 failed | ? |
| nemotron-3-nano:4b | 2.6 | 30.1 |  | PASS | PASS | PASS | PASS | ? | 1.10 |
| gemma3:latest | 3.1 | 42 |  | FAIL | PASS | FAIL | FAIL | ? | 0.76 |
| llama3.1:8b | 4.6 | 64.6 |  | PASS | PASS | PASS | PASS | 22 passed, 0 failed | 0.34 |
| granite3.3:8b | 4.6 | 95.6 |  | FAIL | PASS | FAIL | FAIL | 19 passed, 3 failed | 0.23 |
| qwen3:8b | 4.9 | 95.7 |  | FAIL | FAIL | FAIL | FAIL | 21 passed, 1 failed | 0.20 |
| pdurugyan/qwen3.5-9b-deepseek-v4-flash-Q4_K_M-v_2:latest | 5.2 | 112.3 |  | FAIL | NOT_RUN | NOT_RUN | FAIL | 16 passed, 1 failed | ? |
| kiminoto/T0.0.1:latest | 6.1 | 46.4 |  | FAIL | NOT_RUN | NOT_RUN | FAIL | 16 passed, 1 failed | ? |
| deepseek-coder-v2:16b | 8.3 | 66 |  | FAIL | PASS | FAIL | FAIL | 20 passed, 3 failed | 0.73 |
| starcoder2:15b | 8.4 | 60.1 |  | PASS | PASS | PASS | PASS | ? | 0.71 |
| gpt-oss:20b | 12.8 | 71.4 |  | FAIL | NOT_RUN | NOT_RUN | FAIL | ? | ? |
| qwen3.8:27b | 15.7 | 127.7 |  | FAIL | NOT_RUN | NOT_RUN | FAIL | 16 passed, 1 failed | ? |
| deepseek-r1:32b | 18.5 | 246.5 |  | FAIL | FAIL | FAIL | FAIL | 19 passed, 3 failed | 0.08 |
| ornith-1.5:35b | 20.2 | 119.2 |  | FAIL | NOT_RUN | NOT_RUN | FAIL | 16 passed, 1 failed | ? |
| nemotron-3.5-lightning:30b | 23.7 | 146.1 |  | PASS | PASS | PASS | PASS | 26 passed, 0 failed | 0.51 |
| bigdaddyg-productivity-local:latest | 23.7 | 128 |  | FAIL | NOT_RUN | NOT_RUN | FAIL | 14 passed, 1 failed | ? |
| deepseek-r1:70b | 39.6 | 1034.2 |  | FAIL | FAIL | PASS | FAIL | 22 passed, 0 failed | 0.02 |
| qwen3-next:80b | 46.9 | 229.4 |  | FAIL | NOT_RUN | NOT_RUN | FAIL | 16 passed, 1 failed | ? |
| gpt-oss:120b | 60.9 | 393.7 |  | FAIL | NOT_RUN | NOT_RUN | FAIL | ? | ? |
| laguna-s-2.1:Q4_K_M | 89.4 | 477 |  | FAIL | NOT_RUN | NOT_RUN | FAIL | 17 passed, 1 failed | ? |
| bluehawana/deepseek-v4-flash:iq2_m | 96.9 | 519.7 |  | FAIL | NOT_RUN | NOT_RUN | FAIL | 17 passed, 1 failed | ? |

Models that resolve to no local blob (cloud-only in ollama list): 9
- minimax-m3:cloud
- deepseek-v4.1-flash:cloud
- deepseek-v4-flash:cloud
- glm-5.3-flash:cloud
- glm-5.3:cloud
- deepseek-v4-flash:0731-cloud
- blackgrg26/WORMGPT-14:latest
- glm-5.2:cloud
- kimi-k2.6:cloud
