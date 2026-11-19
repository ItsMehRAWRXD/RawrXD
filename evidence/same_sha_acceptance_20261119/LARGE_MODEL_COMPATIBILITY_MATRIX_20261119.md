# Large-model compatibility matrix

Inventory captured from `F:\\rawrxd\\models` and `ollama list` on 2026-11-19.

| Model artifact | Bytes | Matrix status |
|---|---:|---|
| `nemotron-3.5-lightning_30b.gguf` | 25,430,738,944 | Artifact present; runtime parity not run |
| `bigdaddygnative_latest.gguf` | 25,463,410,912 | Artifact present; Qwen4Exp graph integration open |
| `deepseek-r1_32b.gguf` | 19,851,335,552 | Artifact present; runtime parity not run |
| `ornith-1.5_35b.gguf` | 21,713,462,848 | Artifact present; runtime parity not run |
| `gpt-oss_latest.gguf` | 13,793,604,144 | Artifact present; runtime parity not run |
| `qwen3.8:27b` Ollama model | Ollama-reported 17 GB | Ollama entry present; native GGUF parity not run |
| `qwen3-next:80b` Ollama model | Ollama-reported 50 GB | Ollama entry present; native runtime not run |
| `deepseek-r1:70b` Ollama model | Ollama-reported 42 GB | Ollama entry present; native runtime not run |
| `gpt-oss:120b` Ollama model | Ollama-reported 65 GB | Ollama entry present; native runtime not run |

This is an artifact-availability matrix, not a compatibility PASS. No large-model execution was started by this receipt; independent reference parity, GPU-only execution, memory stability, and multi-token generation remain open per model.

```ini
S052=INVENTORY_COMPLETE_RUNTIME_MATRIX_OPEN
LARGE_MODEL_RUNTIME_TESTS=NOT_RUN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
