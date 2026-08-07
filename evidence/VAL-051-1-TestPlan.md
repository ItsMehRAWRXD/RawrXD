# VAL-051.1 First Real Inference Witness — Test Plan

## Objective
Produce the first `inference_witness_*.json` from an actual model execution.

## Prerequisites

### 1. Acquire Test Model
**Recommended: TinyLlama-1.1B-Chat-v1.0-Q4_K_M.gguf**
- Size: ~700MB (small enough for quick testing)
- Source: https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF
- Alternative: Phi-3-mini-4k-instruct-q4.gguf (~3.8GB)

**Download command:**
```powershell
# Using curl (Windows 10+)
curl -L -o models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
```

### 2. Verify Model Integrity
```powershell
# Compute SHA256 (PowerShell 5.1+)
Get-FileHash models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf -Algorithm SHA256
```

### 3. Deterministic Settings
```json
{
  "temperature": 0.0,
  "top_k": 1,
  "top_p": 1.0,
  "seed": 42,
  "max_tokens": 32,
  "context": 512,
  "threads": 4
}
```

## Test Execution

### Step 1: Run with Witness Recording
```
rawrxd.exe \
  --model models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf \
  --prompt "Hello, my name is" \
  --temperature 0.0 \
  --top-k 1 \
  --seed 42 \
  --max-tokens 32 \
  --validate
```

### Step 2: Verify Witness Artifact
```
evidence/
└── inference_witness_<timestamp>.json
```

### Step 3: Validate Content
Expected structure:
```json
{
  "schema": "VAL-051",
  "build": {
    "gitCommit": "...",
    "binarySha256": "...",
    "timestamp": "..."
  },
  "model": {
    "path": "models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    "sha256": "...",
    "sizeBytes": 736000000,
    "format": "GGUF"
  },
  "parameters": {
    "promptSha256": "...",
    "seed": 42,
    "temperature": 0.0,
    "topK": 1,
    "topP": 1.0,
    "maxTokens": 32
  },
  "stages": {
    "modelLoad": { "completed": true, "success": true, "durationMicros": 150000 },
    "tokenizer": { "completed": true, "success": true, "durationMicros": 5000 },
    "embedding": { "completed": true, "success": true, "durationMicros": 25000 },
    "forwardPass": { "completed": true, "success": true, "durationMicros": 500000 },
    "kvCache": { "completed": true, "success": true, "durationMicros": 10000 },
    "sampler": { "completed": true, "success": true, "durationMicros": 1000 },
    "tokenOutput": { "completed": true, "success": true, "durationMicros": 500 }
  },
  "output": {
    "text": "Hello, my name is ...",
    "tokenChecksum": "sha256:...",
    "logitsChecksum": "sha256:...",
    "tokenCount": 32
  },
  "execution": {
    "success": true,
    "timestamp": "2026-07-24T...",
    "totalDurationMicros": 691000
  }
}
```

## Success Criteria

| Checkpoint | Required |
|------------|----------|
| Model loads without error | ✅ |
| Tokenizer produces tokens | ✅ |
| At least 1 token generated | ✅ |
| Witness artifact created | ✅ |
| Artifact contains all stages | ✅ |
| Execution timestamp recorded | ✅ |

## Failure Handling

If execution fails, witness will contain:
```json
{
  "execution": { "success": false },
  "failure": {
    "stage": "forwardPass",
    "reason": "Kernel dispatch failed: AVX-512 not available"
  }
}
```

This is **still valuable evidence** — it identifies exactly where the pipeline breaks.

## Next Steps After VAL-051.1

```
VAL-051.1  1 token generated     ⏳
       ↓
VAL-051.2  32 token deterministic generation
       ↓
VAL-051.3  streaming generation
       ↓
VAL-052    lifecycle capture
       ↓
VAL-053    performance characterization
```

## Notes

- First run may be slow (model loading, kernel warmup)
- Subsequent runs should be faster
- Keep model file small for rapid iteration
- Document any kernel/backend issues in evidence chain
