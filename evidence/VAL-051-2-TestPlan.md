# VAL-051.2 Real Inference Gateway Binding — Test Plan

## Objective
Replace the simulated response branch with actual GGUF model inference execution.

## Acceptance Criteria

### Given
- Model: `tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`
- SHA256: (to be computed)
- Size: 668,788,096 bytes

### Execute
```
rawrxd.exe --model model.gguf --prompt "Hello" --max-tokens 1
```

### Required Witness Output
```json
{
  "schema": "VAL-051.2",
  "model_sha256": "...",
  "tensor_count": ...,
  "token_input": [...],
  "embedding_hash": "...",
  "layer_0_output_hash": "...",
  "kv_position": 1,
  "sampled_token_id": ...,
  "decoded_token": "..."
}
```

## Key Invariant

**Generated token MUST depend on:**
```
GGUF bytes
    ↓
tensor values
    ↓
forward pass
    ↓
logits
    ↓
sampler
```

**NOT:**
```
CLI
    ↓
hardcoded response
```

## Implementation Strategy

### Step 1: Locate Execution Boundary
Find where the simulated response is generated:
```cpp
// Current (simulated)
result.text = "This is a simulated response...";

// Target (real inference)
ExecutionResult result = inference_engine.Generate(request);
```

### Step 2: Connect NativeBackend
Wire the CLI handler to call:
1. `MappedModelLoader::Load()` — mmap GGUF, resolve tensors
2. `Tokenizer::Encode()` — convert prompt to token IDs
3. `TransformerExecutor::Forward()` — run transformer layers
4. `KVCache::Update()` — store key/value for position
5. `Sampler::Sample()` — select token from logits
6. `Tokenizer::Decode()` — convert token ID to text

### Step 3: Integrate Witness Hooks
Wrap each stage with witness recording:
```cpp
recorder.RecordStageStart(InferenceStage::ModelLoad);
auto model = loader.Load(path);
recorder.RecordStageComplete(InferenceStage::ModelLoad, true, model->GetHash());
```

### Step 4: Validate Determinism
With fixed seed and temperature=0, same input must produce:
- Same token ID
- Same decoded text
- Same intermediate hashes

## Success Criteria

| Checkpoint | Required |
|------------|----------|
| GGUF file mapped into memory | ✅ |
| Tensor metadata resolved | ✅ |
| Tokenizer produces token IDs | ✅ |
| Embedding lookup returns vectors | ✅ |
| Transformer produces logits | ✅ |
| KV cache stores state | ✅ |
| Sampler selects token | ✅ |
| Token decoded to text | ✅ |
| Witness artifact created | ✅ |
| Deterministic output verified | ✅ |

## Evidence Artifact

**File**: `evidence/VAL-051-2-REAL-INFERENCE-WITNESS.json`

**Contents**:
- One generated token from TinyLlama
- Hash chain proving: file bytes → tensor → transformer → token
- Timing and resource metrics
- Stage-by-stage execution proof

## Notes

- Do NOT create another loader — use existing `MappedModelLoader`
- Do NOT reimplement tokenizer — use existing `Tokenizer`
- Do NOT rewrite transformer — use existing `TransformerExecutor`
- Focus on **wiring the execution boundary**, not reimplementing components
- The witness system is already ready — just needs real data

## Definition of Done

```
VAL-051.2 Real Inference Gateway Binding
    ✅
```

When:
- `rawrxd.exe --model model.gguf --prompt "Hello" --max-tokens 1`
- Produces actual token from model weights
- Witness artifact captures complete execution chain
- Deterministic output verified with fixed seed
