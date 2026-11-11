# VAL-051.2 Real Inference Gateway Binding — Implementation Plan

## Current State Analysis

### What We Know
1. **rawrxd.exe executes successfully** with `--model` and `--prompt` arguments
2. **Output is simulated**, not from actual GGUF model weights
3. **Witness infrastructure is ready** but not yet capturing real inference data
4. **All backend components exist** from previous VAL-052 → VAL-057 work

### Execution Path Discovery
The current execution flow:
```
rawrxd.exe
    ↓
CLI argument parsing (working)
    ↓
Simulated response generation (needs replacement)
    ↓
Console output with formatted results
```

The simulated response is likely generated in:
- A dynamically loaded component
- A different source file than entry_point.cpp
- A runtime module that's not yet connected to the inference backend

## Implementation Strategy

### Phase 1: Locate Execution Boundary (30 min)
**Goal**: Find where the simulated response is generated

**Steps**:
1. Search for "simulated" or "production" strings in all linked object files
2. Identify the function that produces the formatted output
3. Map the call stack from CLI handler to response generation

**Expected Output**:
- File path and line number of simulation code
- Function signature of response generator
- Call chain from CLI entry to simulation

### Phase 2: Connect NativeBackend (2 hours)
**Goal**: Replace simulation with real inference call

**Steps**:
1. Include inference engine headers
2. Create ExecutionRequest from CLI arguments
3. Call inference_engine.Generate(request)
4. Handle success/failure paths

**Code Pattern**:
```cpp
// Current (simulated)
result.text = "This is a simulated response...";

// Target (real inference)
ExecutionRequest request;
request.modelPath = modelPath;
request.prompt = prompt;
request.maxTokens = maxTokens;
request.temperature = temperature;
request.seed = seed;

ExecutionResult result = inference_engine.Generate(request);
if (!result.success) {
    // Handle error, record in witness
}
```

### Phase 3: Integrate Witness Hooks (1 hour)
**Goal**: Wrap inference stages with witness recording

**Steps**:
1. Create WitnessRecorder at CLI entry
2. Record stage start/complete for each inference phase
3. Save witness artifact on completion

**Code Pattern**:
```cpp
RawrXD::Evidence::WitnessRecorder recorder(modelPath, prompt);
recorder.SetParameters(seed, temperature, 1.0f, 1, maxTokens);

recorder.RecordStageStart(InferenceStage::ModelLoad);
auto model = loader.Load(modelPath);
recorder.RecordStageComplete(InferenceStage::ModelLoad, 
    model != nullptr, model->GetHash());

// ... repeat for each stage ...

recorder.Finalize(result.success);
recorder.SaveToDefaultLocation();
```

### Phase 4: Validate Determinism (30 min)
**Goal**: Verify fixed seed produces consistent output

**Steps**:
1. Run with same seed multiple times
2. Compare witness artifacts
3. Verify token IDs match

**Success Criteria**:
- Same input → Same output (with temperature=0)
- Witness hashes identical across runs
- Token IDs consistent

## Files to Modify

### Primary Target
| File | Purpose |
|------|---------|
| `src/cli/rawrxd_cli_link_shims.cpp` | CLI entry point — add inference call |
| `src/ui/entry_point.cpp` | Alternative entry — may need update |
| `src/Phase3_Agent_Kernel.cpp` | Contains RunInference simulation — replace |

### Headers to Include
```cpp
#include "inference_witness.h"
#include "MappedModelLoader.hpp"
#include "Tokenizer.hpp"
#include "TransformerExecutor.hpp"
#include "KVCache.hpp"
#include "Sampler.hpp"
```

## Build Commands

### Rebuild rawrxd.exe with changes
```cmd
cd d:\rawrxd\build-ninja
ninja rawrxd.exe
```

### Test execution
```cmd
cd d:\rawrxd\build-ninja\bin
rawrxd.exe --model ..\..\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --prompt "Hello" --temperature 0.0 --top-k 1 --seed 42 --max-tokens 1 --validate
```

### Verify witness artifact
```cmd
dir d:\rawrxd\evidence\inference_witness_*.json
type d:\rawrxd\evidence\inference_witness_*.json
```

## Success Criteria

| Checkpoint | Required |
|------------|----------|
| GGUF file mapped into memory | ✅ |
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

**Required Contents**:
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

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Inference too slow for testing | Use TinyLlama (700MB), limit to 1 token |
| Memory issues | Monitor with Task Manager, start small |
| Backend not ready | Fall back to simulation with clear error |
| Build failures | Keep changes minimal, test incrementally |

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
- Evidence file saved to `evidence/VAL-051-2-REAL-INFERENCE-WITNESS.json`

## Next Steps After VAL-051.2

```
VAL-051.2  Real Inference Gateway Binding     ✅
       ↓
VAL-051.3  32 Token Deterministic Generation
       ↓
VAL-051.4  Streaming Generation
       ↓
VAL-052    Runtime Component Lifecycle Evidence
       ↓
VAL-053    Performance Characterization
```

---

*Status: Ready for Implementation*
