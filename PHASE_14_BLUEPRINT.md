# Phase 14: Multi-Model Registry + Hot-Swap

## Overview

Phase 14 adds a **centralized model registry** that enables:
- Multiple GGUF models managed in one place
- Hot-swapping between models without restart
- Task-based model selection (agent picks best model for job)
- Model metadata and capability tracking
- Performance benchmarking

## Files Created

| File | Purpose |
|------|---------|
| `ModelRegistry.h` | Registry API and data structures |
| `ModelRegistry.cpp` | Implementation with JSON persistence |
| `models/registry.json` | Sample registry with 5 models |

## Key Features

### 1. Model Registry Structure
```c
typedef struct ModelInfo {
    char id[64];              // Unique identifier
    char name[128];           // Display name
    char path[512];           // Path to GGUF file
    char backend_type[32];    // "native", "ollama"
    
    // Specifications
    size_t parameter_count;   // 7B, 14B, etc.
    int context_window;       // 4096, 16384, etc.
    unsigned int capabilities; // Bitmask of CAP_*
    
    // Performance
    float tokens_per_second;
    size_t memory_required_mb;
    
    // Status
    int is_default;
    int is_loaded;
};
```

### 2. Capabilities System
Models declare what they can do:
- `CAP_CODE_GENERATION` - Write code
- `CAP_CODE_FIXING` - Fix errors
- `CAP_OPTIMIZATION` - Optimize code
- `CAP_REASONING` - Complex reasoning
- `CAP_CHAT` - Conversational
- `CAP_MULTILINGUAL` - Multiple languages

### 3. Task-Based Selection
```c
ModelRegistry_SelectModelForTask(
    "code",      // Task type
    "rust",      // Language
    1,           // Prefer speed
    0,           // Prefer quality
    &model       // Output
);
```

### 4. CLI Commands
```bash
# List all models
SovereignCLI_Unified.exe models list

# Show model details
SovereignCLI_Unified.exe models info phi4

# Set default model
SovereignCLI_Unified.exe models set-default deepseek

# Switch active model (hot-swap)
SovereignCLI_Unified.exe models switch qwen3

# Agent uses selected model automatically
SovereignCLI_Unified.exe agent generate "Hello" rust
```

## Sample Registry

The included `registry.json` has 5 models:

| Model | Params | Context | Best For |
|-------|--------|---------|----------|
| Phi-4 | 14B | 16K | Code, reasoning, chat |
| CodeLlama | 7B | 16K | Code generation |
| DeepSeek | 6.7B | 16K | Code fixing, optimization |
| Qwen3 | 8B | 32K | Multilingual, math |
| Ollama-CodeLlama | 7B | 16K | Remote via HTTP |

## Integration with Existing Components

### AgentSubsystem
- Calls `ModelRegistry_SelectModelForTask()` before generation
- Falls back to default if no specific match
- Logs model selection to ExecutionJournal

### InferenceBackend
- `NativeInferenceBackend` loads from registry path
- `OllamaInferenceBackend` uses registry endpoint
- Backend created based on `backend_type` field

### ExecutionJournal
- `MODEL_SELECTED` - When agent picks model
- `MODEL_LOADED` - When model loaded into memory
- `MODEL_SWITCHED` - When hot-swapping

## Hot-Swap Flow

```
User: "Switch to Qwen3"
    ↓
CLI: models switch qwen3
    ↓
ModelRegistry_SwitchModel("qwen3")
    ↓
Unload current model (if loaded)
    ↓
Load Qwen3 GGUF
    ↓
Update active_model_id
    ↓
Log MODEL_SWITCHED to journal
    ↓
Ready for next generation
```

## Benefits

1. **No Restart Required** - Switch models on the fly
2. **Task Optimization** - Use best model for each job
3. **Resource Management** - Know memory requirements upfront
4. **Performance Tracking** - Benchmark and compare models
5. **Unified Interface** - Same API for local and remote models

## Next Steps (Phase 14.5)

1. **GUI Model Panel** - Visual model selector
2. **Auto-Selection** - Agent picks model without explicit command
3. **Model Download** - Fetch from HuggingFace automatically
4. **Quantization Detection** - Auto-detect Q4, Q8, etc.

## Status

- ✅ Registry API defined
- ✅ JSON persistence implemented
- ✅ CLI commands added
- ✅ Sample registry created
- ⚠️ Integration with AgentSubsystem pending
- ⚠️ GUI panel pending

**Phase 14 architecture is complete. Ready for integration.**
