# Production Integration: Q4_0 as Default

**Goal**: Make 131 tok/s the default runtime for RawrXD users  
**Strategy**: Detect Q4_0 models → Use quantized path → Fallback to C4 baseline

## Integration Points

```
┌─────────────────────────────────────────────────────────────┐
│                    RawrXD Inference Path                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Model Load ──▶ Detect Format ──▶ Route to Backend         │
│       │              │                  │                     │
│       │              ▼                  ▼                     │
│       │         Q4_0 detected?    Quantized MatMul            │
│       │              │                  │                     │
│       │         Yes ─┴─ No              │                     │
│       │              │                  │                     │
│       │         ┌────┴────┐             │                     │
│       │         ▼         ▼             │                     │
│       │    Q4_0 Path   C4 Baseline      │                     │
│       │    131 tok/s   31 tok/s         │                     │
│       │         │         │             │                     │
│       └─────────┴─────────┴─────────────┘                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Plan

### Phase 1: Model Detection (Day 1)
- [ ] Detect Q4_0 tensor types in GGUF
- [ ] Set `use_quantization = true` flag
- [ ] Log model format at load time

### Phase 2: Backend Routing (Day 1-2)
- [ ] Create `QuantizedTransformer` class
- [ ] Integrate `quantized_matmul` kernels
- [ ] Maintain C4 fallback path

### Phase 3: Validation (Day 2)
- [ ] Test with real ministral3 Q4_0.gguf
- [ ] Verify output quality vs FP32
- [ ] Benchmark end-to-end

### Phase 4: Default Enablement (Day 3)
- [ ] Make Q4_0 the default when detected
- [ ] Add `--no-quantization` override flag
- [ ] Update documentation

## Code Changes

### 1. Model Loading (model_context.h)
```cpp
struct ModelLoadConfig {
    bool auto_detect_quantization = true;
    bool prefer_quantization = true;  // NEW: Default to Q4_0
    QuantizationType force_type = QUANT_AUTO;  // AUTO, Q4_0, FP32
};

class ModelContext {
    QuantizationType GetQuantizationType() const;
    bool ShouldUseQuantizedPath() const;
};
```

### 2. Inference Routing (inference_engine.hpp)
```cpp
class InferenceEngine {
    std::unique_ptr<ITransformerBackend> backend_;
    
    void SelectBackend(const ModelContext& model) {
        if (model.ShouldUseQuantizedPath()) {
            backend_ = std::make_unique<QuantizedTransformer>();
        } else {
            backend_ = std::make_unique<StandardTransformer>();  // C4 baseline
        }
    }
};
```

### 3. Quantized Backend (quantized_transformer.hpp)
```cpp
class QuantizedTransformer : public ITransformerBackend {
    // Uses quantized_matmul kernels
    // 131 tok/s for Q4_0 models
    // Falls back to C4 for unsupported ops
};
```

## Success Criteria

| Check | Criteria |
|-------|----------|
| ☐ | Q4_0 models auto-detected |
| ☐ | Quantized path used by default |
| ☐ | 131 tok/s achieved in production |
| ☐ | FP32 models still work (31 tok/s) |
| ☐ | Quality validated vs reference |
| ☐ | Users can disable with flag |

## Rollback Plan

If issues detected:
1. Set `prefer_quantization = false` (revert to C4 baseline)
2. Fix issue
3. Re-enable with `--quantization-beta` flag

---

**Target: Ship 131 tok/s to users by end of week**
