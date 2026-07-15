# Phase 14: Q4_K Quantization Optimization for IDE Integration

## Executive Summary

**Goal**: Ensure 7B parameter model fits comfortably under 4GB RAM for RawrXD IDE integration while maintaining inference quality.

**Current State**: 
- Q4_K quantization: ~3.94 GB for 7B parameters (tight margin)
- Need headroom for KV cache, activations, and IDE overhead

**Target**: < 3.5 GB model footprint + 500MB overhead = < 4GB total

---

## Q4_K Memory Structure Analysis

```c
// block_q4_K: 144 bytes per 256 elements (4.5 bits/weight)
typedef struct {
    ggml_half d;                  // 2 bytes - super-block scale
    ggml_half dmin;               // 2 bytes - super-block min scale
    uint8_t scales[12];           // 12 bytes - 6-bit quantized scales
    uint8_t qs[QK_K/2];           // 128 bytes - 4-bit quants
} block_q4_K;
// Total: 144 bytes / 256 weights = 4.5 bits per weight
```

### Memory Breakdown for 7B Model
| Component | Size | Notes |
|-----------|------|-------|
| Q4_K Weights | ~3.94 GB | 7B × 4.5 bits |
| KV Cache (4K ctx) | ~512 MB | Q8_K per layer |
| Activations | ~256 MB | Forward pass buffers |
| **Total** | **~4.7 GB** | **Exceeds target** |

---

## Optimization Strategy

### 1. KV Cache Compression (Priority: HIGH)
**Impact**: -256 to -384 MB

Convert KV cache from Q8_K to Q4_K or hybrid Q4_K/Q2_K:

```cpp
// Current: Q8_K for KV cache (8 bits/weight)
// Optimized: Q4_K for KV cache (4.5 bits/weight)
// Aggressive: Q2_K for older tokens (3.4 bits/weight)

struct KVCacheConfig {
    enum ggml_type k_cache_type = GGML_TYPE_Q4_K;  // Was Q8_K
    enum ggml_type v_cache_type = GGML_TYPE_Q4_K;  // Was Q8_K
    
    // Sliding window compression: recent tokens = Q4_K, older = Q2_K
    uint32_t full_precision_tokens = 512;        // Keep recent in Q8
    uint32_t standard_tokens = 2048;               // Q4_K for middle
    uint32_t compressed_tokens = 1536;           // Q2_K for oldest
};
```

**Implementation**:
```cpp
// src/quantization/kv_cache_quant.cpp
void optimize_kv_cache_for_ide(struct llama_context* ctx) {
    // Reduce KV cache precision while maintaining quality
    ctx->kv_cache.k_type = GGML_TYPE_Q4_K;
    ctx->kv_cache.v_type = GGML_TYPE_Q4_K;
    
    // Enable sliding window compression
    ctx->kv_cache.sliding_window.enabled = true;
    ctx->kv_cache.sliding_window.full_precision_tokens = 512;
    ctx->kv_cache.sliding_window.compressed_tokens = 1536;
}
```

### 2. Layer-Wise Precision Scaling (Priority: HIGH)
**Impact**: -200 to -400 MB

Different layers have different sensitivity to quantization:

```cpp
// Layer-wise quantization strategy
struct LayerQuantConfig {
    // Embeddings and output: Keep Q4_K (most sensitive)
    // Early layers: Q4_K (high feature extraction)
    // Middle layers: Mixed Q4_K/Q3_K
    // Late layers: Q3_K (more robust to quantization)
    
    std::vector<ggml_type> layer_types = {
        GGML_TYPE_Q4_K,   // Layer 0 (embedding)
        GGML_TYPE_Q4_K,   // Layers 1-8 (early)
        GGML_TYPE_Q4_K,   // Layers 9-16 (middle-early)
        GGML_TYPE_Q3_K,   // Layers 17-24 (middle-late) - 3.4 bits
        GGML_TYPE_Q3_K,   // Layers 25-30 (late)
        GGML_TYPE_Q4_K    // Layer 31 (output)
    };
};
```

**Memory Savings**:
- 8 layers × Q3_K (3.4 bits) vs Q4_K (4.5 bits) = ~0.8 bits/layer
- 8 layers × 0.8 bits × 7B/32 layers = ~1.4B bits = ~175 MB saved

### 3. Activation-Aware Quantization (Priority: MEDIUM)
**Impact**: -100 to -200 MB

Use importance matrix (imatrix) for better quantization:

```cpp
// src/quantization/activation_aware_quant.cpp
void quantize_with_activation_awareness(
    const float* weights,
    const float* activations,  // Importance matrix
    void* quantized_output,
    int64_t n_rows,
    int64_t n_per_row
) {
    // Weights activated more frequently get higher precision
    // Weights rarely activated can tolerate more quantization error
    
    quantize_q4_K(weights, quantized_output, n_rows, n_per_row, activations);
}
```

### 4. Dynamic Quantization Switching (Priority: MEDIUM)
**Impact**: Variable, up to -500 MB during idle

Switch precision based on IDE state:

```cpp
// src/inference/dynamic_quant_switch.cpp
class DynamicQuantizationManager {
public:
    void on_ide_state_change(IDEState state) {
        switch(state) {
            case IDEState::IDLE:
                // Decompress to CPU, unload GPU
                unload_model_from_gpu();
                break;
                
            case IDEState::COMPLETION_REQUESTED:
                // Load with Q4_K
                load_model(GGML_TYPE_Q4_K);
                break;
                
            case IDEState::COMPLETION_STREAMING:
                // Already loaded, maintain Q4_K
                break;
                
            case IDEState::BACKGROUND_INDEXING:
                // Use Q3_K for lower quality but faster indexing
                switch_quantization(GGML_TYPE_Q3_K);
                break;
        }
    }
    
private:
    ggml_type current_type = GGML_TYPE_Q4_K;
    std::unordered_map<ggml_type, void*> model_cache;
};
```

### 5. MMAP-Based Lazy Loading (Priority: HIGH)
**Impact**: -2GB+ initial footprint

Use memory-mapped files for on-demand loading:

```cpp
// src/quantization/mmap_quant_loader.cpp
class MMAPQuantizedLoader {
public:
    // Map file to virtual memory, load pages on demand
    void* mmap_load(const char* gguf_path) {
        HANDLE hFile = CreateFileA(gguf_path, GENERIC_READ, ...);
        HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, ...);
        void* ptr = MapViewOfFile(hMap, FILE_MAP_READ, ...);
        
        // Only ~10% of model resident initially
        // Pages faulted in as needed
        return ptr;
    }
    
    // Preload critical layers (embeddings, first 4 layers)
    void preload_critical_layers(void* mmap_ptr) {
        for(int i = 0; i < 4; i++) {
            touch_pages(layer_ptr[i], layer_size); // Force load
        }
    }
};
```

---

## Implementation Roadmap

### Phase 14A: KV Cache Optimization (Week 1)
- [ ] Implement Q4_K KV cache backend
- [ ] Add sliding window compression
- [ ] Benchmark quality degradation
- [ ] **Target**: -256 MB

### Phase 14B: Layer-Wise Quantization (Week 1-2)
- [ ] Profile layer sensitivity to quantization
- [ ] Implement mixed-precision loading
- [ ] Create quantization config format
- [ ] **Target**: -200 MB

### Phase 14C: MMAP Integration (Week 2)
- [ ] Implement cross-platform MMAP loader
- [ ] Add page prefetching for critical layers
- [ ] Handle page fault latency
- [ ] **Target**: -2GB initial footprint

### Phase 14D: Dynamic Switching (Week 3)
- [ ] IDE state detection
- [ ] Hot-swap quantization precision
- [ ] Cache multiple quant versions
- [ ] **Target**: Variable savings

---

## Expected Results

| Optimization | Memory Saved | Quality Impact | Implementation |
|--------------|--------------|----------------|------------------|
| KV Cache Q4_K | -256 MB | Minimal | 3 days |
| Layer-wise Q3/Q4 | -200 MB | Low | 5 days |
| MMAP Loading | -2GB initial | None | 4 days |
| Dynamic Switching | -500 MB idle | None | 5 days |
| **Total** | **~3GB** | **Low** | **~2 weeks** |

### Final Memory Footprint
```
Before:  ~4.7 GB (Q4_K weights + Q8_K KV + activations)
After:   ~1.7 GB resident (MMAP) + 512 MB KV + 256 MB activations = ~2.5 GB
Target:  < 4.0 GB ✓
Headroom: 1.5 GB for IDE and OS
```

---

## ABI Integration Points

```cpp
// Sovereign_Engine exports for quantization control
extern "C" {
    // Set KV cache quantization level
    __declspec(dllexport) void Sovereign_SetKVCacheType(ggml_type type);
    
    // Enable/disable layer-wise quantization
    __declspec(dllexport) void Sovereign_EnableLayerWiseQuant(bool enable);
    
    // Configure MMAP loading
    __declspec(dllexport) void Sovereign_EnableMMAPLoading(bool enable);
    
    // Get current memory footprint
    __declspec(dllexport) size_t Sovereign_GetMemoryFootprintMB();
}
```

---

## Next Steps

1. **Immediate**: Implement KV cache Q4_K conversion
2. **This Week**: Profile layer-wise quantization sensitivity
3. **Next Week**: MMAP loader integration
4. **Integration**: Wire into RawrXD IDE via Sovereign ABI

**Success Criteria**: 7B model runs in < 4GB with < 5% quality degradation vs full Q4_K.
