# GGUF Adapter Integration Guide

## Quick Start - 3 Lines to Integration

```cpp
#include "gguf_adapter_bridge_v2.hpp"

// 1. Open model
sovereign::StreamingGGUFLoader loader("model.gguf");

// 2. Iterate tensors
loader.forEachTensor([](const sovereign::TensorView& view) {
    printf("%s: %s\n", view.info().name.c_str(), view.info().typeName().c_str());
});

// 3. Load specific weights
auto data = loader.loadTensor("token_embd.weight");
```

## Integration Points

### 1. Transformer/SEG Runtime Hook

```cpp
class TransformerEngine {
    sovereign::StreamingGGUFLoader weightLoader_;
    
public:
    bool loadWeights(const std::string& ggufPath) {
        // Open and validate
        if (!weightLoader_.open(ggufPath)) {
            return false;
        }
        
        // Load only weight tensors
        auto weights = weightLoader_.loadWeights();
        
        // Feed into SEG
        for (auto& [info, data] : weights) {
            if (info.name.find("attn_qkv") != std::string::npos) {
                // Handle fused QKV
                loadFusedQKV(info, data);
            } else if (info.name.find("attn_output") != std::string::npos) {
                loadAttentionOutput(info, data);
            } else if (info.name.find("ffn") != std::string::npos) {
                loadFFN(info, data);
            }
        }
        
        return true;
    }
};
```

### 2. TensorView to Execution Context

```cpp
// In your execution loop
sovereign::TensorView inputView = ...;  // From GGUF

// Get raw data pointer
void* weightData = inputView.mutableData();

// Pass to kernel
runAttentionKernel(weightData, outputBuffer, dims...);
```

### 3. Filtered Loading

```cpp
// Load only specific layer
loader.forEachTensor(
    [](const sovereign::TensorInfo& info) {
        return info.name.find("blk.0.") != std::string::npos;
    },
    [](const sovereign::TensorView& view) {
        processLayer0Weight(view);
    }
);
```

## Build Commands

```batch
:: 1. Build MASM core
build_gguf_adapter.bat

:: 2. Build C++ bridge
build_bridge_v2.bat

:: 3. Test
build\test_streaming_loader.exe D:\test_model.gguf list
```

## Runtime Flow

```
┌─────────────────┐
│  Your Runtime   │
│  (Transformer)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ StreamingGGUF   │
│ Loader          │
│ (C++ Bridge)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ GGUFAdapter     │
│ (C++ Wrapper)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ MASM Core       │
│ (Syscalls)      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ GGUF File       │
└─────────────────┘
```

## Performance Notes

- **Zero-copy iteration**: Metadata only, no data loaded
- **On-demand loading**: `loadTensorData()` reads when needed
- **Sequential access**: Optimized for streaming
- **No heap**: All buffers static in MASM

## Next Steps

1. **Add to CMake**: Link `gguf_adapter.obj` to your build
2. **Memory map**: Use `NtMapViewOfSection` for large files
3. **Async loading**: Implement `GGUF_LoadTensorDataAsync`
4. **Quantized inference**: Add dequant kernels per type
