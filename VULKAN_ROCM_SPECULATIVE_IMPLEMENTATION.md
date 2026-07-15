# Vulkan/ROCm + Speculative Execution + Generation Logic Implementation

## Overview

This implementation provides a complete GPU-accelerated inference stack for the RawrXD CLI and GUI IDE, featuring:

1. **Full Vulkan/ROCm GPU Backend** - Cross-platform GPU compute support
2. **Speculative Execution Layer** - 2-3x inference speedup via draft model acceleration
3. **Complete Generation Logic** - End-to-end text generation pipeline

## File Structure

```
src/
├── backend/
│   ├── vulkan_rocm_backend.h      # Unified GPU backend interface
│   └── vulkan_rocm_backend.cpp    # Vulkan + HIP/ROCm implementations
├── speculative/
│   ├── speculative_execution_engine.h   # Speculative decoding interface
│   └── speculative_execution_engine.cpp # Draft model + tree attention + verification
└── generation/
    ├── generation_engine.h        # Complete generation pipeline
    └── generation_engine.cpp      # CLI + GUI IDE interfaces
```

## Features

### Vulkan/ROCm Backend (`vulkan_rocm_backend.h/cpp`)

#### Unified Interface (IGPUBackend)
- **Memory Management**: Buffer allocation, mapping, host/device transfers
- **Compute Operations**: MatMul, Softmax, LayerNorm, RMSNorm, RoPE, Attention, FlashAttention
- **KV Cache**: Create, update, clear cache entries for transformer inference
- **Device Enumeration**: Query available GPUs, select optimal device

#### Vulkan Backend
- Vulkan 1.3 compute pipeline with SPIR-V shaders
- Multi-queue async execution
- Descriptor pool management
- Embedded compute shaders for core operations

#### HIP/ROCm Backend
- AMD GPU support via HIP runtime
- Dynamic library loading (hiprt64.dll, amdhip64.dll)
- CUDA-compatible API for cross-platform support

#### Backend Factory
```cpp
// Auto-detect best available backend
auto backend = GPUBackendFactory::CreateAutoBackend();

// Or explicitly select
auto vulkan = GPUBackendFactory::CreateBackend(GPUBackendType::Vulkan);
auto hip = GPUBackendFactory::CreateBackend(GPUBackendType::HIP);
```

### Speculative Execution Engine (`speculative_execution_engine.h/cpp`)

#### Draft Model Support
- Lightweight draft model for fast token generation
- KV cache reuse for efficient single-token generation
- Async draft generation with producer/consumer queue

#### Self-Speculative Mode
- N-gram cache for context-based speculation
- No draft model required
- Falls back gracefully when draft unavailable

#### Tree Attention
- Parallel verification of multiple draft paths
- Attention mask computation for tree structures
- GPU-accelerated tree attention kernels

#### Verification Engine
- Rejection sampling for draft token acceptance
- Temperature-scaled acceptance criteria
- Fused GPU verification kernels
- Adaptive speculation depth based on acceptance rate

#### Usage
```cpp
SpeculativeConfig config;
config.useDraftModel = true;
config.draftModelPath = "draft_model.gguf";
config.maxDraftTokens = 8;
config.useTreeAttention = true;

auto engine = SpeculativeEngineFactory::CreateEngine(config, backend);
auto tokens = engine->GenerateSpeculative(prompt, maxTokens, targetForward);
```

### Generation Engine (`generation_engine.h/cpp`)

#### Tokenizer
- BPE tokenizer with byte-level encoding
- Special token handling (BOS, EOS, PAD)
- Vocabulary management

#### Model Weights
- GGUF loading support
- GPU weight storage and management
- Layer-wise weight organization

#### Sampler
- Multiple strategies: Greedy, Temperature, Top-K, Top-P, Top-K+Top-P
- Repetition penalty
- Configurable temperature and sampling parameters

#### Transformer Layer
- Full transformer implementation
- Attention with KV caching
- FFN with gate/up/down projections
- Layer normalization

#### Generation Modes

**CLI Mode (Batch)**:
```cpp
CLIGenerator cli;
cli.Initialize("model.gguf");
std::string response = cli.Generate("Hello, how are you?");
```

**GUI/IDE Mode (Streaming)**:
```cpp
GUIIDEGenerator gui;
gui.Initialize("model.gguf");
gui.SetOnToken([](const std::string& token) {
    // Update UI with token
});
gui.StartGeneration("Hello");
```

#### Performance Features
- Flash Attention support
- GPU layer offloading
- Speculative execution integration
- Async generation
- Performance statistics tracking

## Integration

### CLI Application
```cpp
#include "generation/generation_engine.h"

int main() {
    auto cli = GenerationEngineFactory::CreateCLI("model.gguf");
    if (!cli) {
        std::cerr << "Failed to initialize\n";
        return 1;
    }
    
    // Interactive mode
    cli->RunInteractive();
    
    // Or single generation
    std::string response = cli->Generate("What is AI?");
    std::cout << response << std::endl;
    
    return 0;
}
```

### GUI/IDE Application
```cpp
#include "generation/generation_engine.h"

class MyIDE : public Generation::IStreamingCallback {
    std::unique_ptr<Generation::GUIIDEGenerator> generator;
    
public:
    bool Initialize() {
        generator = GenerationEngineFactory::CreateGUI("model.gguf");
        return generator != nullptr;
    }
    
    void OnGenerateClicked(const std::string& prompt) {
        generator->StartGeneration(prompt);
    }
    
    // IStreamingCallback implementation
    void OnToken(const TokenInfo& token) override {
        // Update text editor with token.text
    }
    
    void OnComplete(const GenerationResult& result) override {
        // Generation finished
    }
};
```

## Performance Expectations

### Without Speculative Execution
- ~10-50 tokens/second on modern GPU
- Depends on model size and GPU capabilities

### With Speculative Execution
- ~20-150 tokens/second (2-3x speedup)
- Draft model generates 4-8 tokens per target forward pass
- Acceptance rate typically 60-80%

### Memory Requirements
- Model weights: ~2-8GB depending on quantization
- KV cache: ~512MB-2GB depending on context length
- Draft model: ~500MB-1GB (if enabled)

## Build Requirements

### Windows
- Visual Studio 2022 or later
- Vulkan SDK 1.3+
- AMD HIP SDK (optional, for ROCm support)

### Libraries
- Vulkan loader (vulkan-1.lib)
- C++17 or later

## Future Enhancements

1. **Quantization**: INT8/FP8 weight quantization for memory efficiency
2. **Multi-GPU**: Tensor parallelism across multiple GPUs
3. **Continuous Batching**: Process multiple requests simultaneously
4. **LoRA**: Runtime adapter loading for model customization
5. **GGML Integration**: Direct GGML backend support

## License

This implementation is part of the RawrXD project.
