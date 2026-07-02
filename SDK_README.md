# Sovereign SDK

C API wrapper for the Sovereign Engine - enabling native IDE integration with distributed LLM inference capabilities.

## Overview

The Sovereign SDK provides a clean C interface to the Sovereign Engine, allowing you to:
- Initialize and manage distributed inference nodes
- Load GGUF models with various quantization levels (Q4, Q8, FP16)
- Submit async tasks (inference, analysis, embedding)
- Query semantic code graphs for IDE features
- Monitor performance metrics (TPS, latency, memory)

## Quick Start

### 1. Include the SDK

```cpp
#include "sovereign_sdk.h"
#pragma comment(lib, "libsovereign.lib")  // Windows
```

### 2. Initialize the Engine

```cpp
SovereignNodeConfig config = {
    .node_id = 0,
    .total_nodes = 1,
    .is_head = true,
    .enable_gpu = true,
    .enable_amx = Sovereign_HasAMX(),
    .thread_pool_size = Sovereign_GetOptimalThreadCount(),
    .kv_cache_size = 8ULL * 1024 * 1024 * 1024,  // 8GB
    .head_node_ip = "127.0.0.1",
    .router_port = 5555,
    .pub_port = 5556
};

SovereignHandle engine = Sovereign_Init(&config);
if (!engine) {
    // Handle error
}
```

### 3. Load a Model

```cpp
SovereignModelConfig model_config = {
    .model_path = "models/llama-7b-q4.gguf",
    .quantization = SOVEREIGN_QUANT_Q4_0,
    .memory_map = true,
    .lazy_load = true,
    .max_context = 4096
};

SovereignModelHandle model = Sovereign_LoadModel(engine, &model_config);
```

### 4. Submit a Task

```cpp
SovereignTaskParams params = {
    .type = SOVEREIGN_TASK_INFERENCE,
    .input = "Hello, world!",
    .input_len = 13,
    .max_tokens = 100,
    .temperature = 0.7f,
    .on_complete = [](const char* result, size_t len, void* user_data) {
        printf("Result: %.*s\n", (int)len, result);
    }
};

SovereignTaskHandle task = Sovereign_SubmitTask(engine, model, &params);
Sovereign_WaitForTask(engine, task, 30000);  // 30s timeout
```

### 5. Cleanup

```cpp
Sovereign_UnloadModel(engine, model);
Sovereign_Shutdown(engine);
```

## API Reference

### Lifecycle Functions

| Function | Description |
|----------|-------------|
| `Sovereign_Init()` | Initialize the engine with node configuration |
| `Sovereign_Shutdown()` | Clean shutdown of engine and resources |
| `Sovereign_GetStatus()` | Get current engine status and metrics |
| `Sovereign_GetVersion()` | Get SDK version string |

### Model Management

| Function | Description |
|----------|-------------|
| `Sovereign_LoadModel()` | Load a GGUF model from disk |
| `Sovereign_UnloadModel()` | Unload a model and free resources |

### Task Execution

| Function | Description |
|----------|-------------|
| `Sovereign_SubmitTask()` | Submit an async task for execution |
| `Sovereign_CancelTask()` | Cancel a pending or running task |
| `Sovereign_WaitForTask()` | Wait for task completion with timeout |

### Semantic Graph (IDE Features)

| Function | Description |
|----------|-------------|
| `Sovereign_LoadCodeBase()` | Load and index a code base |
| `Sovereign_QuerySemanticGraph()` | Query the semantic graph |
| `Sovereign_GetCallGraph()` | Get call graph for a symbol |

### Hardware Detection

| Function | Description |
|----------|-------------|
| `Sovereign_HasAVX512()` | Check for AVX-512 support |
| `Sovereign_HasAMX()` | Check for Intel AMX support |
| `Sovereign_GetOptimalThreadCount()` | Get optimal thread count for system |
| `Sovereign_GetMemoryInfo()` | Get system memory information |

### Error Handling

| Function | Description |
|----------|-------------|
| `Sovereign_GetLastError()` | Get last error code |
| `Sovereign_GetErrorString()` | Get human-readable error message |
| `Sovereign_SetLogLevel()` | Set logging verbosity |
| `Sovereign_SetLogCallback()` | Set custom log callback |

## Configuration

### Node Configuration

```cpp
typedef struct {
    uint32_t node_id;           // Unique node ID (0 = head)
    uint32_t total_nodes;       // Total nodes in cluster
    bool is_head;               // Is this the head node?
    bool enable_gpu;            // Enable GPU acceleration
    bool enable_amx;            // Enable Intel AMX
    uint32_t thread_pool_size;  // Worker threads
    uint64_t kv_cache_size;     // KV cache size in bytes
    const char* head_node_ip;   // Head node IP (for workers)
    uint16_t router_port;       // Router port
    uint16_t pub_port;          // Publisher port
} SovereignNodeConfig;
```

### Quantization Levels

| Level | Description | Memory |
|-------|-------------|--------|
| `SOVEREIGN_QUANT_FP32` | Full precision | 4 bytes/weight |
| `SOVEREIGN_QUANT_FP16` | Half precision | 2 bytes/weight |
| `SOVEREIGN_QUANT_Q8_0` | 8-bit quantized | 1 byte/weight |
| `SOVEREIGN_QUANT_Q4_0` | 4-bit quantized | 0.5 bytes/weight |
| `SOVEREIGN_QUANT_Q4_K` | Q4_K_M optimized | ~0.5 bytes/weight |

## Building

### Windows (Visual Studio)

```batch
build_sdk.bat
```

### CMake

```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

## Integration Examples

### IDE Completion Provider

```cpp
void ProvideCompletions(const char* code, int line, int column) {
    SovereignTaskParams params = {
        .type = SOVEREIGN_TASK_COMPLETION,
        .input = code,
        .max_tokens = 50,
        .temperature = 0.2f,  // Low temp for deterministic completions
        .on_complete = [](const char* result, size_t len, void* user_data) {
            // Display completions in IDE
            ShowCompletionsInEditor(result, len);
        }
    };
    
    Sovereign_SubmitTask(engine, model, &params);
}
```

### Semantic Code Search

```cpp
void SearchCode(const char* query) {
    SovereignGraphHandle graph = Sovereign_LoadCodeBase(engine, "./src");
    
    char results[4096];
    size_t results_len = sizeof(results);
    
    if (Sovereign_QuerySemanticGraph(engine, graph, query, results, &results_len) == 0) {
        // Display results in IDE sidebar
        ShowSearchResults(results, results_len);
    }
}
```

## Thread Safety

The SDK is thread-safe for:
- Multiple concurrent task submissions
- Status queries from any thread
- Model loading/unloading (serialized internally)

Not thread-safe:
- `Sovereign_Init()` / `Sovereign_Shutdown()` must be called from single thread
- Individual task handles should not be shared across threads

## Performance Tips

1. **Use memory-mapped models**: Set `memory_map = true` for faster loading
2. **Enable lazy loading**: Set `lazy_load = true` to defer tensor loading
3. **Batch small tasks**: Submit multiple tasks together for better throughput
4. **Monitor metrics**: Use `Sovereign_GetStatus()` to track TPS and latency
5. **Use appropriate quantization**: Q4 for inference, Q8 for fine-tuning

## Troubleshooting

### Engine fails to initialize
- Check that AVX-512 is available (or disable `enable_amx`)
- Verify sufficient memory for KV cache
- Check that ports are not in use

### Model fails to load
- Verify GGUF file format version compatibility
- Check file permissions
- Ensure sufficient disk space for memory mapping

### Low throughput
- Increase `thread_pool_size` (typically match CPU cores)
- Enable GPU acceleration if available
- Use lower quantization (Q4 vs Q8)
- Check for thermal throttling

## License

Proprietary - RawrXD Technologies

## Support

For issues and feature requests, contact the Sovereign Engine team.