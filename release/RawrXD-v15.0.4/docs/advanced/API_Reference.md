# RawrXD Advanced - API Reference
## Complete API Documentation

**Version:** 1.0.0  
**Date:** 2026-07-15  
**Status:** ✅ Complete

---

## Table of Contents

1. [Overview](#overview)
2. [Core API](#core-api)
3. [Inference API](#inference-api)
4. [Model API](#model-api)
5. [Memory API](#memory-api)
6. [GPU API](#gpu-api)
7. [Network API](#network-api)
8. [Extension API](#extension-api)

---

## Overview

Complete reference for all RawrXD APIs.

### API Conventions

| Convention | Description |
|-----------|-------------|
| `RAWRXD_API` | Export macro for public APIs |
| `__cdecl` | C calling convention |
| `__stdcall` | Windows calling convention |
| `const` | Input parameters |
| `out` | Output parameters |

---

## Core API

### Initialization

```c
// Initialize RawrXD runtime
RAWRXD_API int RawrXD_Initialize(const RawrXDConfig* config);

// Shutdown runtime
RAWRXD_API void RawrXD_Shutdown(void);

// Get version
RAWRXD_API const char* RawrXD_GetVersion(void);

// Get build info
RAWRXD_API const char* RawrXD_GetBuildInfo(void);
```

### Configuration

```c
// Configuration structure
typedef struct {
    uint32_t version;           // API version
    const char* model_path;     // Path to model
    uint32_t context_size;      // Context window size
    uint32_t batch_size;        // Batch size
    uint32_t thread_count;      // Number of threads
    uint32_t gpu_layers;        // Layers on GPU
    RawrXDLogLevel log_level;   // Logging level
    const char* cache_path;       // KV cache path
} RawrXDConfig;

// Set configuration
RAWRXD_API int RawrXD_SetConfig(const RawrXDConfig* config);

// Get current configuration
RAWRXD_API int RawrXD_GetConfig(RawrXDConfig* config);
```

### Error Handling

```c
// Error codes
typedef enum {
    RAWRXD_OK = 0,
    RAWRXD_ERROR_INVALID_PARAM = -1,
    RAWRXD_ERROR_OUT_OF_MEMORY = -2,
    RAWRXD_ERROR_FILE_NOT_FOUND = -3,
    RAWRXD_ERROR_INVALID_MODEL = -4,
    RAWRXD_ERROR_GPU_NOT_AVAILABLE = -5,
    RAWRXD_ERROR_INFERENCE_FAILED = -6,
    RAWRXD_ERROR_TIMEOUT = -7,
    RAWRXD_ERROR_CANCELLED = -8
} RawrXDError;

// Get last error
RAWRXD_API RawrXDError RawrXD_GetLastError(void);

// Get error string
RAWRXD_API const char* RawrXD_GetErrorString(RawrXDError error);

// Set error callback
RAWRXD_API void RawrXD_SetErrorCallback(
    void (*callback)(RawrXDError error, const char* message)
);
```

---

## Inference API

### Synchronous Inference

```c
// Run inference synchronously
RAWRXD_API int RawrXD_Infer(
    const char* prompt,           // Input prompt
    char* output,                  // Output buffer
    size_t output_size,            // Buffer size
    const RawrXDInferenceParams* params  // Parameters
);

// Inference parameters
typedef struct {
    uint32_t max_tokens;           // Maximum tokens to generate
    float temperature;             // Sampling temperature
    float top_p;                   // Nucleus sampling
    uint32_t top_k;                // Top-k sampling
    float repeat_penalty;          // Repetition penalty
    const char** stop_sequences;   // Stop sequences
    uint32_t stop_count;           // Number of stop sequences
} RawrXDInferenceParams;
```

### Asynchronous Inference

```c
// Inference callback
typedef void (*RawrXDInferenceCallback)(
    const char* token,              // Generated token
    uint32_t token_index,          // Token index
    void* user_data                // User data
);

// Completion callback
typedef void (*RawrXDCompletionCallback)(
    const char* full_text,          // Complete output
    uint32_t token_count,          // Total tokens
    RawrXDError error,              // Error code
    void* user_data                // User data
);

// Run inference asynchronously
RAWRXD_API RawrXDInferenceHandle RawrXD_InferAsync(
    const char* prompt,
    const RawrXDInferenceParams* params,
    RawrXDInferenceCallback token_callback,
    RawrXDCompletionCallback completion_callback,
    void* user_data
);

// Cancel inference
RAWRXD_API int RawrXD_CancelInference(RawrXDInferenceHandle handle);

// Wait for completion
RAWRXD_API int RawrXD_WaitForInference(
    RawrXDInferenceHandle handle,
    uint32_t timeout_ms
);
```

### Streaming Inference

```c
// Stream callback
typedef void (*RawrXDStreamCallback)(
    const char* chunk,              // Text chunk
    uint32_t chunk_size,             // Chunk size
    bool is_last,                   // Is last chunk
    void* user_data                // User data
);

// Stream inference
RAWRXD_API int RawrXD_InferStream(
    const char* prompt,
    const RawrXDInferenceParams* params,
    RawrXDStreamCallback callback,
    void* user_data
);
```

---

## Model API

### Model Loading

```c
// Load model
RAWRXD_API RawrXDModelHandle RawrXD_LoadModel(
    const char* path,
    const RawrXDModelParams* params
);

// Model parameters
typedef struct {
    uint32_t n_gpu_layers;         // Layers on GPU
    bool use_mmap;                 // Use memory mapping
    bool use_mlock;                // Lock memory
    const char* tensor_split;      // Tensor split config
    const char* main_gpu;          // Main GPU name
    bool vocab_only;               // Load vocab only
} RawrXDModelParams;

// Unload model
RAWRXD_API void RawrXD_UnloadModel(RawrXDModelHandle model);

// Get model info
RAWRXD_API int RawrXD_GetModelInfo(
    RawrXDModelHandle model,
    RawrXDModelInfo* info
);

// Model info structure
typedef struct {
    char name[256];                // Model name
    char arch[64];                 // Architecture
    uint32_t vocab_size;           // Vocabulary size
    uint32_t context_size;         // Context size
    uint32_t embedding_length;     // Embedding dimension
    uint32_t feed_forward_length;    // FFN dimension
    uint32_t head_count;           // Attention heads
    uint32_t layer_count;          // Number of layers
    uint32_t expert_count;         // Number of experts
    uint64_t parameter_count;      // Total parameters
    uint64_t size_bytes;           // Model size
} RawrXDModelInfo;
```

### Model Quantization

```c
// Quantization types
typedef enum {
    RAWRXD_Q4_0 = 0,
    RAWRXD_Q4_1 = 1,
    RAWRXD_Q5_0 = 2,
    RAWRXD_Q5_1 = 3,
    RAWRXD_Q8_0 = 4,
    RAWRXD_Q8_1 = 5,
    RAWRXD_F16 = 6,
    RAWRXD_F32 = 7
} RawrXDQuantizationType;

// Quantize model
RAWRXD_API int RawrXD_QuantizeModel(
    const char* input_path,
    const char* output_path,
    RawrXDQuantizationType type
);

// Get quantization info
RAWRXD_API int RawrXD_GetQuantizationInfo(
    RawrXDQuantizationType type,
    RawrXDQuantizationInfo* info
);
```

---

## Memory API

### Memory Management

```c
// Allocate aligned memory
RAWRXD_API void* RawrXD_AlignedAlloc(
    size_t size,
    size_t alignment
);

// Free aligned memory
RAWRXD_API void RawrXD_AlignedFree(void* ptr);

// Get memory info
RAWRXD_API int RawrXD_GetMemoryInfo(RawrXDMemoryInfo* info);

// Memory info structure
typedef struct {
    size_t total_physical;         // Total physical memory
    size_t available_physical;   // Available physical memory
    size_t total_virtual;          // Total virtual memory
    size_t available_virtual;      // Available virtual memory
    size_t used_by_rawrxd;         // Memory used by RawrXD
} RawrXDMemoryInfo;
```

### KV Cache

```c
// KV cache handle
typedef struct RawrXDKVCache* RawrXDKVCacheHandle;

// Create KV cache
RAWRXD_API RawrXDKVCacheHandle RawrXD_CreateKVCache(
    uint32_t context_size,
    uint32_t layer_count,
    uint32_t head_count,
    uint32_t head_dim
);

// Destroy KV cache
RAWRXD_API void RawrXD_DestroyKVCache(RawrXDKVCacheHandle cache);

// Clear KV cache
RAWRXD_API void RawrXD_ClearKVCache(RawrXDKVCacheHandle cache);

// Save KV cache
RAWRXD_API int RawrXD_SaveKVCache(
    RawrXDKVCacheHandle cache,
    const char* path
);

// Load KV cache
RAWRXD_API RawrXDKVCacheHandle RawrXD_LoadKVCache(const char* path);
```

---

## GPU API

### Device Management

```c
// Get device count
RAWRXD_API uint32_t RawrXD_GetDeviceCount(void);

// Get device info
RAWRXD_API int RawrXD_GetDeviceInfo(
    uint32_t device_id,
    RawrXDDeviceInfo* info
);

// Device info structure
typedef struct {
    char name[256];                // Device name
    uint64_t total_memory;         // Total memory
    uint64_t free_memory;          // Free memory
    uint32_t compute_capability;   // Compute capability
    bool is_available;             // Is available
} RawrXDDeviceInfo;

// Set active device
RAWRXD_API int RawrXD_SetDevice(uint32_t device_id);

// Get active device
RAWRXD_API uint32_t RawrXD_GetDevice(void);
```

### GPU Operations

```c
// Allocate GPU memory
RAWRXD_API void* RawrXD_GpuMalloc(size_t size);

// Free GPU memory
RAWRXD_API void RawrXD_GpuFree(void* ptr);

// Copy to GPU
RAWRXD_API int RawrXD_CopyToGpu(
    void* dst,
    const void* src,
    size_t size
);

// Copy from GPU
RAWRXD_API int RawrXD_CopyFromGpu(
    void* dst,
    const void* src,
    size_t size
);

// Synchronize
RAWRXD_API void RawrXD_GpuSynchronize(void);
```

---

## Network API

### Cluster Management

```c
// Initialize cluster
RAWRXD_API int RawrXD_ClusterInit(
    const RawrXDClusterConfig* config
);

// Cluster config
typedef struct {
    const char* master_address;
    uint32_t master_port;
    uint32_t node_id;
    uint32_t world_size;
    const char** node_addresses;
} RawrXDClusterConfig;

// Finalize cluster
RAWRXD_API void RawrXD_ClusterFinalize(void);

// Get rank
RAWRXD_API uint32_t RawrXD_GetRank(void);

// Get world size
RAWRXD_API uint32_t RawrXD_GetWorldSize(void);

// Barrier
RAWRXD_API void RawrXD_Barrier(void);
```

### Communication

```c
// Broadcast
RAWRXD_API int RawrXD_Broadcast(
    void* data,
    size_t count,
    uint32_t root
);

// All-reduce
RAWRXD_API int RawrXD_AllReduce(
    const void* sendbuf,
    void* recvbuf,
    size_t count,
    RawrXDMPIOp op
);

// Send
RAWRXD_API int RawrXD_Send(
    const void* buf,
    size_t count,
    uint32_t dest,
    uint32_t tag
);

// Receive
RAWRXD_API int RawrXD_Recv(
    void* buf,
    size_t count,
    uint32_t source,
    uint32_t tag
);
```

---

## Extension API

### Extension Interface

```c
// Extension entry point
typedef struct {
    uint32_t api_version;
    const char* name;
    const char* version;
    int (*initialize)(RawrXDExtensionHost* host);
    void (*shutdown)(void);
    void (*on_event)(RawrXDEventType type, const void* data);
} RawrXDExtension;

// Extension host interface
typedef struct {
    uint32_t version;
    
    // Commands
    int (*register_command)(
        const char* id,
        void (*handler)(const RawrXDCommandArgs* args)
    );
    void (*unregister_command)(const char* id);
    
    // Events
    int (*subscribe_event)(
        RawrXDEventType type,
        void (*handler)(const void* data)
    );
    void (*unsubscribe_event)(RawrXDEventType type);
    
    // Documents
    RawrXDDocumentHandle (*get_active_document)(void);
    int (*open_document)(const char* path);
    void (*close_document)(RawrXDDocumentHandle doc);
    
    // UI
    void (*show_message)(const char* message);
    void (*show_error)(const char* message);
    void (*show_panel)(const char* id);
} RawrXDExtensionHost;

// Export extension
RAWRXD_API const RawrXDExtension* RawrXD_GetExtension(void);
```

---

## Summary

API reference coverage:

- ✅ Core API (initialization, configuration, errors)
- ✅ Inference API (sync, async, streaming)
- ✅ Model API (loading, quantization)
- ✅ Memory API (allocation, KV cache)
- ✅ GPU API (devices, operations)
- ✅ Network API (cluster, communication)
- ✅ Extension API (interface, host)

**Status:** ✅ Complete

---

*End of API Reference*
