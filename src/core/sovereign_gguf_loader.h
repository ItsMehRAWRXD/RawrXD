// =============================================================================
// sovereign_gguf_loader.h
// Phase 21: Model Loading & Quantization
// Memory-mapped GGUF loader with zero-copy quantization
// =============================================================================

#ifndef SOVEREIGN_GGUF_LOADER_H
#define SOVEREIGN_GGUF_LOADER_H

#include "sovereign_memory_pool.h"
#include <inttypes.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Configuration
// =============================================================================

#define SOVEREIGN_GGUF_MAX_DIMS       4
#define SOVEREIGN_GGUF_MAX_TENSORS    1024
#define SOVEREIGN_GGUF_MAX_METADATA   256
#define SOVEREIGN_GGUF_MAGIC          0x46554747  // "GGUF"
#define SOVEREIGN_GGUF_VERSION        3

// =============================================================================
// GGUF Format Types (from llama.cpp spec)
// =============================================================================

typedef enum {
    SOVEREIGN_GGUF_TYPE_UINT8   = 0,
    SOVEREIGN_GGUF_TYPE_INT8    = 1,
    SOVEREIGN_GGUF_TYPE_UINT16  = 2,
    SOVEREIGN_GGUF_TYPE_INT16   = 3,
    SOVEREIGN_GGUF_TYPE_UINT32  = 4,
    SOVEREIGN_GGUF_TYPE_INT32   = 5,
    SOVEREIGN_GGUF_TYPE_FLOAT32 = 6,
    SOVEREIGN_GGUF_TYPE_BOOL    = 7,
    SOVEREIGN_GGUF_TYPE_STRING  = 8,
    SOVEREIGN_GGUF_TYPE_ARRAY   = 9,
    SOVEREIGN_GGUF_TYPE_UINT64  = 10,
    SOVEREIGN_GGUF_TYPE_INT64   = 11,
    SOVEREIGN_GGUF_TYPE_FLOAT64 = 12,
} SovereignGGUFType;

typedef enum {
    SOVEREIGN_GGML_TYPE_F32  = 0,
    SOVEREIGN_GGML_TYPE_F16  = 1,
    SOVEREIGN_GGML_TYPE_Q4_0 = 2,
    SOVEREIGN_GGML_TYPE_Q4_1 = 3,
    SOVEREIGN_GGML_TYPE_Q5_0 = 6,
    SOVEREIGN_GGML_TYPE_Q5_1 = 7,
    SOVEREIGN_GGML_TYPE_Q8_0 = 8,
    SOVEREIGN_GGML_TYPE_Q8_1 = 9,
    SOVEREIGN_GGML_TYPE_Q2_K = 10,
    SOVEREIGN_GGML_TYPE_Q3_K = 11,
    SOVEREIGN_GGML_TYPE_Q4_K = 12,
    SOVEREIGN_GGML_TYPE_Q5_K = 13,
    SOVEREIGN_GGML_TYPE_Q6_K = 14,
    SOVEREIGN_GGML_TYPE_Q8_K = 15,
    SOVEREIGN_GGML_TYPE_IQ2_XXS = 16,
    SOVEREIGN_GGML_TYPE_IQ2_XS  = 17,
    SOVEREIGN_GGML_TYPE_IQ3_XXS = 18,
    SOVEREIGN_GGML_TYPE_IQ1_S   = 19,
    SOVEREIGN_GGML_TYPE_BF16    = 30,  // For AMX-BF16
    SOVEREIGN_GGML_TYPE_AMX_INT4 = 100, // Custom: AMX-optimized INT4
} SovereignGGMLType;

// =============================================================================
// Opaque Handles
// =============================================================================

typedef struct SovereignGGUFModel* SovereignGGUFModelHandle;
typedef struct SovereignGGUFTensor* SovereignGGUFTensorHandle;
typedef struct SovereignModelLoader* SovereignModelLoaderHandle;

// =============================================================================
// GGUF Header
// =============================================================================

typedef struct SovereignGGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
} SovereignGGUFHeader;

// =============================================================================
// Tensor Info
// =============================================================================

typedef struct SovereignGGUFTensorInfo {
    char name[64];
    uint32_t n_dims;
    uint64_t dims[SOVEREIGN_GGUF_MAX_DIMS];
    uint32_t type;  // SovereignGGMLType
    uint64_t offset;  // Offset in file
    uint64_t size;    // Size in bytes
    
    // Memory-mapped pointer (valid after loading)
    void* data;
    
    // Quantization parameters
    float scale;
    float zero_point;
    uint32_t group_size;
    
    // AMX tiling info
    uint32_t tile_rows;
    uint32_t tile_cols;
    uint32_t is_tiled;
} SovereignGGUFTensorInfo;

// =============================================================================
// Model Configuration (from metadata)
// =============================================================================

typedef struct SovereignModelConfig {
    // Architecture
    char architecture[32];
    uint32_t vocab_size;
    uint32_t hidden_size;
    uint32_t num_layers;
    uint32_t num_heads;
    uint32_t num_kv_heads;
    uint32_t head_dim;
    uint32_t intermediate_size;
    uint32_t max_position_embeddings;
    
    // Quantization
    uint32_t quantization_type;
    float quantization_scale;
    
    // AMX settings
    uint32_t use_amx_tiling;
    uint32_t tile_size;
    
    // Memory
    uint64_t model_size_bytes;
    uint64_t working_memory_bytes;
} SovereignModelConfig;

// =============================================================================
// Loading Statistics
// =============================================================================

typedef struct SovereignLoadingStats {
    uint64_t file_size;
    uint64_t mapped_size;
    uint64_t tensor_count;
    uint64_t metadata_count;
    double load_time_ms;
    double map_time_ms;
    double quantize_time_ms;
    double tile_time_ms;
    uint32_t use_memory_mapping;
    uint32_t use_zero_copy;
    uint32_t use_prefetch;
} SovereignLoadingStats;

// =============================================================================
// Loader Configuration
// =============================================================================

typedef struct SovereignLoaderConfig {
    uint32_t use_memory_mapping;     // Use mmap/CreateFileMapping
    uint32_t use_zero_copy;          // Quantize in-place
    uint32_t use_prefetch;           // Prefetch weights
    uint32_t enable_amx_tiling;      // Pre-tile for AMX
    uint32_t target_quantization;    // Target type (Q4_K, etc.)
    uint32_t num_threads;            // Parallel loading threads
    uint64_t max_memory_bytes;       // Memory limit
} SovereignLoaderConfig;

// =============================================================================
// Model Loader API
// =============================================================================

// Initialize loader system
__declspec(dllexport) int Sovereign_Loader_Init(void);

// Shutdown loader system
__declspec(dllexport) void Sovereign_Loader_Shutdown(void);

// Load model from file
__declspec(dllexport) SovereignGGUFModelHandle Sovereign_LoadModel(
    const char* filepath,
    const SovereignLoaderConfig* config
);

// Unload model and free resources
__declspec(dllexport) void Sovereign_UnloadModel(SovereignGGUFModelHandle model);

// Get model configuration
__declspec(dllexport) int Sovereign_Model_GetConfig(
    SovereignGGUFModelHandle model,
    SovereignModelConfig* config
);

// Get loading statistics
__declspec(dllexport) int Sovereign_Model_GetStats(
    SovereignGGUFModelHandle model,
    SovereignLoadingStats* stats
);

// =============================================================================
// Tensor Access
// =============================================================================

// Get tensor by name
__declspec(dllexport) SovereignGGUFTensorHandle Sovereign_Model_GetTensor(
    SovereignGGUFModelHandle model,
    const char* name
);

// Get tensor data pointer (ready for AMX)
__declspec(dllexport) void* Sovereign_Tensor_GetData(
    SovereignGGUFTensorHandle tensor
);

// Get tensor info
__declspec(dllexport) int Sovereign_Tensor_GetInfo(
    SovereignGGUFTensorHandle tensor,
    SovereignGGUFTensorInfo* info
);

// Get number of tensors
__declspec(dllexport) uint64_t Sovereign_Model_GetTensorCount(
    SovereignGGUFModelHandle model
);

// Iterate tensors
__declspec(dllexport) SovereignGGUFTensorHandle Sovereign_Model_GetTensorByIndex(
    SovereignGGUFModelHandle model,
    uint64_t index
);

// =============================================================================
// Memory Mapping
// =============================================================================

// Prefetch model weights into memory
__declspec(dllexport) void Sovereign_Model_Prefetch(
    SovereignGGUFModelHandle model,
    uint64_t offset,
    uint64_t size
);

// Lock model in physical memory (prevent swapping)
__declspec(dllexport) int Sovereign_Model_LockInMemory(
    SovereignGGUFModelHandle model
);

// Unlock model from physical memory
__declspec(dllexport) void Sovereign_Model_UnlockMemory(
    SovereignGGUFModelHandle model
);

// Get memory usage
__declspec(dllexport) uint64_t Sovereign_Model_GetMemoryUsage(
    SovereignGGUFModelHandle model
);

// =============================================================================
// Quantization
// =============================================================================

// Convert tensor to target quantization (in-place if zero-copy)
__declspec(dllexport) int Sovereign_Tensor_Quantize(
    SovereignGGUFTensorHandle tensor,
    uint32_t target_type
);

// Dequantize tensor to F32
__declspec(dllexport) int Sovereign_Tensor_Dequantize(
    SovereignGGUFTensorHandle tensor,
    float* output,
    uint64_t output_size
);

// Get quantization type name
__declspec(dllexport) const char* Sovereign_GetQuantizationName(
    uint32_t type
);

// Check if quantization is supported
__declspec(dllexport) int Sovereign_IsQuantizationSupported(
    uint32_t type
);

// =============================================================================
// AMX Weight Tiling
// =============================================================================

// Pre-tile weights for AMX (16x16 or 32x32 blocks)
__declspec(dllexport) int Sovereign_Tensor_TileForAMX(
    SovereignGGUFTensorHandle tensor,
    uint32_t tile_rows,
    uint32_t tile_cols
);

// Check if tensor is tiled
__declspec(dllexport) int Sovereign_Tensor_IsTiled(
    SovereignGGUFTensorHandle tensor
);

// Get tile dimensions
__declspec(dllexport) int Sovereign_Tensor_GetTileDims(
    SovereignGGUFTensorHandle tensor,
    uint32_t* tile_rows,
    uint32_t* tile_cols
);

// Get pointer to specific tile
__declspec(dllexport) void* Sovereign_Tensor_GetTile(
    SovereignGGUFTensorHandle tensor,
    uint32_t tile_row,
    uint32_t tile_col
);

// =============================================================================
// Debug & Diagnostics
// =============================================================================

// Dump model information
__declspec(dllexport) void Sovereign_Model_DumpInfo(
    SovereignGGUFModelHandle model
);

// Validate model integrity
__declspec(dllexport) int Sovereign_Model_Validate(
    SovereignGGUFModelHandle model
);

// Get last error message
__declspec(dllexport) const char* Sovereign_Loader_GetLastError(void);

// Set debug logging
__declspec(dllexport) void Sovereign_Loader_SetDebugLogging(int enable);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_GGUF_LOADER_H
