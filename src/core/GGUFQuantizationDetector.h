//==============================================================================
// GGUFQuantizationDetector.h - Phase 15B: Quantization Format Detection
//
// Parses GGUF file headers to automatically detect:
// - Quantization type (Q2_K, Q4_K_M, Q5_K, Q8_0, FP16, etc.)
// - Parameter count
// - Tensor shapes and types
// - Architecture metadata
//
// Enables automatic model registration without manual configuration.
//==============================================================================

#ifndef GGUF_QUANTIZATION_DETECTOR_H
#define GGUF_QUANTIZATION_DETECTOR_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Constants
//==============================================================================

#define GGUF_MAGIC 0x46554747  // "GGUF" in little-endian
#define GGUF_VERSION 3
#define MAX_TENSOR_NAME 64
#define MAX_ARCH_NAME 64
#define MAX_QUANT_NAME 32

//==============================================================================
// GGUF Value Types
//==============================================================================

typedef enum {
    GGUF_TYPE_UINT8   = 0,
    GGUF_TYPE_INT8    = 1,
    GGUF_TYPE_UINT16  = 2,
    GGUF_TYPE_INT16   = 3,
    GGUF_TYPE_UINT32  = 4,
    GGUF_TYPE_INT32   = 5,
    GGUF_TYPE_FLOAT32 = 6,
    GGUF_TYPE_BOOL    = 7,
    GGUF_TYPE_STRING  = 8,
    GGUF_TYPE_ARRAY   = 9,
    GGUF_TYPE_UINT64  = 10,
    GGUF_TYPE_INT64   = 11,
    GGUF_TYPE_FLOAT64 = 12,
    GGUF_TYPE_COUNT   = 13
} GgufType;

//==============================================================================
// Quantization Types (detected from tensor types)
//==============================================================================

typedef enum {
    QUANT_UNKNOWN = 0,
    QUANT_F32,           // 32-bit float
    QUANT_F16,           // 16-bit float
    QUANT_Q4_0,          // 4-bit, type 0
    QUANT_Q4_1,          // 4-bit, type 1
    QUANT_Q4_K,          // 4-bit, K-quant
    QUANT_Q4_K_M,        // 4-bit, K-quant medium
    QUANT_Q4_K_S,        // 4-bit, K-quant small
    QUANT_Q5_0,          // 5-bit, type 0
    QUANT_Q5_1,          // 5-bit, type 1
    QUANT_Q5_K,          // 5-bit, K-quant
    QUANT_Q5_K_M,        // 5-bit, K-quant medium
    QUANT_Q6_K,          // 6-bit, K-quant
    QUANT_Q8_0,          // 8-bit, type 0
    QUANT_Q8_1,          // 8-bit, type 1
    QUANT_Q8_K,          // 8-bit, K-quant
    QUANT_Q2_K,          // 2-bit, K-quant
    QUANT_Q3_K,          // 3-bit, K-quant
    QUANT_Q3_K_M,        // 3-bit, K-quant medium
    QUANT_Q3_K_S,        // 3-bit, K-quant small
    QUANT_IQ2_XXS,       // 2-bit, importance matrix
    QUANT_IQ2_XS,        // 2-bit, importance matrix
    QUANT_IQ3_XXS,       // 3-bit, importance matrix
    QUANT_IQ4_XS,        // 4-bit, importance matrix
    QUANT_COUNT
} QuantizationType;

//==============================================================================
// Detected Model Info
//==============================================================================

typedef struct DetectedModelInfo {
    // File info
    char file_path[512];
    uint64_t file_size;
    
    // Architecture
    char architecture[MAX_ARCH_NAME];     // "llama", "qwen2", "phi3", etc.
    char quantization[MAX_QUANT_NAME];    // "Q4_K_M", "Q8_0", etc.
    QuantizationType quant_type;
    
    // Model dimensions
    uint32_t vocab_size;
    uint32_t context_length;
    uint32_t embedding_length;
    uint32_t num_layers;
    uint32_t num_heads;
    uint32_t num_kv_heads;
    uint32_t feed_forward_length;
    
    // Parameter count (estimated)
    uint64_t parameter_count;
    
    // Tensor statistics
    uint32_t tensor_count;
    uint32_t quantized_tensors;
    uint32_t float_tensors;
    
    // Metadata
    char model_name[128];
    char author[128];
    char version[32];
    char license[64];
    char description[512];
    char url[256];
    
    // Detection status
    int detection_success;
    char error_message[256];
} DetectedModelInfo;

//==============================================================================
// Detection API
//==============================================================================

// Initialize detector subsystem
int GGUFDetector_Init(void);

// Shutdown detector
int GGUFDetector_Shutdown(void);

// Detect quantization and metadata from GGUF file
// Returns 0 on success, negative error code on failure
int GGUFDetector_AnalyzeFile(const char* file_path, DetectedModelInfo* out_info);

// Quick detection - just get quantization type
int GGUFDetector_GetQuantization(const char* file_path, char* out_quant, size_t out_size);

// Get parameter count estimate
int GGUFDetector_GetParameterCount(const char* file_path, uint64_t* out_params);

// Get context window size
int GGUFDetector_GetContextLength(const char* file_path, uint32_t* out_length);

//==============================================================================
// Quantization Utilities
//==============================================================================

// Convert quantization enum to string
const char* GGUFDetector_QuantTypeToString(QuantizationType type);

// Parse quantization string to enum
QuantizationType GGUFDetector_StringToQuantType(const char* str);

// Get bits per weight for quantization type
float GGUFDetector_GetBitsPerWeight(QuantizationType type);

// Estimate model quality score (0-100) based on quantization
// Higher = better quality (more bits per weight)
int GGUFDetector_GetQualityScore(QuantizationType type);

// Get recommended use cases for quantization type
const char* GGUFDetector_GetRecommendedUse(QuantizationType type);

// Check if quantization is K-quant (better quality)
int GGUFDetector_IsKQuant(QuantizationType type);

// Check if quantization uses importance matrix (IQ quants)
int GGUFDetector_IsIQQuant(QuantizationType type);

//==============================================================================
// Memory Estimation
//==============================================================================

// Estimate RAM/VRAM required for model
// Returns estimated bytes needed
uint64_t GGUFDetector_EstimateMemoryRequired(const DetectedModelInfo* info);

// Estimate memory for specific quantization at given parameter count
uint64_t GGUFDetector_EstimateMemoryForParams(uint64_t params, QuantizationType type);

//==============================================================================
// Architecture Detection
//==============================================================================

// Detect model family from architecture string
const char* GGUFDetector_GetModelFamily(const char* architecture);

// Get default capabilities for architecture
unsigned int GGUFDetector_GetDefaultCapabilities(const char* architecture);

// Check if architecture supports specific feature
int GGUFDetector_ArchitectureSupports(const char* architecture, const char* feature);

//==============================================================================
// Validation
//==============================================================================

// Validate GGUF file integrity
int GGUFDetector_ValidateFile(const char* file_path, char* out_error, size_t error_size);

// Check if file is a valid GGUF
int GGUFDetector_IsValidGGUF(const char* file_path);

// Get file version
int GGUFDetector_GetFileVersion(const char* file_path, uint32_t* out_version);

#ifdef __cplusplus
}
#endif

#endif // GGUF_QUANTIZATION_DETECTOR_H
