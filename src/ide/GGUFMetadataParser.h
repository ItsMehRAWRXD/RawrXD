/*=============================================================================
 * GGUFMetadataParser.h
 * Audit-grade GGUF metadata extraction for reproducible benchmarks
 * 
 * Parses actual GGUF file headers to extract:
 * - Architecture (llama, falcon, etc.)
 * - Block count (layers)
 * - Context length
 * - Tensor types and quantization
 * - Tensor count
 *
 * This replaces filename-based inference with actual file metadata,
 * eliminating ambiguity from renamed files.
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <string>

// GGUF Magic number
static constexpr uint32_t GGUF_MAGIC = 0x46554747; // "GGUF" in little-endian

// GGUF metadata value types
enum class GGUFType : uint32_t {
    UINT8   = 0,
    INT8    = 1,
    UINT16  = 2,
    INT16   = 3,
    UINT32  = 4,
    INT32   = 5,
    FLOAT32 = 6,
    BOOL    = 7,
    STRING  = 8,
    ARRAY   = 9,
    UINT64  = 10,
    INT64   = 11,
    FLOAT64 = 12
};

// Parsed GGUF metadata structure
struct GGUFMetadata {
    // File info
    uint32_t    version           = 0;
    uint64_t    tensorCount       = 0;
    uint64_t    metadataCount     = 0;
    
    // Model architecture
    char        architecture[64]  = {0};
    uint32_t    blockCount        = 0;      // Number of layers
    uint32_t    contextLength     = 0;
    uint32_t    embeddingLength   = 0;      // Hidden size
    uint32_t    feedForwardLength = 0;      // Intermediate size
    uint32_t    headCount         = 0;       // Attention heads
    uint32_t    headCountKV       = 0;       // KV heads
    
    // Quantization info
    char        quantization[32]   = {0};     // Q4_K_M, Q8_0, etc.
    uint32_t    quantizationVersion = 0;
    
    // General info
    char        modelName[256]   = {0};
    char        modelFile[512]   = {0};
    
    // Validation
    bool        valid             = false;
    char        errorMsg[256]     = {0};
};

// Function prototypes
bool GGUF_ParseMetadata(const char* filePath, GGUFMetadata* outMetadata);
bool GGUF_ParseMetadataW(const wchar_t* filePath, GGUFMetadata* outMetadata);
void GGUF_FormatMetadata(const GGUFMetadata* metadata, char* outBuffer, size_t bufferSize);

// SHA256 hashing for model verification
bool ComputeFileSHA256(const char* filePath, char* outHash, size_t hashBufferSize);
bool ComputeFileSHA256W(const wchar_t* filePath, char* outHash, size_t hashBufferSize);
